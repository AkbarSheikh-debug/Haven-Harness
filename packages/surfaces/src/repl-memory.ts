import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { SessionEvent } from '@hn/core';
import {
  MemoryFile, answerCard, approveLearned, bytesHash, checkLearned, discardLearned, dreamDue, learnPrompt, listEntries, morningCards, parseLearnReply,
  atomicWrite, quarantineSkill, readOrNull, renderMemoryCard, ruleDiff, runCurator, storedBytes, type DreamReport, type LearnSource, type MemoryPaths,
} from '@hn/memory';
import { formatDream } from './dream.ts';
import { REVIEW_EVERY_TURNS, type ReviewResult } from './review.ts';

export interface MemoryDoorSession {
  readonly review: (() => Promise<ReviewResult>) | null;
  readonly dream?: ((dryRun: boolean) => Promise<DreamReport>) | null;
  readonly memoryPaths?: MemoryPaths | null;
  /** Memory gates (slide 37): false when the policy keeps /learn away from this person's sessions. */
  readonly learnAllowed?: boolean;
  readonly agent: {
    readonly events: readonly SessionEvent[];
    run?(input: string, options?: { readonly origin?: 'user' | 'harness' }): Promise<{ readonly text: string }>;
  };
}

export interface MemoryDoorOptions {
  /** One line from the person at the door. */
  readonly ask?: (prompt: string) => Promise<string>;
  /** The harness home, for skills and the user's AGENTS.md. */
  readonly home?: string;
  /** Who answers cards, recorded as `approvedBy`. */
  readonly person?: string;
  /** This session's id, so its own new log does not count as the user being active. */
  readonly sessionId?: string;
  readonly now?: () => Date;
}

/** User turns so far: turns that began with something a person typed. */
export function userTurns(events: readonly SessionEvent[]): number {
  let count = 0;
  for (let index = 0; index < events.length; index += 1) {
    if (events[index]?.type !== 'turn/start') continue;
    if (events[index + 1]?.type === 'user/message' && events[index + 1]?.origin === 'user') count += 1;
  }
  return count;
}

/** What `/learn <source>` means: a URL, a folder, or (with nothing, or "this") the conversation. */
export function parseLearnSource(rest: string): LearnSource {
  const value = rest.trim();
  if (value === '' || value === 'this' || value === 'this conversation') return { kind: 'conversation' };
  return /^https?:\/\//i.test(value) ? { kind: 'url', value } : { kind: 'folder', value };
}

/**
 * Memory at the REPL door: morning cards, the curator and a due dream at launch; background review
 * every 10 user turns; and the memory commands. Never in `-p`, which has no door and shows no card.
 */
export class MemoryDoor {
  readonly #session: MemoryDoorSession;
  readonly #out: (text: string) => void;
  readonly #options: MemoryDoorOptions;
  readonly #running = new Set<Promise<void>>();

  constructor(session: MemoryDoorSession, out: (text: string) => void, options: MemoryDoorOptions = {}) {
    this.#session = session;
    this.#out = out;
    this.#options = options;
  }

  #now(): Date {
    return (this.#options.now ?? (() => new Date()))();
  }

  #background(work: Promise<void>): Promise<void> {
    const run = work.finally(() => this.#running.delete(run));
    this.#running.add(run);
    return run;
  }

  /** Starts a review when this turn made the count a multiple of 10, and none is running. */
  afterTurn(): Promise<void> | null {
    const review = this.#session.review;
    if (review === null || this.#running.size > 0) return null;
    const turns = userTurns(this.#session.agent.events);
    if (turns === 0 || turns % REVIEW_EVERY_TURNS !== 0) return null;
    return this.#background(
      review()
        .then((result) => {
          const cost = `${result.usage.input.toLocaleString('en-US')} in, ${result.usage.output.toLocaleString('en-US')} out, ${result.steps} steps`;
          this.#out(`\n[background review] ${result.notes} note${result.notes === 1 ? '' : 's'}, ${result.proposals} proposal${result.proposals === 1 ? '' : 's'} (${cost})\n`);
        })
        .catch((error: unknown) => this.#out(`\n[background review] did not finish: ${error instanceof Error ? error.message : String(error)}\n`)),
    );
  }

  /** Waits for background work still running, so leaving never cuts a write off halfway. */
  async settle(): Promise<void> {
    await Promise.all([...this.#running]);
  }

  /** At launch: the curator if the user has been idle, a dream if one is due (in the background), then the cards. */
  async start(): Promise<void> {
    const paths = this.#session.memoryPaths;
    if (paths === null || paths === undefined) return;
    const home = this.#options.home;
    if (home !== undefined) {
      const report = await runCurator({ root: join(home, 'skills'), now: this.#now(), lastActivity: await newestActivity(join(home, 'sessions'), this.#options.sessionId) }).catch(() => null);
      if (report?.ran === true && report.stale.length + report.archived.length > 0) {
        this.#out(`[curator] stale: ${report.stale.join(', ') || 'none'}; archived: ${report.archived.join(', ') || 'none'}. Nothing was deleted.\n`);
      }
    }
    const dream = this.#session.dream;
    if (dream !== null && dream !== undefined && (await dreamDue(paths, this.#now()))) {
      void this.#background(dream(false).then((report) => this.#out(`\n[dream] ${formatDream(report, false)}`)).catch(() => undefined));
    }
    await this.cards();
  }

  /** Up to three cards, each answered on its own: y saves, n suppresses, d opens a rule's diff, anything else is later. */
  async cards(): Promise<void> {
    const paths = this.#session.memoryPaths;
    const ask = this.#options.ask;
    if (paths === null || paths === undefined || ask === undefined) return;
    const cards = await morningCards(paths, this.#now());
    const person = this.#options.person ?? 'user';
    for (const [index, card] of cards.entries()) {
      const shownHash = bytesHash(storedBytes(card));
      this.#out(renderMemoryCard(card, { index: index + 1, of: cards.length }));
      let line = (await ask('card> ')).trim().toLowerCase();
      let diffOpened = false;
      if (line === 'd' && card.kind === 'rule' && this.#options.home !== undefined) {
        const target = join(this.#options.home, 'AGENTS.md');
        this.#out(`${ruleDiff(await readOrNull(target), storedBytes(card)).diff}\nThis adds one line to ${target}. [y] save it   [n] no\n`);
        diffOpened = true;
        line = (await ask('card> ')).trim().toLowerCase();
      }
      if (line === 'y' || line === 'yes') {
        const outcome = await answerCard(paths, card.id, { kind: 'yes', by: person, shownHash, diffOpened }, this.#now());
        if (outcome.ok && outcome.rule !== undefined && this.#options.home !== undefined) {
          const target = join(this.#options.home, 'AGENTS.md');
          await atomicWrite(target, ruleDiff(await readOrNull(target), outcome.rule).next);
        }
        this.#out(`${outcome.message}\n`);
      } else if (line === 'n' || line === 'no') {
        this.#out(`${(await answerCard(paths, card.id, { kind: 'no', by: person }, this.#now())).message}\n`);
      } else {
        this.#out('Later. It will be offered again until it expires.\n');
      }
    }
  }

  /** `/memory`, `/memory history`, `/memory undo`, `/memory accept`, `/learn`, `/dream`, `/cards`. True when the line was one of them. */
  async command(line: string): Promise<boolean> {
    const [word, sub = '', ...rest] = line.trim().split(/\s+/);
    if (word === '/cards') return (await this.cards(), true);
    if (word === '/dream') {
      const dream = this.#session.dream;
      if (dream === null || dream === undefined) this.#out('There is no memory in this session.\n');
      else this.#out(formatDream(await dream(sub === '--dry-run'), sub === '--dry-run'));
      return true;
    }
    if (word === '/learn') return (await this.#learn(parseLearnSource([sub, ...rest].join(' '))), true);
    if (word !== '/memory') return false;
    const paths = this.#session.memoryPaths;
    if (paths === null || paths === undefined) return (this.#out('There is no memory in this session.\n'), true);
    const target = rest[0] ?? (sub === 'history' || sub === 'undo' || sub === 'accept' ? 'memory' : '');
    const files = await openAll(paths, this.#now());
    if (sub === '' || sub === 'show') {
      for (const [name, file] of Object.entries(files)) {
        const state = file.status === 'ok' ? `${file.used} of ${file.cap} characters` : file.status === 'corrupt' ? 'damaged, not loaded' : 'changed by hand, not loaded until you /memory accept it';
        this.#out(`${name} (${state})\n${file.status === 'ok' ? listEntries(file.entries) : (file.markdown ?? '')}\n\n`);
      }
      return true;
    }
    const file = target === 'user' ? files['USER.md'] : target === 'notes' ? files["today's notes"] : files['MEMORY.md'];
    if (file === undefined || !['user', 'memory', 'notes'].includes(target)) return (this.#out('Name the file: user, memory or notes.\n'), true);
    if (sub === 'history') {
      const items = await file.history();
      this.#out(items.length === 0 ? 'No earlier versions.\n' : `${items.map((item) => `${item.seq}. ${item.when}: ${item.entries} entries`).join('\n')}\n`);
    } else if (sub === 'undo') {
      this.#out(`${(await file.undo()).reason}\n`);
    } else if (sub === 'accept') {
      const result = await file.acceptHandEdit(this.#options.person ?? 'user');
      this.#out(result.ok ? 'Kept your edit.\n' : `${result.reason}\n`);
    } else {
      this.#out('Use /memory, /memory history <file>, /memory undo <file> or /memory accept <file>.\n');
    }
    return true;
  }

  /** `/learn` (10.6): one harness turn with the house prompt, then every check, then quarantine and a yes or no. */
  async #learn(source: LearnSource): Promise<void> {
    if (this.#session.learnAllowed === false) return this.#out('The policy does not allow /learn in this session.\n');
    const run = this.#session.agent.run;
    const home = this.#options.home;
    if (run === undefined || home === undefined || this.#options.ask === undefined) return this.#out('/learn needs an interactive session.\n');
    const result = await run.call(this.#session.agent, learnPrompt(source), { origin: 'harness' });
    const files = parseLearnReply(result.text);
    if (typeof files === 'string') return this.#out(`${files}\n`);
    // The source is everything the model read or was told, never its own reply, so a flag it made up cannot vouch for itself.
    const sourceText = this.#session.agent.events
      .filter((event) => event.type === 'tool/result' || (event.type === 'user/message' && event.data['pinned'] !== true))
      .map((event) => String(event.data['content'] ?? event.data['text'] ?? ''))
      .join('\n');
    const check = await checkLearned(files, sourceText);
    if (check.errors.length > 0 || check.name === null) return this.#out(`The skill was not saved:\n- ${check.errors.join('\n- ')}\n`);
    const skills = join(home, 'skills');
    await quarantineSkill(skills, check.name, check.files);
    this.#out(`${[...check.files].map(([path, text]) => `── ${path} ──\n${text}`).join('\n')}\nSave the skill ${check.name}? It loads in every later session. [y/N]\n`);
    const answer = (await this.#options.ask('learn> ')).trim().toLowerCase();
    if (answer === 'y' || answer === 'yes') {
      await approveLearned(skills, check.name);
      this.#out(`Saved to ${join(skills, check.name)}.\n`);
    } else {
      await discardLearned(skills, check.name);
      this.#out('Not saved.\n');
    }
  }
}

async function openAll(paths: MemoryPaths, now: Date): Promise<Record<string, MemoryFile>> {
  const { dailyNotePath } = await import('@hn/memory');
  return {
    'USER.md': await MemoryFile.open({ path: paths.user, scope: 'user', project: null }),
    'MEMORY.md': await MemoryFile.open({ path: paths.memory, scope: 'project', project: paths.projectKey }),
    "today's notes": await MemoryFile.open({ path: dailyNotePath(paths, now), scope: 'daily', project: paths.projectKey }),
  };
}

/** The newest session activity anywhere: the curator only runs after two idle hours. */
async function newestActivity(sessions: string, current: string | undefined): Promise<Date | null> {
  let newest = 0;
  for (const project of await readdir(sessions, { withFileTypes: true }).catch(() => [])) {
    if (!project.isDirectory()) continue;
    for (const name of await readdir(join(sessions, project.name)).catch(() => [] as string[])) {
      if (name === current) continue;
      const info = await stat(join(sessions, project.name, name)).catch(() => null);
      if (info !== null && info.isFile()) newest = Math.max(newest, info.mtimeMs);
    }
  }
  return newest === 0 ? null : new Date(newest);
}
