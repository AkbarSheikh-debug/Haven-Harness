import { createHash } from 'node:crypto';
import { createInterface, type Interface } from 'node:readline';
import { sanitizeForDisplay } from '@hn/core';
import type { Quarantined } from '@hn/context';
import { parseSkillTest, skillTestBrief } from './skill-test.ts';
import type { Answer, Question } from '@hn/tools';
import type { KeyStore } from '@hn/provider';
import type { ImportPlan } from '@hn/operations';
import { describeChange, type McpTrustChange } from '@hn/tools';
import { MAX_CARD_BYTES, renderCard, type ApprovalAnswer, type ApprovalCard, type Approver } from '@hn/security';
import { describeHandback, formatUsage } from './print.ts';
import { openSession, type CliOptions, type OpenSession } from './session.ts';
import { openSessionControl, type ControlChannel } from './control.ts';
import { MemoryDoor } from './repl-memory.ts';
import { DelegationDoor } from './repl-delegation.ts';
import { compactCommand, microCommand } from './repl-context.ts';
import { userInfo } from 'node:os';
import { resolvePaths } from '@hn/config';

export const NOT_SANDBOXED_BANNER =
  'NOT SANDBOXED. hn runs on your machine in this phase. The gate slows mistakes down but does not stop an attacker.';

const out = (text: string): void => {
  process.stdout.write(sanitizeForDisplay(text));
};

/** One answer from a fresh prompt, because the line loop has already closed the input by the time a session ends. */
function askOnce(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.readableEnded) return resolve('');
    const lines = createInterface({ input: process.stdin, output: process.stdout });
    let answered = false;
    lines.once('close', () => {
      if (!answered) resolve('');
    });
    out(prompt);
    lines.question('', (answer) => {
      answered = true;
      lines.close();
      resolve(answer);
    });
  });
}

/** Drawn only by the harness. Model text is escaped to ASCII and prefixed, so it cannot draw a card or hide a character. */
export const renderApprovalCard = (card: ApprovalCard): string => renderCard(card);

export function parseApproval(line: string, card: ApprovalCard): ApprovalAnswer {
  const answer = line.trim().toLowerCase();
  if (answer === 'y' || answer === 'yes') return 'once';
  if ((answer === 's' || answer === 'session') && card.canRememberForSession) return 'session';
  return 'deny';
}

class Repl {
  readonly #lines: Interface;
  #session: OpenSession | undefined;
  #busy = false;
  #queued: string[] = [];
  memory: MemoryDoor | null = null;
  #pendingApproval: ((line: string) => void) | null = null;

  constructor() {
    this.#lines = createInterface({ input: process.stdin, output: process.stdout });
  }

  readonly #askedInstructions = new Set<string>();
  readonly approver: Approver = (card) =>
    new Promise((resolve) => {
      out(renderApprovalCard(card));
      this.#pendingApproval = (line) => resolve(parseApproval(line, card));
    });

  readonly delegation = new DelegationDoor(out, (prompt) => this.ask(prompt), () => this.#session, (session, home) => this.attach(session, home));

  async closeControl(): Promise<void> {
    await (await this.#control)?.close();
  }

  get current(): OpenSession | undefined {
    return this.#session;
  }

  #control: Promise<ControlChannel | null> = Promise.resolve(null);

  /** The session the REPL drives now. Its control channel moves with it, so `hn steer` reaches the current one. */
  attach(session: OpenSession, hnHome?: string): void {
    this.#session = session;
    const previous = this.#control;
    this.#control = previous.then(async (channel) => {
      await channel?.close();
      return hnHome === undefined ? null : openSessionControl(hnHome, session).catch(() => null);
    });
    this.memory = new MemoryDoor(session, out, { ask: (prompt) => this.ask(prompt), ...(hnHome === undefined ? {} : { home: hnHome }), person: userInfo().username, sessionId: session.sessionId });
  }

  /** One line from the person, for memory cards and /learn. Before the line loop, or awaited inside it. */
  ask(prompt: string): Promise<string> {
    return new Promise((resolve) => this.#lines.question(prompt, resolve));
  }

  /**
   * Asks about each file the box wants to bring back that the host-exec manifest holds, one card at a time, with the
   * reasons and the diff. Only a plain yes applies a file, and only the exact content that was shown. At the end of
   * input nobody can answer, so nothing is applied.
   */
  async approveImport(plan: ImportPlan): Promise<ReadonlyMap<string, string>> {
    const approved = new Map<string, string>();
    for (const change of plan.gated) {
      const summary = `${change.kind} ${change.path}\nwhy a person must decide: ${change.reasons.join('; ')}\n${change.diff}`.slice(0, MAX_CARD_BYTES);
      const card: ApprovalCard = {
        approvalId: `import-${change.path}`,
        tool: 'import',
        effect: 'execution',
        summary,
        target: change.path,
        byteCount: Buffer.byteLength(summary),
        canRememberForSession: false,
      };
      const line = await askOnce(renderApprovalCard(card));
      // An empty line is the same as no answer, and no answer is a no.
      if (parseApproval(line, card) === 'once') approved.set(change.path, change.hash ?? 'delete');
    }
    return approved;
  }

  /**
   * One card for an instruction file: its exact bytes, or for a change what changed. A file too large for a
   * card cannot be approved here, because content nobody saw is never approved.
   */
  async approveInstruction(file: Quarantined): Promise<boolean> {
    const body = file.state === 'changed' && file.diff !== null ? `${file.diff}\n\n--- whole file ---\n` : '';
    const summary = `${body}${file.content.toString('utf8')}`;
    if (Buffer.byteLength(summary) > MAX_CARD_BYTES) {
      out(`${file.display} is too large to approve on a card, so it stays unloaded. Open it, shorten it, or approve it another way.\n`);
      return false;
    }
    const card: ApprovalCard = {
      approvalId: `instructions-${file.path}`,
      tool: 'instructions',
      effect: 'irreversible',
      summary,
      target: `instruction file ${file.display} (${file.state})`,
      byteCount: Buffer.byteLength(summary),
      canRememberForSession: false,
    };
    return parseApproval(await askOnce(renderApprovalCard(card)), card) === 'once';
  }

  /**
   * `ask_user_question`. Drawn as plain numbered text, never in the reserved card style, so a question can never
   * pass for an approval. A number picks a model-written option; anything else is the person's own words.
   */
  async askQuestion(question: Question): Promise<Answer | null> {
    const options = question.options.map((option, index) => `  ${index + 1}) ${option.label}${option.description === undefined ? '' : ` - ${option.description}`}`);
    const how = question.multiSelect ? 'Answer with numbers separated by commas, or type your own answer: ' : 'Answer with a number, or type your own answer: ';
    const reply = (await askOnce([`\nQuestion from the agent: ${question.question}`, ...options, how].join('\n'))).trim();
    if (reply === '') return null;
    if (/^\d+(\s*,\s*\d+)*$/.test(reply)) {
      const picked = reply.split(',').map((part) => Number(part.trim()) - 1);
      return { kind: 'options', picked: question.multiSelect ? picked : picked.slice(0, 1) };
    }
    return { kind: 'text', text: reply };
  }

  /** Files that changed during the turn load only after a person says yes, so model output cannot promote itself. */
  async #reviewInstructions(): Promise<void> {
    const access = this.#session?.instructions;
    if (access === null || access === undefined) return;
    let approved = false;
    for (const file of access.chain.pending) {
      const key = `${file.path}:${createHash('sha256').update(file.content).digest('hex')}`;
      if (this.#askedInstructions.has(key)) continue;
      this.#askedInstructions.add(key);
      if (await this.approveInstruction(file)) {
        await access.trust(file);
        approved = true;
      }
    }
    if (approved) await this.#session?.agent.refreshInstructions();
  }

  /**
   * One card for a new or changed MCP server or tool, with the exact text that would be trusted and, for a change,
   * what changed. Only a plain yes approves it, and an approval covers exactly that text.
   */
  async approveMcp(server: string, changes: readonly McpTrustChange[]): Promise<boolean> {
    const summary = `${changes.map(describeChange).join('\n\n')}`.slice(0, MAX_CARD_BYTES);
    const card: ApprovalCard = {
      approvalId: `mcp-${server}`,
      tool: 'mcp',
      effect: 'irreversible',
      summary,
      target: `MCP server ${server}`,
      byteCount: Buffer.byteLength(summary),
      canRememberForSession: false,
    };
    return parseApproval(await askOnce(renderApprovalCard(card)), card) === 'once';
  }

  async #slash(line: string): Promise<void> {
    const session = this.#session;
    const checkpoints = session?.checkpoints;
    if (session === undefined || checkpoints === null || checkpoints === undefined) {
      out('Checkpoints are not available in this session.\n');
      return;
    }
    if (line === '/checkpoints') {
      const mine = (await checkpoints.list()).filter((info) => info.ref.startsWith(`${session.sessionId}/`));
      out(mine.length === 0 ? 'No checkpoints yet. One is taken before the first change.\n' : `${mine.map((info) => `#${info.seq} ${info.ts} ${info.reason}: ${info.fileCount} files, ${info.skipped.length} not saved`).join('\n')}\n`);
      return;
    }
    const all = line.split(/\s+/).includes('--all');
    try {
      const sandbox = session.sandbox;
      const report = await checkpoints.rollback({
        all,
        ...(sandbox === null ? {} : { whileStopped: (work) => sandbox.whileStopped(work), boxAlive: () => sandbox.alive }),
      });
      out(`Restored ${report.restored.length} file(s) and removed ${report.deleted.length} to match checkpoint #${report.checkpoint.seq}.\n`);
      if (!all) out('Only files the agent wrote were restored, so your own edits are kept. Use /rollback --all to restore everything.\n');
      const unsaved = [...report.skipped.map((entry) => `not saved: ${entry.path} (${entry.why})`), ...report.failed.map((entry) => `could not restore: ${entry.path} (${entry.why})`)];
      if (unsaved.length > 0) out(`${unsaved.join('\n')}\n`);
    } catch (error) {
      out(`${error instanceof Error ? error.message : String(error)}\n`);
    }
  }

  /**
   * `/skill-test <skill> <task>`: a fresh child uses the skill and reviews it harshly. The review is shown and added
   * to the session as child data, so the next thing you type (for example "revise the skill") can use it.
   */
  async #skillTest(line: string): Promise<void> {
    const session = this.#session;
    const parsed = parseSkillTest(line);
    if (session === undefined) return;
    if (parsed === null) {
      out('Use: /skill-test <skill-name> <a task to try it on>\n');
      return;
    }
    out(`Starting a fresh child to test ${parsed.skill}. It knows nothing about how the skill was written.\n`);
    const result = await session.runChild(skillTestBrief(parsed.skill, parsed.task), new AbortController().signal);
    out(`${sanitizeForDisplay(result.content)}\n`);
    if (!result.isError) await session.agent.addContext(result.content, 'child');
  }

  /** Lines typed during a turn steer it. A pending approval takes the next line first. */
  #onDuringTurn(line: string): void {
    const session = this.#session;
    if (session === undefined) return;
    if (line === '/stop') session.agent.stop();
    else if (line.startsWith('/queue ')) this.#queued.push(line.slice(7));
    else if (line.startsWith('/steer ')) session.agent.steer(line.slice(7));
    else if (line.trim() !== '') session.agent.redirect(line);
  }

  async #turn(model: string, input: string): Promise<void> {
    const session = this.#session;
    if (session === undefined) return;
    this.#busy = true;
    // Only URLs the user typed may be fetched unseen once untrusted text is in the session.
    session.egress.noteUserText(input);
    const result = await session.agent.run(input);
    this.#busy = false;
    out(`\n[${result.end}] ${formatUsage(model, result)}\n`);
    await this.#reviewInstructions();
    const context = session.agent.contextStatus();
    const rhythm = context.rhythm === 'flat' ? 'micro on (flat)' : 'folds when full (sawtooth)';
    out(`context ~${context.tokens.toLocaleString('en-US')} of ${context.window.toLocaleString('en-US')} tokens, ${rhythm}\n`);
    if (result.detail !== undefined) out(`${result.detail}\n`);
    void this.memory?.afterTurn();
  }

  async run(model: string): Promise<void> {
    process.on('SIGINT', () => {
      if (this.#busy) this.#session?.agent.stop();
      else this.#lines.close();
    });
    this.#lines.setPrompt('hn> ');
    this.#lines.prompt();

    const pending: Promise<void>[] = [];
    let chain: Promise<void> = Promise.resolve();
    for await (const line of this.#lines) {
      if (this.#pendingApproval !== null) {
        const answer = this.#pendingApproval;
        this.#pendingApproval = null;
        answer(line);
        continue;
      }
      if (this.#busy) {
        this.#onDuringTurn(line);
        continue;
      }
      if (line === '/exit') break;
      if (line === '/micro' || line === '/micro on' || line === '/micro off') {
        if (this.#session !== undefined) await microCommand(this.#session.agent, line, out);
        this.#lines.prompt();
        continue;
      }
      if (line.startsWith('/skill-test')) {
        await this.#skillTest(line);
        this.#lines.prompt();
        continue;
      }
      if (/^\/(memory|learn|dream|cards)\b/.test(line)) {
        await this.memory?.command(line);
        this.#lines.prompt();
        continue;
      }
      if (this.delegation.handles(line)) {
        await this.delegation.command(line);
        this.#lines.prompt();
        continue;
      }
      if (/^\/(implement|scout-and-plan|implement-and-review)(\s|$)/.test(line)) {
        // Run like a turn, beside the line loop, so the person can answer a worker's approval card while it runs.
        chain = chain.then(async () => {
          const session = this.#session;
          if (session === undefined) return;
          this.#busy = true;
          session.egress.noteUserText(line);
          await this.delegation.preset(session, line).finally(() => {
            this.#busy = false;
          });
          this.#lines.prompt();
        });
        pending.push(chain);
        continue;
      }
      if (line === '/compact') {
        if (this.#session !== undefined) await compactCommand(this.#session.agent, out);
        this.#lines.prompt();
        continue;
      }
      if (line === '/checkpoints' || line.startsWith('/rollback')) {
        await this.#slash(line);
        this.#lines.prompt();
        continue;
      }
      if (line.trim() === '') {
        this.#lines.prompt();
        continue;
      }
      chain = chain.then(async () => {
        await this.#turn(model, line);
        for (const queued of this.#queued.splice(0)) await this.#turn(model, queued);
        this.#lines.prompt();
      });
      pending.push(chain);
    }
    await Promise.all(pending);
  }
}

export async function runRepl(options: CliOptions, keys: KeyStore): Promise<number> {
  const repl = new Repl();
  const sessionOptions: CliOptions = {
      ...options,
      approver: repl.approver,
      mcpApprover: (server, changes) => repl.approveMcp(server, changes),
      instructionApprover: (file) => repl.approveInstruction(file),
      asker: (question) => repl.askQuestion(question),
      onEvent: (event) => {
        if (event.type === 'text') out(event.text);
        if (event.type === 'tool_input') out(`\n[${event.name}]\n`);
      },
    };
  const session = await openSession(sessionOptions, keys);
  repl.attach(session, resolvePaths(options.env).home);
  repl.delegation.setup(sessionOptions, keys, resolvePaths(options.env).home);
  for (const note of session.notes) out(`${note}\n`);
  const where = session.sandbox === null ? NOT_SANDBOXED_BANNER : `Sandboxed: a verified ${session.sandbox.kind === 'native' ? `${session.sandbox.label} (tier ${session.tier}, shell: ${session.sandbox.shell}; ${session.sandbox.layers})` : `container (tier ${session.tier})`}, working on a copy. Changes come back when you /exit.`;
  out(`${where}\nmode ${options.mode}, model ${options.model}. /exit to leave, /stop to stop a turn, /rollback to undo, /checkpoints to list, /implement <task> to delegate, /agents to list children.\n`);
  try {
    await repl.memory?.start();
    await repl.run(options.model);
  } finally {
    await repl.memory?.settle();
    await repl.closeControl();
    // After a /handoff the session to close is the new one; the old one was closed when it handed off.
    const current = repl.current ?? session;
    await current.agent.close();
    // Always closed, so MCP servers never outlive the session. For a box this also brings changes back.
    const report = await current.close((plan) => repl.approveImport(plan));
    if (report !== null) out(describeHandback(report));
    out(`\nResume with: hn --resume ${current.sessionId}\n`);
  }
  return 0;
}
