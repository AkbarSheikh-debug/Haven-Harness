import type { EventType, Origin, SessionEvent } from '@hn/core';
import type { Harvest, Workspaces } from '@hn/operations';
import { EMPTY_SNAPSHOT, LEAD, applyAction, describeTasks, releaseAll, type ApplyResult, type TeamAction, type TeamSnapshot } from './team-graph.ts';

export const MAX_MEMBERS = 16;
const NAME = /^[a-z][a-z0-9-]{0,31}$/;

export type MemberState = 'provisioning' | 'active' | 'stopped' | 'failed';

export interface MemberInfo {
  readonly name: string;
  readonly state: MemberState;
  readonly base?: string;
}

/** What it takes to run one member: a child in its own clone, with a team grant. Resolves when the member's run ends. */
export type MemberLauncher = (member: { readonly name: string; readonly brief: string; readonly workdir: string }, signal: AbortSignal) => Promise<{ readonly ok: boolean; readonly text: string }>;

export interface TeamOptions {
  /** Clones and the merge queue, under `refs/hn/team`. */
  readonly workspaces: Workspaces;
  readonly launch: MemberLauncher;
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  readonly events: () => readonly SessionEvent[];
  /** Something the Lead should read: a member settled, a message for the lead, a merge result. */
  readonly notify: (text: string, origin: Exclude<Origin, 'user' | 'human-selected'>) => void;
  readonly maxMembers?: number;
}

/** The roster, folded from `team/member` rows. Names are never reused, whatever happened to their first owner. */
export function rosterOf(events: readonly SessionEvent[]): Map<string, MemberInfo> {
  const roster = new Map<string, MemberInfo>();
  for (const event of events) {
    if (event.type !== 'team/member' || typeof event.data['name'] !== 'string') continue;
    const name = event.data['name'];
    const before = roster.get(name);
    const base = typeof event.data['base'] === 'string' ? event.data['base'] : before?.base;
    roster.set(name, { name, state: event.data['state'] as MemberState, ...(base === undefined ? {} : { base }) });
  }
  return roster;
}

/** The newest whole snapshot of the task graph. */
export function snapshotOf(events: readonly SessionEvent[]): TeamSnapshot {
  const row = events.findLast((event) => event.type === 'team/task' && typeof event.data['snapshot'] === 'object');
  return (row?.data['snapshot'] as TeamSnapshot | undefined) ?? EMPTY_SNAPSHOT;
}

/** Where the queue last left the branch, from the `team/merge` rows. */
function queueHead(events: readonly SessionEvent[]): string | null {
  const row = events.findLast((event) => event.type === 'team/merge' && typeof event.data['head'] === 'string');
  return (row?.data['head'] as string | undefined) ?? null;
}

/**
 * An agent team (11.5): the root session is the Lead. Members are children, each in its own clone with its own refs;
 * the graph and the roster live in the Lead's log; messages arrive at a member's step boundaries carrying their origin;
 * the Lead owns the merge queue, and only the queue moves the project's branch.
 */
export class Team {
  readonly #options: TeamOptions;
  readonly #ports = new Map<string, (message: unknown) => void>();
  readonly #running = new Map<string, Promise<void>>();
  readonly #pendingEvents: string[] = [];
  readonly #waiters: (() => void)[] = [];
  readonly #stop = new AbortController();
  #queue: Promise<unknown> = Promise.resolve();
  /** Completions still committing and fetching a member's work. Their merges are not queued yet, so idle waits for them. */
  readonly #completing = new Set<Promise<unknown>>();
  #halted: string | null = null;

  constructor(options: TeamOptions) {
    this.#options = options;
  }

  get roster(): Map<string, MemberInfo> {
    return rosterOf(this.#options.events());
  }

  get snapshot(): TeamSnapshot {
    return snapshotOf(this.#options.events());
  }

  /** Why the queue stopped, or null while it runs. */
  get halted(): string | null {
    return this.#halted;
  }

  /** News for the Lead, once: to a `wait_agent` that is waiting, or else as a notice at its next step. */
  #event(text: string, origin: Exclude<Origin, 'user' | 'human-selected'> = 'harness'): void {
    if (this.#waiters.length === 0) {
      this.#options.notify(text, origin);
      return;
    }
    this.#pendingEvents.push(text);
    for (const wake of this.#waiters.splice(0)) wake();
  }

  #member(name: string, state: MemberState, extra: Record<string, unknown> = {}): void {
    this.#options.record('team/member', { name, state, ...extra });
  }

  /** A member's channel to the Lead opens or closes: the route for its inbox. */
  port(name: string, send: ((message: unknown) => void) | null): void {
    if (send === null) this.#ports.delete(name);
    else this.#ports.set(name, send);
  }

  /** Starts a member. Refused for a used name, a full roster, or a project the queue cannot merge into. */
  async addMember(name: string, brief: string): Promise<string> {
    if (!NAME.test(name)) throw new Error('A member name is lowercase letters, digits or hyphens, starting with a letter.');
    const roster = this.roster;
    if (roster.has(name)) throw new Error(`The name ${name} is already used in this team, and names are never reused.`);
    if (roster.size >= (this.#options.maxMembers ?? MAX_MEMBERS)) throw new Error(`A team has at most ${this.#options.maxMembers ?? MAX_MEMBERS} members.`);
    const problem = await this.#options.workspaces.check();
    if (problem !== null) throw new Error(`Team members each need a private clone, and ${problem}.`);
    if (queueHead(this.#options.events()) === null) this.#options.record('team/merge', { kind: 'start', head: (await this.#options.workspaces.head()).commit });
    this.#member(name, 'provisioning');
    let workdir: string;
    let base: string;
    try {
      ({ path: workdir, base } = await this.#options.workspaces.create(name));
    } catch (error) {
      this.#member(name, 'failed', { why: error instanceof Error ? error.message : String(error) });
      throw error;
    }
    this.#member(name, 'active', { base });
    const run = this.#options.launch({ name, brief, workdir }, this.#stop.signal).then(
      (result) => this.#settle(name, result.ok, result.text),
      (error: unknown) => this.#settle(name, false, error instanceof Error ? error.message : String(error)),
    );
    this.#running.set(name, run);
    return `Started ${name} in its own clone. It reports through the task graph and messages; wait_agent waits for news.`;
  }

  /** A member's run ended: its claims go back to open (11.5), and the Lead hears how it went. */
  #settle(name: string, ok: boolean, text: string): void {
    this.#running.delete(name);
    this.#ports.delete(name);
    this.#member(name, ok ? 'stopped' : 'failed', ok ? {} : { why: text.slice(0, 500) });
    const before = this.snapshot;
    const after = releaseAll(before, name);
    if (after !== before) this.#options.record('team/task', { by: LEAD, why: `${name} stopped`, snapshot: after as never });
    this.#event(`Member ${name} ${ok ? 'finished' : 'stopped without finishing'}${after !== before ? '; its claimed tasks are open again' : ''}.\n<member-report name="${name}">\n${text.slice(0, 4_000).replace(/<\/member-report/gi, '<\\/member-report')}\n</member-report>`, 'child');
  }

  /** One write to the graph, recorded as a whole snapshot. */
  apply(actor: string, action: TeamAction, origin: Origin): ApplyResult {
    const result = applyAction(this.snapshot, action, actor, origin);
    if (result.ok) this.#options.record('team/task', { by: actor, action: action.kind, task: result.task.id, snapshot: result.snapshot as never });
    return result;
  }

  /**
   * A member completes a task: the Lead commits what is in its clone, fetches it into `refs/hn/team/<member>/<task>`,
   * checks the write scope, and queues the merge. The member's own word about what it changed is not used.
   */
  async complete(member: string, action: Extract<TeamAction, { kind: 'complete' }>): Promise<ApplyResult> {
    const task = this.snapshot.tasks.find((candidate) => candidate.id === action.id);
    if (task === undefined || task.owner !== member || task.status !== 'claimed') return applyAction(this.snapshot, action, member, 'child');
    const base = this.roster.get(member)?.base;
    let harvest: Harvest | null = null;
    if (base !== undefined) {
      const harvesting = this.#options.workspaces.harvest(member, base, `${task.id}: ${task.title} (by ${member})`, `${member}/${task.id}`);
      this.#completing.add(harvesting);
      try {
        harvest = await harvesting;
      } finally {
        this.#completing.delete(harvesting);
      }
    }
    const result = this.apply(member, { ...action, changed: harvest?.files ?? [] }, 'child');
    if (result.ok && harvest !== null) {
      this.#member(member, 'active', { base: harvest.commit });
      this.#enqueue(member, task.id, task.title, harvest);
    }
    return result;
  }

  #enqueue(member: string, taskId: string, title: string, harvest: Harvest): void {
    const step = this.#queue.then(() => this.#merge(member, taskId, title, harvest));
    this.#queue = step.catch(() => undefined);
  }

  /** The merge queue, one at a time and in order. A conflict becomes a task holding the ref, so no work is lost. */
  async #merge(member: string, taskId: string, title: string, harvest: Harvest): Promise<void> {
    if (this.#halted !== null) {
      this.#options.record('team/merge', { kind: 'held', member, task: taskId, ref: harvest.ref, why: this.#halted });
      return;
    }
    const expected = queueHead(this.#options.events()) ?? (await this.#options.workspaces.head()).commit;
    const merged = await this.#options.workspaces.mergeIntoHead(harvest.ref, expected, `Merge ${taskId} (${title.slice(0, 120)}) from ${member}`);
    if (merged.ok) {
      this.#options.record('team/merge', { kind: 'merged', member, task: taskId, ref: harvest.ref, head: merged.head });
      this.#event(`Merged ${taskId} from ${member}.`);
      return;
    }
    if (merged.kind === 'conflict') {
      this.#options.record('team/merge', { kind: 'conflict', member, task: taskId, ref: harvest.ref, why: merged.why });
      const created = this.apply(LEAD, { kind: 'create', title: `Resolve merge conflict: ${title}`.slice(0, 200), detail: `The work for ${taskId} by ${member} conflicts with what was merged first (${merged.why}). It is kept at ${harvest.ref}.`, ref: harvest.ref }, 'child');
      this.#event(`The merge of ${taskId} from ${member} conflicted; ${created.ok ? `task ${created.task.id} holds it at ${harvest.ref}` : 'its work is kept at ' + harvest.ref}.`, 'child');
      return;
    }
    // The branch moved outside the queue, or the tree is dirty: stop merging and say so; nothing is forced.
    this.#halted = `${merged.kind}: ${merged.why}`;
    this.#options.record('team/merge', { kind: 'halted', member, task: taskId, ref: harvest.ref, why: this.#halted });
    this.#event(`The merge queue stopped (${this.#halted}). The work for ${taskId} is kept at ${harvest.ref}.`);
  }

  /** A message to a member (pushed to its inbox if it is running) or to the lead. Always logged with its origin. */
  message(from: string, to: string, text: string, origin: Exclude<Origin, 'user' | 'human-selected'>): string {
    const body = text.slice(0, 8_000);
    this.#options.record('team/message', { from, to, text: body, origin });
    if (to === LEAD) {
      this.#event(`Message from ${from}:\n<team-message from="${from}">\n${body.replace(/<\/team-message/gi, '<\\/team-message')}\n</team-message>`, origin);
      return 'Sent to the lead.';
    }
    if (!this.roster.has(to)) throw new Error(`There is no member ${to}.`);
    const port = this.#ports.get(to);
    if (port === undefined) return `${to} is not running, so the message is logged but not delivered.`;
    port({ kind: 'inbox', text: `Message from ${from}:\n<team-message from="${from}">\n${body.replace(/<\/team-message/gi, '<\\/team-message')}\n</team-message>`, origin });
    return `Delivered to ${to}'s inbox.`;
  }

  /** What a member asks of the Lead over its channel. Anything not understood is refused. */
  async memberRequest(member: string, request: Readonly<Record<string, unknown>>): Promise<unknown> {
    if (request['op'] === 'list') return describeTasks(this.snapshot);
    if (request['op'] === 'message') return this.message(member, String(request['to'] ?? ''), String(request['text'] ?? ''), 'child');
    if (request['op'] !== 'task') throw new Error('Unknown team request.');
    const action = request['action'] as TeamAction;
    if (typeof action !== 'object' || action === null) throw new Error('A task request needs an action.');
    const result = action.kind === 'complete' ? await this.complete(member, action) : this.apply(member, action, 'child');
    if (!result.ok) throw new Error(`${result.code}: ${result.message}`);
    return [`${result.task.id} is now ${result.task.status} (revision ${result.task.revision}).`, ...result.warnings].join('\n');
  }

  /** `wait_agent`: until something happens in the team, or the time runs out (10 s to 1 h). */
  async wait(seconds: number, signal: AbortSignal): Promise<string> {
    const ms = Math.max(10, Math.min(3_600, Number.isFinite(seconds) ? seconds : 60)) * 1_000;
    if (this.#pendingEvents.length === 0 && (this.#running.size > 0 || !(await this.idle(0)))) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, ms);
        const done = (): void => {
          clearTimeout(timer);
          signal.removeEventListener('abort', done);
          resolve();
        };
        this.#waiters.push(done);
        signal.addEventListener('abort', done, { once: true });
      });
    }
    const news = this.#pendingEvents.splice(0);
    return news.length === 0 ? 'Nothing happened in the team in that time.' : news.join('\n\n');
  }

  /** True once no member is running and the merge queue is empty, waiting up to `ms`. */
  async idle(ms: number): Promise<boolean> {
    const deadline = Date.now() + ms;
    for (;;) {
      // Found on a slow CI runner: a member can finish while the Lead is still harvesting its last task, whose merge
      // is queued only afterwards, so idle waits for those too, then for the queue, and checks again.
      if (this.#running.size === 0) {
        await Promise.allSettled([...this.#completing]);
        await this.#queue;
        if (this.#running.size === 0 && this.#completing.size === 0) return true;
      }
      const left = deadline - Date.now();
      if (left <= 0) return false;
      await Promise.race([Promise.all([...this.#running.values()]), new Promise((resolve) => setTimeout(resolve, Math.min(left, 1_000)))]);
    }
  }

  stop(): void {
    this.#stop.abort();
  }
}
