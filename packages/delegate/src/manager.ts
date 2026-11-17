import { randomUUID } from 'node:crypto';
import type { SessionEvent } from '@hn/core';
import { childSpend, chargeData, familySpend, ownSpend, tokensOf } from './ledger.ts';
import { childTools, narrowMode } from './grant.ts';
import { framedReport, parseReport, unfinishedText, type ChildRun } from './report.ts';
import type { Role } from './roles.ts';
import { asUsage, childrenOf, describeChildren, finalAnswer, findChild, repairFromChildLogs } from './children.ts';
import { DEFAULT_ITERATIONS, DEFAULT_LIMITS, DelegationRefused, ITERATIONS, MAX_BRIEF_CHARS, type ChildInfo, type ChildResult, type DelegationLimits, type LaunchSpec, type ManagerOptions, type RunRequest, type TaskRequest } from './manager-types.ts';
export * from './manager-types.ts';
export * from './children.ts';

type Planned = Omit<LaunchSpec, 'childId' | 'signal' | 'tokenBudget' | 'tainted'>;
type Take = (childId: string, role: string) => number;
type Give = (childId: string) => void;

/**
 * Starts children for one root session. It decides only what the caps decide: which role,
 * how narrow, how much budget, whether there is a slot. Everything a child does passes the child's own gate, and
 * only its report comes back, as `child` data. Children are durable: each has its own log, can be woken with a
 * new message, stopped, and listed, and a crash of either side is repaired from the logs.
 */
export class SubagentManager {
  readonly #options: ManagerOptions;
  readonly limits: DelegationLimits;
  /** Children holding a slot now, with what they reserved from the family budget. */
  readonly #active = new Map<string, { readonly role: string; readonly reserved: number }>();
  /** Workflow and team children: they hold leases from their own pools, not slots, but still reserve family budget. */
  readonly #leased = new Map<string, number>();
  /** A way to stop each running child. */
  readonly #stops = new Map<string, AbortController>();
  /** Background runs, so a headless door can wait for them. */
  readonly #background = new Set<Promise<unknown>>();
  /** Background children belong to the session, not to the call that started them; this stops them all. */
  readonly #session = new AbortController();
  #backgroundStarted = 0;

  constructor(options: ManagerOptions) {
    this.#options = options;
    this.limits = { ...DEFAULT_LIMITS, ...options.limits };
  }

  get roles(): readonly Role[] {
    return this.#options.roles;
  }

  /** How many background children this session started, so a headless door knows to wait. */
  get backgroundStarted(): number {
    return this.#backgroundStarted;
  }

  get activeCount(): number {
    return this.#active.size;
  }

  role(name: string): Role {
    const role = this.#options.roles.find((candidate) => candidate.name === name);
    if (role === undefined) throw new DelegationRefused(`There is no role called "${name}". Roles: ${this.#options.roles.map((r) => r.name).join(', ')}.`);
    return role;
  }

  /** The refusals that apply before anything starts: depth and capacity. Reject, never queue. */
  #checkCanStart(slots: number): void {
    if (this.#options.nested || this.limits.maxDepth < 1) {
      throw new DelegationRefused(this.limits.maxDepth < 1 ? 'Delegation is turned off for this session (maxDepth 0).' : 'A child session cannot start another child (the depth limit is 1).');
    }
    const free = this.limits.maxActive - this.#active.size;
    if (slots > free) {
      throw new DelegationRefused(
        `${this.#active.size} of ${this.limits.maxActive} child sessions are already running, so ${slots === 1 ? 'another one' : `${slots} more`} cannot start. Nothing was started. Wait for one to finish, or stop one with interrupt_agent.`,
      );
    }
  }

  /** What one child may spend: the per-child cap, cut to what the family has left after every active reservation. */
  #budgetFor(cap: number = this.limits.childTokens): number {
    const spent = tokensOf(familySpend(this.#options.events()));
    const reserved = [...this.#active.values()].reduce((sum, child) => sum + child.reserved, 0) + [...this.#leased.values()].reduce((sum, value) => sum + value, 0);
    const left = this.limits.familyTokens - spent - reserved;
    const budget = Math.min(this.limits.childTokens, cap, left);
    if (budget < this.limits.minChildTokens) {
      throw new DelegationRefused(`The family token budget is spent (${spent.toLocaleString('en-US')} used, ${reserved.toLocaleString('en-US')} reserved by running children, of ${this.limits.familyTokens.toLocaleString('en-US')}). No child was started.`);
    }
    return budget;
  }

  /** Validates a request against the model's capabilities and the caps before any process starts. */
  plan(task: TaskRequest, request: RunRequest): Planned {
    const role = this.role(task.agent);
    const brief = task.task.trim();
    if (brief === '' || brief.length > MAX_BRIEF_CHARS) throw new DelegationRefused(`A task must be 1 to ${MAX_BRIEF_CHARS} characters.`);
    const { model, caps } = this.#options.resolveModel(role);
    if (request.start === 'fork') {
      const needed = this.#options.contextTokens();
      // The child must hold the parent's history plus room to work: at least a quarter of its window left over.
      if (needed > caps.window * 0.75) {
        throw new DelegationRefused(`A fork would give the ${role.name} child ${needed.toLocaleString('en-US')} tokens of history, more than its model (${model}, window ${caps.window.toLocaleString('en-US')}) can work with. Use start: "spawn" with a complete task instead.`);
      }
    }
    const narrowed = narrowMode(this.#options.parentMode(), role.mode, { tier: this.#options.tier, parentAllow: this.#options.parentAllow, roleTools: role.tools });
    return {
      role,
      model,
      brief,
      mode: narrowed.mode,
      allow: narrowed.allow,
      tools: [...childTools(this.#options.parentTools(), role.tools), ...(request.team === undefined ? [] : ['team_task', 'team_message'])],
      maxIterations: ITERATIONS[role.name] ?? DEFAULT_ITERATIONS,
      fork: request.start === 'fork',
      resume: false,
      workdir: request.workdir ?? null,
      ...(request.team === undefined ? {} : { team: request.team }),
    };
  }

  /**
   * Takes `slots` slots for the length of `work`, or refuses at once. The check and the reservation happen before
   * this returns, so two calls in one message cannot both see the same free slots, and a refusal is never late.
   */
  #withSlots<T>(slots: number, work: (take: Take, give: Give) => Promise<T>): Promise<T> {
    this.#checkCanStart(slots);
    const holders = Array.from({ length: slots }, () => `slot-${randomUUID()}`);
    for (const holder of holders) this.#active.set(holder, { role: 'starting', reserved: 0 });
    const take: Take = (childId, role) => {
      const holder = holders.pop();
      if (holder !== undefined) this.#active.delete(holder);
      try {
        const reserved = this.#budgetFor();
        this.#active.set(childId, { role, reserved });
        return reserved;
      } catch (error) {
        if (holder !== undefined) {
          holders.push(holder);
          this.#active.set(holder, { role: 'starting', reserved: 0 });
        }
        throw error;
      }
    };
    const give: Give = (childId) => {
      if (!this.#active.delete(childId)) return;
      const holder = `slot-${randomUUID()}`;
      holders.push(holder);
      this.#active.set(holder, { role: 'starting', reserved: 0 });
    };
    return (async () => {
      try {
        return await work(take, give);
      } finally {
        for (const holder of holders) this.#active.delete(holder);
      }
    })();
  }

  /** Runs one planned child in a held slot and turns whatever happened into a result. */
  async #runOne(planned: Planned, tainted: boolean, signal: AbortSignal, take: Take, give: Give, extra: { readonly childId?: string; readonly callId?: string } = {}): Promise<ChildResult> {
    const childId = extra.childId ?? randomUUID();
    let tokenBudget: number;
    try {
      tokenBudget = take(childId, planned.role.name);
    } catch (error) {
      // A refusal here (the family budget) belongs to this task only; lanes already running keep their slots.
      if (!(error instanceof DelegationRefused)) throw error;
      return { childId, role: planned.role.name, ok: false, content: error.message, report: null, cancelled: false };
    }
    const stop = new AbortController();
    this.#stops.set(childId, stop);
    const childSignal = AbortSignal.any([signal, stop.signal]);
    const spec: LaunchSpec = { ...planned, childId, tokenBudget, tainted: tainted || this.#options.tainted(), signal: childSignal };
    this.#options.record('subagent/catalog', {
      kind: planned.resume ? 'message' : 'spawned',
      child: childId,
      role: planned.role.name,
      roleHash: planned.role.hash,
      mode: planned.mode,
      model: planned.model,
      start: planned.resume ? 'resume' : planned.fork ? 'fork' : 'spawn',
      budget: tokenBudget,
      brief: planned.brief.slice(0, 500),
      ...(extra.callId === undefined ? {} : { callId: extra.callId }),
    });
    let run: ChildRun;
    try {
      await this.#options.onStart?.(planned.brief, childSignal);
      run = await this.#options.launch(spec);
    } catch (error) {
      run = { code: null, stdout: '', stderr: error instanceof Error ? error.message : String(error), timedOut: false, cancelled: childSignal.aborted, logPath: '' };
    } finally {
      give(childId);
      this.#stops.delete(childId);
    }
    const report = parseReport(run.stdout);
    if (report !== null) this.#options.record('budget/charge', chargeData(childId, planned.model, asUsage(report.usage), planned.resume ? 'message' : 'settled'));
    this.#options.record('subagent/catalog', {
      kind: 'settled',
      child: childId,
      role: planned.role.name,
      end: run.cancelled ? 'cancelled' : (report?.end ?? (run.timedOut ? 'timeout' : 'lost')),
      steps: report?.steps ?? 0,
      code: run.code,
    });
    await this.#options.onStop?.(report?.text ?? '', signal).catch(() => undefined);
    if (report === null || run.cancelled) {
      return { childId, role: planned.role.name, ok: false, content: unfinishedText(run, this.limits.timeoutMs), report: null, cancelled: run.cancelled };
    }
    return { childId, role: planned.role.name, ok: report.end === 'done', content: framedReport(report, planned.role.name, run.logPath), report, cancelled: false };
  }

  /**
   * A child that holds a lease from its caller's own pool of `poolSize` instead of one of the eight slots (workflow
   * and team children). Each takes at most 1/poolSize of the family budget, so a full pool always fits.
   */
  async leased(task: TaskRequest, request: RunRequest, signal: AbortSignal, childId?: string, poolSize = 1): Promise<ChildResult> {
    if (this.#options.nested || this.limits.maxDepth < 1) throw new DelegationRefused('A child session cannot start another child (the depth limit is 1).');
    const planned = this.plan(task, request);
    const take = (id: string): number => {
      const budget = this.#budgetFor(Math.floor(this.limits.familyTokens / Math.max(1, poolSize)));
      this.#leased.set(id, budget);
      return budget;
    };
    return this.#runOne(planned, false, signal, take, (id) => void this.#leased.delete(id), { ...(childId === undefined ? {} : { childId }), ...(request.callId === undefined ? {} : { callId: request.callId }) });
  }

  async single(task: TaskRequest, request: RunRequest, signal: AbortSignal): Promise<ChildResult> {
    const planned = this.plan(task, request);
    return this.#withSlots(1, (take, give) => this.#runOne(planned, false, signal, take, give, request.callId === undefined ? {} : { callId: request.callId }));
  }

  /**
   * One child in the background: the call returns at once with the child's id, and the report arrives later as a
   * notice. The child is not tied to the call that started it, only to the session; it still holds its slot.
   */
  background(task: TaskRequest, request: RunRequest): string {
    const sessionSignal = this.#session.signal;
    const planned = this.plan(task, request);
    const childId = randomUUID();
    const run = this.#withSlots(1, (take, give) => this.#runOne(planned, false, sessionSignal, take, give, { childId, ...(request.callId === undefined ? {} : { callId: request.callId }) }));
    this.#track(run);
    return childId;
  }

  #track(run: Promise<ChildResult>): void {
    this.#backgroundStarted += 1;
    const settled = run.then(
      (result) => this.#options.notify?.(`A background child settled (${result.role} ${result.childId}).\n${result.content}`),
      (error: unknown) => this.#options.notify?.(`A background child failed to run: ${error instanceof Error ? error.message : String(error)}`),
    );
    this.#background.add(settled);
    void settled.finally(() => this.#background.delete(settled));
  }

  /** `parallel`: up to 8 tasks, at most 4 at once, results in input order. Every task is checked before any starts. */
  async parallel(tasks: readonly TaskRequest[], request: RunRequest, signal: AbortSignal): Promise<ChildResult[]> {
    if (tasks.length === 0 || tasks.length > this.limits.maxParallelTasks) throw new DelegationRefused(`parallel takes 1 to ${this.limits.maxParallelTasks} tasks.`);
    const planned = tasks.map((task) => this.plan(task, request));
    const width = Math.min(this.limits.maxConcurrency, planned.length);
    const extra = request.callId === undefined ? {} : { callId: request.callId };
    // Writers never share a checkout: each gets a private clone, or the call is refused before anything starts.
    const writes = (task: Planned): boolean => task.mode !== 'read-only';
    const isolate = planned.length > 1 && planned.some(writes);
    if (isolate) {
      const workspaces = this.#options.workspaces;
      const problem = workspaces === undefined ? 'this session has no private workspaces (it runs in a box or without git)' : await workspaces.check();
      if (problem !== null) throw new DelegationRefused(`Parallel children that can change files each need a private clone, and ${problem}. Nothing was started. Run the writers one at a time or as a chain, or make the parallel tasks read-only roles.`);
    }
    const ids = planned.map(() => randomUUID());
    const results = await this.#withSlots(width, async (take, give) => {
      const out: ChildResult[] = new Array(planned.length);
      let next = 0;
      const lane = async (): Promise<void> => {
        for (let index = next++; index < planned.length; index = next++) {
          const task = planned[index]!;
          const id = ids[index]!;
          const workdir = isolate && writes(task) ? await this.#options.workspaces!.create(id) : task.workdir;
          out[index] = await this.#runOne({ ...task, workdir }, false, signal, take, give, { ...extra, childId: id });
        }
      };
      await Promise.all(Array.from({ length: width }, lane));
      return out;
    });
    if (!isolate) return results;
    // The merge queue: writers land in input order; one that no longer applies is reported, never forced.
    const landed: ChildResult[] = [];
    for (const [index, result] of results.entries()) {
      if (!writes(planned[index]!)) {
        landed.push(result);
        continue;
      }
      const landing = await this.#options.workspaces!.land(result.childId, `${result.role} ${result.childId}: ${planned[index]!.brief.slice(0, 200)}`);
      landed.push({ ...result, ok: result.ok && landing.ok, content: `${result.content}\n${landing.text}` });
    }
    return landed;
  }

  /**
   * `chain`: steps one after another on one slot. `{previous}` in a step becomes the previous step's report, which
   * is child data, so every step that receives it starts tainted. A step that fails ends the chain.
   */
  async chain(steps: readonly TaskRequest[], request: RunRequest, signal: AbortSignal): Promise<ChildResult[]> {
    if (steps.length === 0 || steps.length > this.limits.maxChainSteps) throw new DelegationRefused(`chain takes 1 to ${this.limits.maxChainSteps} steps.`);
    for (const step of steps) this.plan({ agent: step.agent, task: step.task.replaceAll('{previous}', '') || 'x' }, request);
    const extra = request.callId === undefined ? {} : { callId: request.callId };
    return this.#withSlots(1, async (take, give) => {
      const results: ChildResult[] = [];
      let previous: string | null = null;
      for (const [index, step] of steps.entries()) {
        const brief = previous === null ? step.task : step.task.includes('{previous}') ? step.task.replaceAll('{previous}', previous) : `${step.task}\n\nThe previous step reported:\n${previous}`;
        const planned = this.plan({ agent: step.agent, task: brief.slice(0, MAX_BRIEF_CHARS) }, index === 0 ? request : { ...request, start: 'spawn' });
        const result = await this.#runOne(planned, previous !== null, signal, take, give, extra);
        results.push(result);
        if (!result.ok || result.report === null) break;
        previous = result.report.text;
      }
      return results;
    });
  }

  /** The children of this session, from its log: id, role, status, spend. */
  list(): ChildInfo[] {
    return [...childrenOf(this.#options.events()).values()].map((child) => (this.#stops.has(child.id) ? { ...child, status: 'running' as const } : child));
  }

  /** A child named by its full id or by a unique prefix of at least 8 characters. */
  find(reference: string): ChildInfo {
    return findChild(this.list(), reference);
  }

  /**
   * `send_message`: wakes a child that is not running with a new turn on its own log (a cold resume, so it works
   * after a restart too). Its role must still be the one it was started as; it gets a fresh grant, narrowed now.
   */
  async sendMessage(reference: string, message: string, signal: AbortSignal, options: { readonly background?: boolean; readonly callId?: string } = {}): Promise<ChildResult | string> {
    const child = this.find(reference);
    if (child.status === 'running') throw new DelegationRefused(`Child ${child.id} is still running. Wait for its report, or stop it with interrupt_agent.`);
    const role = this.role(child.role);
    if (role.hash !== child.roleHash) throw new DelegationRefused(`The ${role.name} role has changed since child ${child.id} started, so it is not woken under the new one. Start a new child instead.`);
    const planned: Planned = { ...this.plan({ agent: role.name, task: message }, { start: 'spawn' }), resume: true };
    const extra = { childId: child.id, ...(options.callId === undefined ? {} : { callId: options.callId }) };
    if (options.background === true) {
      this.#track(this.#withSlots(1, (take, give) => this.#runOne(planned, false, this.#session.signal, take, give, extra)));
      return child.id;
    }
    return this.#withSlots(1, (take, give) => this.#runOne(planned, false, signal, take, give, extra));
  }

  /** `interrupt_agent`: stops a running child. Its log stays, and send_message can wake it later. */
  interrupt(reference: string): boolean {
    const child = this.find(reference);
    const stop = this.#stops.get(child.id);
    if (stop === undefined) return false;
    stop.abort();
    return true;
  }

  /** Waits for background children, up to `timeoutMs`. Resolves true when none is left. */
  async drain(timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (this.#background.size > 0) {
      const left = deadline - Date.now();
      if (left <= 0) return false;
      await Promise.race([Promise.all([...this.#background]), new Promise((resolve) => setTimeout(resolve, left).unref())]);
    }
    return true;
  }

  stopAll(): void {
    this.#session.abort();
    for (const stop of this.#stops.values()) stop.abort();
  }

  /**
   * After the parent restarts: any child the log says started but never settled is settled now from what its own
   * log says. A child that finished is `done` with its spend charged; one that did not is `lost`, and can be woken.
   */
  async recover(): Promise<number> {
    let fixed = 0;
    for (const child of childrenOf(this.#options.events()).values()) {
      if (child.status !== 'running' || this.#stops.has(child.id)) continue;
      const events = (await this.#options.childLog?.(child.id).catch(() => null)) ?? null;
      const answer = events === null ? null : finalAnswer(events);
      const end = answer === null ? 'lost' : answer.end;
      if (events !== null && answer !== null) {
        const spend = ownSpend(events);
        this.#options.record('budget/charge', { ...chargeData(child.id, 'recovered', spend, 'recovered'), dollars: spend.dollars });
      }
      this.#options.record('subagent/catalog', { kind: 'settled', child: child.id, role: child.role, end, recovered: true });
      fixed += 1;
    }
    return fixed;
  }

  /** Repair for an unfinished `subagent` call, from the children's own logs (see `repairFromChildLogs`). */
  async repairResult(callId: string, events: readonly SessionEvent[]): Promise<{ content: string; isError: boolean; origin: 'child' | 'harness' } | null> {
    return repairFromChildLogs(callId, events, this.#options.childLog);
  }

  /** One line per child, for `list_agents` and the REPL. */
  describe(): string {
    return describeChildren(this.list(), childSpend(this.#options.events()));
  }
}
