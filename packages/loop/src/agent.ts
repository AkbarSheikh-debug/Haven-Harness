import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { computeBudget, guardsFromLog } from '@hn/context';
import { FlushFailedError, SessionUnverifiedError, type EventType, type SessionEvent } from '@hn/core';
import {
  acquireSessionLock,
  closingRecords,
  parseLog,
  SessionWriter,
  type LogSeed,
  type SessionLock,
  type WriterOptions,
} from '@hn/session';
import { callModel } from './turn-api.ts';
import { beginIteration, checkBudget, closeOpenRecords, prepareIteration } from './turn-iteration.ts';
import { finishTextReply } from './turn-text.ts';
import { currentEstimate, runCompaction, type CompactContext, type CompactOutcome } from './turn-compact.ts';
import { microEnabled, runMicro, type MicroResult } from './turn-micro.ts';
import { ensureSnapshot } from './turn-instructions.ts';
import { ensureMemory, recallForTurn } from './turn-memory.ts';
import { runToolRound } from './turn-tools.ts';
import {
  TurnState,
  type Action,
  type CompactionHolder,
  type LiveLog,
  type LoopConfig,
  type TurnContext,
  type TurnResult,
} from './types.ts';

const MAX_OUTER_ERRORS = 8;

export interface OpenAgentOptions {
  readonly config: LoopConfig;
  readonly path: string;
  readonly sessionId: string;
  readonly key: Buffer;
  readonly lockDir: string;
  readonly redact?: (row: string) => string;
  readonly seed?: LogSeed;
  /**
   * Repair for a tool call a crash left open: the harness can know more than "unknown", such as a child that
   * finished on its own. Returns the result to append instead, or null to write the honest unknown.
   */
  readonly repair?: (callId: string, events: readonly SessionEvent[]) => Promise<{ readonly content: string; readonly isError: boolean; readonly origin: SessionEvent['origin'] } | null>;
  readonly writer?: Partial<Pick<WriterOptions, 'beforeWrite' | 'sync'>>;
}

async function readEvents(path: string, key: Buffer): Promise<SessionEvent[]> {
  const bytes = await readFile(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (bytes === null) return [];
  const log = parseLog(bytes, key);
  if (log.trust !== 'verified') throw new SessionUnverifiedError(path);
  return [...log.events];
}

/** One running session: the only owner of its log, driving turns through the phases. */
export class Agent {
  readonly #config: LoopConfig;
  readonly #writer: SessionWriter;
  readonly #lock: SessionLock;
  readonly #log: LiveLog;
  #closed = false;
  #steers: string[] = [];
  #notices: { text: string; origin: SessionEvent['origin'] }[] = [];
  #redirect: string | null = null;
  #turn: AbortController | null = null;
  #call: AbortController | null = null;
  readonly #compaction: CompactionHolder;
  #instructionsReady = false;

  private constructor(config: LoopConfig, writer: SessionWriter, lock: SessionLock, events: SessionEvent[]) {
    this.#config = config;
    this.#writer = writer;
    this.#lock = lock;
    // Fixed for the session, and refused here for a window under 16k, before any turn.
    const budget = computeBudget({
      window: config.caps.window,
      modelMaxOutput: config.caps.maxOutput,
      maxOutput: config.maxOutputTokens,
      ...(config.compaction?.overrides === undefined ? {} : { overrides: config.compaction.overrides }),
    });
    this.#compaction = { budget, guards: guardsFromLog(events), calibration: 1 };
    this.#log = {
      events,
      append: (type, data, origin) => {
        const event = writer.append(type, data, origin);
        events.push(event);
        return event;
      },
      flush: () => writer.flush(),
    };
  }

  /** Takes the lock, loads the log and closes anything a crash left open, all before the first turn. */
  static async open(options: OpenAgentOptions): Promise<Agent> {
    const lock = await acquireSessionLock({ sessionId: options.sessionId, lockDir: options.lockDir });
    let writer: SessionWriter | undefined;
    try {
      const events = await readEvents(options.path, options.key);
      writer = await SessionWriter.open({
        path: options.path,
        sessionId: options.sessionId,
        key: options.key,
        ...(options.redact === undefined ? {} : { redact: options.redact }),
        ...(options.seed === undefined ? {} : { seed: options.seed }),
        ...options.writer,
      });
      const agent = new Agent(options.config, writer, lock, events);
      for (const record of closingRecords(events)) {
        const fixed = record.type === 'tool/result' && options.repair !== undefined ? await options.repair(String(record.data['callId']), events).catch(() => null) : null;
        if (fixed === null) agent.#log.append(record.type, record.data, record.origin);
        else agent.#log.append(record.type, { ...record.data, content: fixed.content, isError: fixed.isError, outcome: 'recovered' }, fixed.origin);
      }
      await agent.#log.flush();
      return agent;
    } catch (error) {
      // A refused session (a bad config, a failed repair) must not leave its log file open.
      await writer?.close().catch(() => undefined);
      await lock.release();
      throw error;
    }
  }

  get events(): readonly SessionEvent[] {
    return this.#log.events;
  }

  /**
   * Adds a log-only record, such as a gate decision. Once the session has closed there is no log to add to, and a
   * record that arrives then (a background job or a child that settles as the session ends) is dropped, not thrown:
   * thrown from a promise callback it would end the whole process before the run's result was written. Nothing is lost
   * that matters, because the next open closes any job or child still open in the log as `lost`.
   */
  record(type: EventType, data: Record<string, unknown>): void {
    if (this.#closed) return;
    this.#log.append(type, data);
  }

  /** Adds a message after the newest tool result, without stopping work. */
  steer(text: string): void {
    this.#steers.push(text);
  }

  /**
   * A notice from the harness, such as a background child settling. During a turn it arrives at the next step
   * boundary; between turns it is added now and the next turn sees it. It keeps its real origin and is never the
   * user's (invariant 15).
   */
  notice(text: string, origin: Exclude<SessionEvent['origin'], 'user' | 'human-selected'>): void {
    if ((origin as string) === 'user' || (origin as string) === 'human-selected') throw new Error('A notice is never from the user.');
    if (this.#turn !== null) this.#notices.push({ text, origin });
    else this.#log.append('user/message', { text, notice: true }, origin);
  }

  /** True while a turn is running. */
  get busy(): boolean {
    return this.#turn !== null;
  }

  /** Stops the current model call, keeps what it said, and adds this correction. */
  redirect(text: string): void {
    this.#redirect = text;
    this.#call?.abort();
  }

  stop(): void {
    this.#turn?.abort();
  }

  /** After a person approves an instruction file mid-session: reload the chain and send what changed. */
  async refreshInstructions(): Promise<void> {
    const frame = await this.#config.instructions?.touched([]);
    if (frame === null || frame === undefined) return;
    this.#log.append('user/message', { text: frame.text, instructions: true, digest: frame.digest }, frame.origin);
    await this.#log.flush();
  }

  /** `/micro on|off`, kept in the log so it survives a resume. */
  setMicro(enabled: boolean): void {
    this.#log.append('command/run', { command: '/micro', enabled });
  }

  get microOn(): boolean {
    return microEnabled(this.#log.events, this.#config.compaction?.micro ?? false);
  }

  /** `/micro`: one micro fold now, between turns, whether or not micro is on. */
  async micro(): Promise<MicroResult> {
    if (this.#turn !== null) throw new Error('Micro-compaction runs between turns. Wait for this turn to end.');
    return runMicro(this.#foldContext());
  }

  /** The window as the next request will see it, and its rhythm: sawtooth (folds) or flat (micro). */
  contextStatus(): { tokens: number; window: number; rhythm: 'flat' | 'sawtooth' } {
    const tokens = currentEstimate(this.#foldContext()).tokens;
    return { tokens, window: this.#compaction.budget.window, rhythm: this.microOn ? 'flat' : 'sawtooth' };
  }

  #foldContext(): CompactContext {
    return { config: this.#config, log: this.#log, signal: new AbortController().signal, compaction: this.#compaction };
  }

  /**
   * Adds a message for the model between turns, such as a child's review from /skill-test. It carries its real
   * origin; nothing added here can claim to be the user (invariant 15).
   */
  async addContext(text: string, origin: Exclude<SessionEvent['origin'], 'user' | 'human-selected'>): Promise<void> {
    if (this.#turn !== null) throw new Error('Context is added between turns. Wait for this turn to end.');
    if ((origin as string) === 'user' || (origin as string) === 'human-selected') throw new Error('Added context is never from the user.');
    this.#log.append('user/message', { text }, origin);
    await this.#log.flush();
  }

  /** `/compact`: one fold now, between turns. It clears the cooldown and no-op backoff, as the plan says. */
  async compact(): Promise<CompactOutcome> {
    if (this.#turn !== null) throw new Error('Compaction runs between turns. Wait for this turn to end.');
    const guards = this.#compaction.guards;
    this.#compaction.guards = { ...guards, cooldownUntil: 0, noopUntil: 0 };
    return runCompaction(this.#foldContext(), 'manual');
  }

  async close(): Promise<void> {
    this.#closed = true;
    try {
      await this.#writer.close();
    } finally {
      await this.#lock.release();
    }
  }

  /**
   * One turn. `origin` is `user` for what a person typed; a turn the harness starts itself (background review) is
   * `harness`, so it never claims to be the user (invariant 15) and gets no recall. A schedule's model-written prompt is
   * `model-derived`, and a prompt from another process over a control channel is `ipc`.
   */
  async run(input: string, options: { readonly origin?: Exclude<SessionEvent['origin'], 'human-selected'> } = {}): Promise<TurnResult> {
    const origin = options.origin ?? 'user';
    const config = this.#config;
    const turn = new AbortController();
    this.#turn = turn;
    const state = new TurnState(randomUUID(), (config.now ?? Date.now)());
    const ctx: TurnContext = {
      config,
      log: this.#log,
      state,
      signal: turn.signal,
      callSignal: () => {
        this.#call = new AbortController();
        return AbortSignal.any([turn.signal, this.#call.signal]);
      },
      takeSteers: () => this.#steers.splice(0),
      takeNotices: () => this.#notices.splice(0),
      takeRedirect: () => {
        const correction = this.#redirect;
        this.#redirect = null;
        return correction;
      },
      compaction: this.#compaction,
    };

    if (!this.#instructionsReady) {
      await ensureSnapshot(config, this.#log);
      await ensureMemory(config, this.#log);
      this.#instructionsReady = true;
      for (const message of (await config.hooks?.sessionStart(turn.signal))?.messages ?? []) {
        this.#log.append('user/message', { text: message.text }, message.origin);
      }
    }
    this.#log.append('turn/start', { turnId: state.turnId });
    this.#log.append('user/message', { text: input }, origin);
    try {
      const prompt = await config.hooks?.userPrompt(input, turn.signal);
      for (const message of prompt?.messages ?? []) this.#log.append('user/message', { text: message.text }, message.origin);
      if (prompt !== undefined && prompt.blocked !== null) state.finish('refusal', `A hook blocked this prompt: ${prompt.blocked}`);
      else {
        if (origin === 'user') await recallForTurn(config, this.#log, input, turn.signal);
        await this.#runLaps(ctx);
      }
    } catch (error) {
      // A log that cannot be written means nothing else may happen, so it is not caught as a tool failure.
      if (error instanceof FlushFailedError) throw error;
      state.finish('failed', error instanceof Error ? error.message : String(error));
    }

    closeOpenRecords(ctx, state.end);
    this.#turn = null;
    // A notice that came after the last step is kept for the next turn, never dropped.
    for (const notice of this.#notices.splice(0)) this.#log.append('user/message', { text: notice.text, notice: true }, notice.origin);
    await this.#log.flush();
    if (state.end === 'done' && this.microOn) {
      const every = Math.max(1, this.#config.compaction?.microEveryNTurns ?? 1);
      const turns = this.#log.events.filter((event) => event.type === 'turn/start').length;
      if (turns % every === 0) await runMicro(this.#foldContext());
    }
    return {
      text: state.text,
      end: state.end,
      usage: state.usage,
      steps: state.apiCalls,
      ...(state.detail === undefined ? {} : { detail: state.detail }),
    };
  }

  async #runLaps(ctx: TurnContext): Promise<void> {
    const { state } = ctx;
    for (;;) {
      try {
        if ((await this.#runLap(ctx)) === 'end_turn') return;
      } catch (error) {
        if (error instanceof FlushFailedError) throw error;
        state.outerErrors += 1;
        if (state.outerErrors >= MAX_OUTER_ERRORS) throw error;
      }
    }
  }

  async #runLap(ctx: TurnContext): Promise<Action> {
    for (const phase of [beginIteration, prepareIteration]) {
      const action = phase(ctx);
      if (action !== 'next_phase') return action;
    }
    const budget = await checkBudget(ctx);
    if (budget !== 'next_phase') return budget;
    const reply = await callModel(ctx);
    if (typeof reply === 'string') return reply;
    if (ctx.signal.aborted) return ctx.state.finish('cancelled');
    return reply.stopReason === 'tool_use' ? runToolRound(ctx, reply) : finishTextReply(ctx, reply);
  }
}

export function newSessionId(): string {
  return randomUUID();
}
