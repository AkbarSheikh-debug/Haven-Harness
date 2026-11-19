import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULTS, projectKey, resolvePaths } from '@hn/config';
import { HnError, type Origin } from '@hn/core';
import { newSessionId, spentTokens, type TurnResult } from '@hn/loop';
import { KeyStore } from '@hn/provider';
import type { ImportPlan } from '@hn/operations';
import { forkSession, loadOrCreateLogKey, parseLog } from '@hn/session';
import { openSessionControl, type ControlChannel } from './control.ts';
import { openSession } from './session.ts';
import type { CliOptions, OpenSession } from './session-types.ts';
import type { FinishReport } from './sandbox.ts';

export interface HarnessOptions extends Omit<CliOptions, 'mode' | 'model'> {
  /** Default `read-only`: an SDK caller has no person at a terminal unless it passes an approver. */
  readonly mode?: string;
  readonly model?: string;
  /**
   * `false` runs on a throwaway home removed at close: no log, memory, approvals, trust or audit outlive the
   * instance (the website case, slide 15). Default `true`.
   */
  readonly persist?: boolean;
  /** The model keys. Default: taken out of this process's environment once, so nothing spawned later inherits them. */
  readonly keys?: KeyStore;
  /** Open the control channel, so `hn steer` and `hn stop` reach this session from another process (section 11.6). */
  readonly control?: boolean;
}

export interface RunOptions {
  /** Who wrote the prompt. Default `user`: the program holding the instance is the person at this door. */
  readonly origin?: Exclude<Origin, 'human-selected'>;
  /** How long to wait for background children started in this run before stopping them. 0 does not wait. */
  readonly waitForChildrenMs?: number;
}

export interface HarnessResult extends TurnResult {
  readonly sessionId: string;
}

export interface HarnessState {
  readonly sessionId: string;
  readonly busy: boolean;
  readonly mode: string;
  readonly tier: number;
  readonly turns: number;
  /** Tokens in the window the next request would send. */
  readonly contextTokens: number;
  /** Every token this session's own model calls used, from its log. */
  readonly spentTokens: number;
}

let processKeys: KeyStore | null = null;
const defaultKeys = (): KeyStore => (processKeys ??= KeyStore.capture());

/**
 * One harness, behind every door (section 12): the `-p` door, JSON-RPC, the fleet, schedules and ralph each hold
 * one. It decides nothing; `openSession` plugs the modules into their sockets. Two instances share nothing: each has
 * its own log, gate, jail, taint and backend, and its tools see only its own session id.
 */
export class Harness {
  readonly #options: HarnessOptions;
  #opening: Promise<OpenSession> | null = null;
  #session: OpenSession | null = null;
  #home: string | null = null;
  #closed: Promise<FinishReport | null> | null = null;
  #control: ControlChannel | null = null;

  constructor(options: HarnessOptions) {
    if (typeof options.workdir !== 'string' || options.workdir === '') throw new HnError('BAD_WORKDIR', 'A harness needs a working folder.');
    this.#options = options;
  }

  /** The control channel's endpoint while it is open, or null. */
  get control(): ControlChannel | null {
    return this.#control;
  }

  /** The open session, or null before the first `open` or `run`. Doors that need more than `run` use it. */
  get session(): OpenSession | null {
    return this.#session;
  }

  get sessionId(): string | null {
    return this.#session?.sessionId ?? null;
  }

  /** With `persist: false`, the throwaway home while the instance is open; otherwise null. */
  get throwawayHome(): string | null {
    return this.#home;
  }

  /** Opens the session once; later calls get the same one. */
  open(): Promise<OpenSession> {
    if (this.#closed !== null) return Promise.reject(new HnError('HARNESS_CLOSED', 'This harness is closed.'));
    this.#opening ??= this.#open().catch(async (error: unknown) => {
      this.#opening = null;
      await this.#removeHome();
      throw error;
    });
    return this.#opening;
  }

  async #open(): Promise<OpenSession> {
    const { persist, keys, mode, model, env, control, ...rest } = this.#options;
    let sessionEnv = env;
    if (persist === false) {
      this.#home = await mkdtemp(join(tmpdir(), 'hn-harness-'));
      sessionEnv = { ...(env ?? process.env), HN_HOME: this.#home };
    }
    const session = await openSession(
      { ...rest, mode: mode ?? 'read-only', model: model ?? DEFAULTS.mainModel, ...(sessionEnv === undefined ? {} : { env: sessionEnv }) },
      keys ?? defaultKeys(),
    );
    this.#session = session;
    if (control === true) {
      try {
        this.#control = await openSessionControl(resolvePaths(sessionEnv).home, session);
      } catch (error) {
        await session.agent.close();
        await session.close();
        throw error;
      }
    }
    return session;
  }

  /** One turn. Background children it started are waited for, then the model gets one more turn to use their reports. */
  async run(prompt: string, options: RunOptions = {}): Promise<HarnessResult> {
    const session = await this.open();
    const origin = options.origin ?? 'user';
    // Under the Rule of Two only URLs a person typed may be fetched unseen.
    if (origin === 'user') session.egress.noteUserText(prompt);
    // A prompt a model or another process wrote leaves the session as untrusted as its writer, before the first step.
    else if (origin !== 'harness') session.observe(origin);
    const started = session.subagents.backgroundStarted;
    let result = await session.agent.run(prompt, { origin });
    const wait = options.waitForChildrenMs ?? 0;
    if (wait > 0 && session.subagents.backgroundStarted > started) {
      const settled = await session.subagents.drain(wait);
      if (!settled) session.subagents.stopAll();
      else if (result.end === 'done') result = await session.agent.run('Background children have settled; their reports are above. Use them to finish the task.', { origin: 'harness' });
    }
    return { ...result, sessionId: session.sessionId };
  }

  /** A message for the running turn, after the newest tool result. From the program holding the instance, so `user`. */
  steer(text: string): void {
    this.#session?.agent.steer(text);
  }

  stop(): void {
    this.#session?.agent.stop();
  }

  async state(): Promise<HarnessState> {
    const session = await this.open();
    const events = session.agent.events;
    return {
      sessionId: session.sessionId,
      busy: session.agent.busy,
      mode: session.gate.mode,
      tier: session.tier,
      turns: events.filter((event) => event.type === 'turn/start').length,
      contextTokens: session.agent.contextStatus().tokens,
      spentTokens: spentTokens(events),
    };
  }

  /**
   * Copies this session up to its newest closed step into a new session and returns the new id; this one goes on
   * untouched. Open the copy with a new `Harness` and `sessionId`. Both logs name each other.
   */
  async fork(): Promise<string> {
    const session = await this.open();
    if (session.agent.busy) throw new HnError('HARNESS_BUSY', 'A session is forked between turns. Wait for this turn to end.');
    if (this.#options.childOf !== undefined) throw new HnError('NOT_A_ROOT', 'Only a root session can be forked here.');
    const paths = resolvePaths(this.#home === null ? this.#options.env : { ...(this.#options.env ?? process.env), HN_HOME: this.#home });
    const childId = newSessionId();
    const folder = join(paths.sessions, projectKey(this.#options.workdir));
    const key = await loadOrCreateLogKey(paths.logKey);
    const source = parseLog(await readFile(join(folder, session.sessionId)), key);
    const writer = await forkSession({ source, path: join(folder, childId), sessionId: childId, key });
    writer.append('session/link', { kind: 'fork', parent: session.sessionId });
    await writer.close();
    session.agent.record('session/link', { kind: 'forked-to', child: childId });
    return childId;
  }

  /**
   * Ends the session: children, jobs and servers stop, and a box hands its changes back, asking `approve` about each
   * manifest file (with none, those are held back). Safe to call more than once.
   */
  close(approve?: (plan: ImportPlan) => Promise<ReadonlyMap<string, string>>): Promise<FinishReport | null> {
    this.#closed ??= this.#close(approve);
    return this.#closed;
  }

  async #close(approve?: (plan: ImportPlan) => Promise<ReadonlyMap<string, string>>): Promise<FinishReport | null> {
    const session = this.#session ?? (this.#opening === null ? null : await this.#opening.catch(() => null));
    if (session === null) {
      await this.#removeHome();
      return null;
    }
    try {
      await this.#control?.close();
      await session.agent.close();
      return await session.close(approve);
    } finally {
      await session.agent.close().catch(() => undefined);
      for (const server of session.mcp) server.close();
      await session.sandbox?.stop();
      await this.#removeHome();
    }
  }

  async #removeHome(): Promise<void> {
    if (this.#home === null) return;
    const home = this.#home;
    this.#home = null;
    await rm(home, { recursive: true, force: true, maxRetries: 5 }).catch(() => undefined);
  }
}
