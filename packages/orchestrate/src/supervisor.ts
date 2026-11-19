import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

/** Section 12: at most 100 instances, a heartbeat every 30 s. */
export const MAX_INSTANCES = 100;
export const HEARTBEAT_MS = 30_000;
export const HEARTBEAT_TIMEOUT_MS = 10_000;

/** One running instance: an `hn rpc` process with one session, reached by requests. */
export interface InstanceHandle {
  readonly pid: number | undefined;
  request(method: string, params: Readonly<Record<string, unknown>>, timeoutMs?: number): Promise<unknown>;
  /** Settles when the process has gone. */
  readonly exited: Promise<number | null>;
  kill(): void;
  /** Asks it to close its sessions and exit. */
  shutdown(): Promise<void>;
}

export type InstanceStarter = (workdir: string) => InstanceHandle;

export interface SessionSettings {
  readonly workdir: string;
  readonly mode?: string;
  readonly model?: string;
  readonly baseUrl?: string;
  readonly window?: number;
  readonly allow?: readonly string[];
  readonly verify?: string;
}

export interface InstanceRecord {
  readonly id: string;
  readonly pid: number | null;
  readonly settings: SessionSettings;
  readonly sessionId: string | null;
  readonly startedAt: string;
  readonly lastHeartbeat: string | null;
  readonly status: 'starting' | 'running' | 'lost' | 'stopped';
  /** For a fork or clone: the instance it came from. */
  readonly from?: string;
}

export interface SupervisorOptions {
  readonly start: InstanceStarter;
  /** `instances.json`: rewritten after every change, so a restarted supervisor knows what was running. */
  readonly file: string;
  readonly maxInstances?: number;
  readonly heartbeatMs?: number;
  readonly heartbeatTimeoutMs?: number;
  readonly now?: () => Date;
}

/**
 * The supervisor (slide 54, experimental, decision 7): many instances, each an `hn rpc` process holding one session,
 * driven through the RPC door. Ops `new_session`, `prompt`, `fork`, `clone`, `get_state`, `stop`. What it forwards is
 * `ipc`, never `user`: the supervisor is another process, not a person at a door. Local only.
 */
export class Supervisor {
  readonly #options: SupervisorOptions;
  readonly #records = new Map<string, InstanceRecord>();
  readonly #handles = new Map<string, InstanceHandle>();
  #next = 1;
  #timer: NodeJS.Timeout | null = null;
  #writes: Promise<void> = Promise.resolve();

  constructor(options: SupervisorOptions) {
    this.#options = options;
  }

  get maxInstances(): number {
    return this.#options.maxInstances ?? MAX_INSTANCES;
  }

  #now(): string {
    return (this.#options.now?.() ?? new Date()).toISOString();
  }

  #set(record: InstanceRecord): void {
    this.#records.set(record.id, record);
    void this.#save();
  }

  #save(): Promise<void> {
    const body = JSON.stringify({ v: 1, instances: [...this.#records.values()] }, null, 1);
    const file = this.#options.file;
    this.#writes = this.#writes.then(async () => {
      await mkdir(dirname(file), { recursive: true, mode: 0o700 });
      await writeFile(`${file}.tmp`, body, { mode: 0o600 });
      await rename(`${file}.tmp`, file);
    }).catch(() => undefined);
    return this.#writes;
  }

  /** Waits until `instances.json` holds every change so far. */
  flush(): Promise<void> {
    return this.#writes;
  }

  #live(): number {
    return [...this.#records.values()].filter((record) => record.status === 'running' || record.status === 'starting').length;
  }

  #handle(id: string): InstanceHandle {
    const handle = this.#handles.get(id);
    const record = this.#records.get(id);
    if (handle === undefined || record === undefined || record.status !== 'running') throw new Error(`There is no running instance ${id}.`);
    return handle;
  }

  async #launch(settings: SessionSettings, sessionId: string | undefined, from: string | undefined): Promise<InstanceRecord> {
    if (this.#live() >= this.maxInstances) throw new Error(`${this.maxInstances} instances are already running. Stop one first.`);
    const id = `i${this.#next}`;
    this.#next += 1;
    const handle = this.#options.start(settings.workdir);
    const base = { id, pid: handle.pid ?? null, settings, startedAt: this.#now(), lastHeartbeat: null, ...(from === undefined ? {} : { from }) };
    this.#set({ ...base, sessionId: null, status: 'starting' });
    this.#handles.set(id, handle);
    void handle.exited.then(() => {
      const record = this.#records.get(id);
      if (record !== undefined && (record.status === 'running' || record.status === 'starting')) this.#set({ ...record, status: 'lost' });
    });
    try {
      await handle.request('initialize', {});
      const opened = (await handle.request('session/open', { ...settings, ...(sessionId === undefined ? {} : { sessionId }) })) as { sessionId: string };
      const record: InstanceRecord = { ...base, sessionId: opened.sessionId, status: 'running', lastHeartbeat: this.#now() };
      this.#set(record);
      return record;
    } catch (error) {
      handle.kill();
      this.#set({ ...base, sessionId: null, status: 'lost' });
      throw error;
    }
  }

  newSession(settings: SessionSettings): Promise<InstanceRecord> {
    return this.#launch(settings, undefined, undefined);
  }

  /** A turn in an instance's session. The text is `ipc`: the supervisor is another process, not a person. */
  async prompt(id: string, text: string): Promise<unknown> {
    const record = this.#records.get(id);
    return this.#handle(id).request('session/prompt', { sessionId: record?.sessionId, text, origin: 'ipc' });
  }

  /** A new instance holding a copy of this one's finished turns; the two then go their own ways. */
  async fork(id: string): Promise<InstanceRecord> {
    const record = this.#records.get(id);
    const forked = (await this.#handle(id).request('session/fork', { sessionId: record?.sessionId })) as { sessionId: string };
    return this.#launch((record as InstanceRecord).settings, forked.sessionId, id);
  }

  /** A new instance with the same settings and a fresh, empty session. */
  async clone(id: string): Promise<InstanceRecord> {
    this.#handle(id);
    return this.#launch((this.#records.get(id) as InstanceRecord).settings, undefined, id);
  }

  /** Every instance as recorded, with each running one's live state. */
  async getState(id?: string): Promise<{ readonly instances: readonly (InstanceRecord & { readonly state?: unknown })[] }> {
    const records = [...this.#records.values()].filter((record) => id === undefined || record.id === id);
    const instances = await Promise.all(
      records.map(async (record) => {
        if (record.status !== 'running') return record;
        const state = await this.#handles.get(record.id)?.request('session/state', { sessionId: record.sessionId }, this.#options.heartbeatTimeoutMs ?? HEARTBEAT_TIMEOUT_MS).catch(() => null);
        return state === null ? record : { ...record, state };
      }),
    );
    return { instances };
  }

  async stop(id: string): Promise<void> {
    const handle = this.#handle(id);
    await handle.shutdown();
    handle.kill();
    this.#set({ ...(this.#records.get(id) as InstanceRecord), status: 'stopped' });
  }

  /** One heartbeat: each running instance must answer `session/state` in time, or it is marked lost. */
  async heartbeat(): Promise<void> {
    await Promise.all(
      [...this.#records.values()].filter((record) => record.status === 'running').map(async (record) => {
        const handle = this.#handles.get(record.id);
        const answer = await handle?.request('session/state', { sessionId: record.sessionId }, this.#options.heartbeatTimeoutMs ?? HEARTBEAT_TIMEOUT_MS).catch(() => null);
        const current = this.#records.get(record.id) as InstanceRecord;
        if (current.status !== 'running') return;
        if (answer === null || answer === undefined) {
          handle?.kill();
          this.#set({ ...current, status: 'lost' });
        } else this.#set({ ...current, lastHeartbeat: this.#now() });
      }),
    );
  }

  startHeartbeat(): void {
    this.#timer ??= setInterval(() => void this.heartbeat(), this.#options.heartbeatMs ?? HEARTBEAT_MS);
    this.#timer.unref?.();
  }

  async close(): Promise<void> {
    if (this.#timer !== null) clearInterval(this.#timer);
    this.#timer = null;
    await Promise.all(
      [...this.#records.values()].filter((record) => record.status === 'running').map(async (record) => {
        const handle = this.#handles.get(record.id);
        await handle?.shutdown().catch(() => undefined);
        handle?.kill();
        this.#set({ ...record, status: 'stopped' });
      }),
    );
    await this.flush();
  }
}
