import { randomBytes } from 'node:crypto';
import type { ProcessOperations, ProcessSignal, RunningProcess } from '@hn/operations';

/** Running jobs and terminals per session. A start past this is refused, never queued. */
export const MAX_JOBS = 10;

export type JobKind = 'bash' | 'terminal';
export type JobStatus = 'running' | 'exited' | 'killed';

export interface Job {
  readonly id: string;
  readonly kind: JobKind;
  readonly command: string;
  readonly startedAt: number;
  readonly process: RunningProcess;
  status: JobStatus;
  code: number | null;
  /** How much of each stream the model has already been shown. */
  readOut: number;
  readErr: number;
  /** Logged only once a job outlives the call that started it, so a quick foreground command leaves no trace. */
  registered: boolean;
}

export type JobRecord = (type: 'job/registered' | 'job/settled', data: Record<string, unknown>) => void;

export interface JobManagerOptions {
  readonly processes: ProcessOperations;
  readonly record: JobRecord;
  readonly now?: () => number;
}

/**
 * The jobs of one session. Ids are random and only mean something inside this manager, so a job is reached by
 * the session that owns it, never by knowing its id. Every job dies with the session or the box.
 */
export class JobManager {
  readonly #options: JobManagerOptions;
  readonly #jobs = new Map<string, Job>();

  constructor(options: JobManagerOptions) {
    this.#options = options;
  }

  get running(): number {
    return [...this.#jobs.values()].filter((job) => job.status === 'running').length;
  }

  /** Starts a process, or says why not. */
  start(kind: JobKind, command: string, cwd: string): Job | string {
    if (this.running >= MAX_JOBS) return `${MAX_JOBS} jobs are already running. Stop one with job_kill or terminal_close first.`;
    const process = this.#options.processes.start(command, { cwd, input: kind === 'terminal' });
    const id = `${kind === 'terminal' ? 'term' : 'job'}-${randomBytes(4).toString('hex')}`;
    const job: Job = {
      id,
      kind,
      command,
      startedAt: (this.#options.now ?? Date.now)(),
      process,
      status: 'running',
      code: null,
      readOut: 0,
      readErr: 0,
      registered: false,
    };
    this.#jobs.set(id, job);
    void process.exited.then(({ code }) => {
      if (job.status === 'running') job.status = 'exited';
      job.code = code;
      if (job.registered) this.#options.record('job/settled', { jobId: id, status: job.status, code });
    });
    if (kind === 'terminal') this.register(job);
    return job;
  }

  /** The job now outlives its call: log it, so a crash closes it as `lost`. */
  register(job: Job): void {
    if (job.registered) return;
    job.registered = true;
    this.#options.record('job/registered', { jobId: job.id, kind: job.kind, command: job.command.slice(0, 500) });
  }

  get(id: string): Job | null {
    return this.#jobs.get(id) ?? null;
  }

  list(): Job[] {
    return [...this.#jobs.values()];
  }

  /** A foreground command that finished in time leaves the table. */
  forget(id: string): void {
    this.#jobs.delete(id);
  }

  signal(job: Job, kind: ProcessSignal): void {
    if (job.status !== 'running') return;
    if (kind === 'kill' || kind === 'terminate') job.status = 'killed';
    job.process.signal(kind);
  }

  /** New output since the model last looked, and marks it read. */
  take(job: Job): { stdout: Buffer; stderr: Buffer } {
    const stdout = job.process.stdout.since(job.readOut);
    const stderr = job.process.stderr.since(job.readErr);
    job.readOut += stdout.length;
    job.readErr += stderr.length;
    return { stdout, stderr };
  }

  /** Stops everything, for the end of a session or a box. */
  async stopAll(): Promise<void> {
    const running = this.list().filter((job) => job.status === 'running');
    for (const job of running) this.signal(job, 'kill');
    await Promise.all(running.map((job) => job.process.exited));
  }
}

/** Waits for a job to end, the deadline to pass, or the user to stop it, whichever is first. */
export async function waitFor(job: Job, timeoutMs: number, signal: AbortSignal): Promise<'done' | 'timeout' | 'cancelled'> {
  let timer: NodeJS.Timeout | undefined;
  let onAbort: (() => void) | undefined;
  const outcome = await Promise.race([
    job.process.exited.then(() => 'done' as const),
    new Promise<'timeout'>((resolve) => {
      timer = setTimeout(() => resolve('timeout'), timeoutMs);
    }),
    new Promise<'cancelled'>((resolve) => {
      onAbort = () => resolve('cancelled');
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }),
  ]);
  clearTimeout(timer);
  if (onAbort !== undefined) signal.removeEventListener('abort', onAbort);
  return outcome;
}
