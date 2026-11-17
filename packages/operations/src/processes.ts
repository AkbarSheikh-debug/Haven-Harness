import type { ChildProcess } from 'node:child_process';

/** A job keeps at most this much of each stream. Past it, output is counted but not kept. */
export const MAX_JOB_STREAM_BYTES = 8 * 1024 * 1024;

export type ProcessSignal = 'interrupt' | 'terminate' | 'kill';

/** Output that can be read again from any point, so a job's new output is never shown twice. */
export class OutputBuffer {
  readonly #chunks: Buffer[] = [];
  readonly #listeners: ((chunk: Buffer) => void)[] = [];
  #kept = 0;
  #seen = 0;

  /** Every chunk as it arrives, past the keep limit too, for a reader that consumes a stream (a language server). */
  onData(listener: (chunk: Buffer) => void): void {
    this.#listeners.push(listener);
  }

  add(chunk: Buffer): void {
    this.#seen += chunk.length;
    for (const listener of this.#listeners) listener(chunk);
    const room = MAX_JOB_STREAM_BYTES - this.#kept;
    if (room <= 0) return;
    const kept = chunk.length > room ? chunk.subarray(0, room) : chunk;
    this.#chunks.push(kept);
    this.#kept += kept.length;
  }

  /** Every byte the process wrote, kept or not. */
  get total(): number {
    return this.#seen;
  }

  get clipped(): boolean {
    return this.#seen > this.#kept;
  }

  get bytes(): Buffer {
    return Buffer.concat(this.#chunks);
  }

  /** What was kept from `offset` on. */
  since(offset: number): Buffer {
    return this.bytes.subarray(Math.min(offset, this.#kept));
  }
}

export interface RunningProcess {
  readonly stdout: OutputBuffer;
  readonly stderr: OutputBuffer;
  /** Settles once, when the process has exited and its pipes are closed. */
  readonly exited: Promise<{ readonly code: number | null }>;
  /** Writes to standard input. False when the process has no input pipe or it is closed. */
  write(text: string): boolean;
  closeInput(): void;
  signal(kind: ProcessSignal): void;
}

export interface StartOptions {
  readonly cwd: string;
  /** Give the process an input pipe, for a terminal. */
  readonly input: boolean;
}

/** Long-running processes: jobs and terminals. Optional, because not every backend can keep one alive. */
export interface ProcessOperations {
  start(command: string, options: StartOptions): RunningProcess;
}

/**
 * Names a job's environment never carries, so a job finds no route back to the harness: no control socket,
 * token or session pipe the harness may set, and no model key (`box_job_cannot_use_tool_socket`).
 * `HN_PARENT_SESSION` and `HN_EXEC` stay: the first makes a nested `hn` refuse to widen anything, the second
 * is how a box finds a command's processes to stop them.
 */
const SCRUBBED = /^(HN_(?!PARENT_SESSION$|EXEC$)|ANTHROPIC_|OPENAI_|CLAUDE_|DEEPSEEK_|OPENROUTER_)/i;

export function scrubJobEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(env)) if (!SCRUBBED.test(name)) out[name] = value;
  return out;
}

/** Wraps a spawned child with the buffers, the exit promise and a signal function the backend supplies. */
export function wrapChild(child: ChildProcess, signal: (kind: ProcessSignal) => void): RunningProcess {
  const stdout = new OutputBuffer();
  const stderr = new OutputBuffer();
  child.stdout?.on('data', (chunk: Buffer) => stdout.add(chunk));
  child.stderr?.on('data', (chunk: Buffer) => stderr.add(chunk));
  child.stdin?.on('error', () => undefined);
  const exited = new Promise<{ code: number | null }>((resolve) => {
    child.once('error', () => resolve({ code: null }));
    child.once('close', (code) => resolve({ code }));
  });
  let open = child.stdin !== null;
  return {
    stdout,
    stderr,
    exited,
    write(text) {
      if (!open || child.stdin === null) return false;
      return child.stdin.write(text);
    },
    closeInput() {
      open = false;
      child.stdin?.end();
    },
    signal,
  };
}
