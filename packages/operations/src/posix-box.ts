import { spawn, type ChildProcess } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { capture } from './native-box.ts';
import { wrapChild, type ProcessSignal, type RunningProcess, type StartOptions } from './processes.ts';
import type { ExecOptions, ExecResult } from './types.ts';

/**
 * What the Linux and macOS boxes share: a folder per session (`box/work`, `box/home`, `box/tmp`, with the session
 * folder itself closed to the box), one process per command, a time limit, and an end that leaves nothing behind.
 * A subclass says how a program is wrapped into the OS's sandbox (`wrap`) and what the box's environment is.
 */

export interface PosixRunRequest {
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
  readonly input?: string;
}

const GRACE_MS = 3_000;

/** What the box layers were, as the box was built. The outside-in check confirms them; this only says what was asked for. */
export interface BoxLayers {
  /** Layers applied, in plain words: `namespaces`, `landlock`, `seccomp`, `seatbelt`. */
  readonly applied: readonly string[];
  /** Layers this machine could not apply and why. A box missing one is reported as such, not as a failed run. */
  readonly missing: readonly { readonly layer: string; readonly reason: string }[];
}

export abstract class PosixBox {
  abstract readonly kind: 'linux' | 'macos';
  readonly root: string;
  readonly work: string;
  readonly home: string;
  readonly tmp: string;

  protected constructor(boxDir: string) {
    this.root = join(boxDir, 'box');
    this.work = join(this.root, 'work');
    this.home = join(this.root, 'home');
    this.tmp = join(this.root, 'tmp');
  }

  /** The three folders the box owns. The copy of the project is made into `work` by the caller. */
  protected async makeFolders(): Promise<void> {
    for (const dir of [this.work, this.home, this.tmp]) await mkdir(dir, { recursive: true, mode: 0o700 });
  }

  abstract get layers(): BoxLayers;
  /** The shell the `bash` tool runs: bash when the box has it, otherwise a POSIX sh. */
  abstract get shellPath(): string;
  /** The program and arguments that run `program args` in the OS's sandbox. */
  abstract wrap(program: string, args: readonly string[], cwd: string): { readonly file: string; readonly args: string[] };
  /** The environment of the process that starts the sandbox. For a box that cannot clear it itself, this is the box's whole environment. */
  protected abstract spawnEnv(): NodeJS.ProcessEnv;
  /** What each kind of stop does to the process group. */
  protected abstract signalFor(kind: ProcessSignal): NodeJS.Signals;

  get shell(): 'bash' | 'posix' {
    return this.shellPath.endsWith('/bash') ? 'bash' : 'posix';
  }

  #launch(program: string, args: readonly string[], cwd: string, stdio: ('pipe' | 'ignore')[]): ChildProcess {
    const { file, args: argv } = this.wrap(program, args, cwd);
    // Its own process group, so one signal reaches the sandbox and everything it started.
    return spawn(file, argv, { stdio, env: this.spawnEnv(), detached: true });
  }

  /** Runs one program in the box to completion, ending everything it started. */
  run(program: string, args: readonly string[], request: PosixRunRequest): Promise<ExecResult> {
    return new Promise((resolve, reject) => {
      const child = this.#launch(program, args, request.cwd, ['pipe', 'pipe', 'pipe']);
      const stdout = capture();
      const stderr = capture();
      let timedOut = false;
      let cancelled = false;
      let drain: NodeJS.Timeout | undefined;
      const stop = (): void => {
        killGroup(child, 'SIGKILL');
        drain = setTimeout(() => {
          child.stdout?.destroy();
          child.stderr?.destroy();
        }, GRACE_MS);
      };
      const onAbort = (): void => {
        cancelled = true;
        stop();
      };
      const timer = setTimeout(() => {
        timedOut = true;
        stop();
      }, request.timeoutMs);
      if (request.signal.aborted) onAbort();
      else request.signal.addEventListener('abort', onAbort, { once: true });
      child.stdout?.on('data', (chunk: Buffer) => stdout.add(chunk));
      child.stderr?.on('data', (chunk: Buffer) => stderr.add(chunk));
      child.stdin?.on('error', () => undefined);
      child.stdin?.end(request.input ?? '');
      child.once('error', reject);
      // The command has ended; whatever it left running in the group goes with it.
      child.once('exit', () => killGroup(child, 'SIGKILL'));
      child.once('close', (code) => {
        clearTimeout(timer);
        if (drain !== undefined) clearTimeout(drain);
        request.signal.removeEventListener('abort', onAbort);
        killGroup(child, 'SIGKILL');
        resolve({ code, stdout: stdout.bytes(), stderr: stderr.bytes(), timedOut, cancelled, clipped: stdout.clipped() || stderr.clipped() });
      });
    });
  }

  /** A shell command, as the `bash` tool runs it. */
  exec(command: string, options: ExecOptions): Promise<ExecResult> {
    return this.run(this.shellPath, ['-c', command], { cwd: options.cwd, timeoutMs: options.timeoutMs, signal: options.signal, ...(options.input === undefined ? {} : { input: options.input }) });
  }

  /** A job or terminal. */
  startProcess(command: string, options: StartOptions): RunningProcess {
    const child = this.#launch(this.shellPath, ['-c', command], options.cwd, [options.input ? 'pipe' : 'ignore', 'pipe', 'pipe']);
    child.once('exit', () => killGroup(child, 'SIGKILL'));
    return wrapChild(child, (kind) => killGroup(child, this.signalFor(kind)));
  }
}

function killGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.pid === undefined) return;
  try {
    process.kill(-child.pid, signal);
  } catch {
    // The group is already gone.
  }
}
