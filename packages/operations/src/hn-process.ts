import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { isAbsolute, join } from 'node:path';
import type { Readable, Writable } from 'node:stream';

export interface HnProcessOptions {
  /** The harness entry point, absolute. Node is this process's own, never a name a project could shadow. */
  readonly entry: string;
  readonly args: readonly string[];
  readonly cwd: string;
  /** The whole environment. Callers pass no model key here; keys go over the protocol (JSON-RPC `initialize`). */
  readonly env: NodeJS.ProcessEnv;
}

export interface HnProcess {
  readonly pid: number | undefined;
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  /** Settles once, with the exit code, when the process has gone. */
  readonly exited: Promise<number | null>;
  /** Stops it and everything it started. */
  kill(): void;
}

/**
 * Starts another `hn` for a door that talks to it over its standard streams: the JSON-RPC client and the supervisor's
 * instances. Not detached: an instance whose owner dies loses its standard input, closes its sessions and exits.
 */
export function startHnProcess(options: HnProcessOptions): HnProcess {
  if (!isAbsolute(options.entry)) throw new Error('The hn entry point must be an absolute path.');
  const child: ChildProcessWithoutNullStreams = spawn(process.execPath, ['--disable-proto=throw', '--no-warnings', options.entry, ...options.args], {
    cwd: options.cwd,
    env: options.env,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  child.stdin.on('error', () => undefined);
  const exited = new Promise<number | null>((resolve) => {
    child.once('error', () => resolve(null));
    child.once('close', (code) => resolve(code));
  });
  return {
    pid: child.pid,
    stdin: child.stdin,
    stdout: child.stdout,
    stderr: child.stderr,
    exited,
    kill: () => {
      if (child.pid === undefined || child.exitCode !== null) return;
      if (process.platform === 'win32') {
        spawnSync(join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'taskkill.exe'), ['/T', '/F', '/PID', String(child.pid)], { stdio: 'ignore', windowsHide: true });
        return;
      }
      child.kill('SIGKILL');
    },
  };
}
