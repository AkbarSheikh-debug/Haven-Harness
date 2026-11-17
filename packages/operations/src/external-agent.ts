import { spawn, spawnSync } from 'node:child_process';
import { join } from 'node:path';

const MAX_OUTPUT_CHARS = 20_000;

/** An external agent's command, as the user configured it: an absolute path, and arguments with `{task}`. */
export interface ExternalCommand {
  readonly command: string;
  readonly args: readonly string[];
  readonly timeoutMs: number;
}

export interface ExternalRun {
  readonly code: number | null;
  readonly output: string;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
}

function killTree(pid: number): void {
  if (process.platform === 'win32') {
    spawnSync(join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'taskkill.exe'), ['/T', '/F', '/PID', String(pid)], { stdio: 'ignore', windowsHide: true });
    return;
  }
  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    // Already gone.
  }
}

/** Runs the agent with no shell, in the project folder, with an environment that holds no model key. */
export function runExternal(agent: ExternalCommand, task: string, cwd: string, signal: AbortSignal): Promise<ExternalRun> {
  return new Promise((resolve) => {
    const args = agent.args.map((arg) => (arg === '{task}' ? task : arg));
    const env: NodeJS.ProcessEnv = { PATH: process.env['PATH'] ?? '', ...(process.platform === 'win32' ? { SystemRoot: process.env['SystemRoot'] ?? '' } : { HOME: process.env['HOME'] ?? '' }) };
    const child = spawn(agent.command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32', windowsHide: true, shell: false });
    let output = '';
    let timedOut = false;
    let cancelled = false;
    const take = (chunk: Buffer): void => {
      output = (output + chunk.toString('utf8')).slice(-MAX_OUTPUT_CHARS * 2);
    };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    const stop = (): void => {
      if (child.pid !== undefined) killTree(child.pid);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, agent.timeoutMs);
    const onAbort = (): void => {
      cancelled = true;
      stop();
    };
    signal.addEventListener('abort', onAbort, { once: true });
    const finish = (code: number | null): void => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      resolve({ code, output: output.slice(-MAX_OUTPUT_CHARS), timedOut, cancelled });
    };
    child.once('error', (error) => {
      output += error.message;
      finish(null);
    });
    child.once('close', finish);
  });
}

