import { spawn } from 'node:child_process';

export interface Ran {
  readonly status: number | null;
  readonly stdout: Buffer;
  readonly stderr: string;
}

/** Runs a program with an argument list (never a shell), with a time limit and an output limit. */
export function run(command: string, args: readonly string[], options: { cwd?: string; env?: NodeJS.ProcessEnv; input?: Buffer; timeoutMs?: number; maxBytes?: number } = {}): Promise<Ran> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args], { cwd: options.cwd, env: options.env ?? process.env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false });
    const out: Buffer[] = [];
    let size = 0;
    let err = '';
    const max = options.maxBytes ?? 64 * 1024 * 1024;
    const timer = setTimeout(() => child.kill(), options.timeoutMs ?? 10 * 60_000);
    child.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > max) child.kill();
      else out.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (err.length < 20_000) err += chunk.toString();
    });
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (status) => {
      clearTimeout(timer);
      resolve({ status, stdout: Buffer.concat(out), stderr: err });
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(options.input);
  });
}

/** git, with nothing from the repository's own configuration that could run a program: no hooks, no filters, no textconv. */
export function git(args: readonly string[], options: { cwd?: string; input?: Buffer; env?: NodeJS.ProcessEnv } = {}): Promise<Ran> {
  return run('git', ['-c', 'core.hooksPath=', '-c', 'core.fsmonitor=false', '-c', 'protocol.ext.allow=never', '--no-pager', ...args], { ...options, env: { ...(options.env ?? process.env), GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1' } });
}
