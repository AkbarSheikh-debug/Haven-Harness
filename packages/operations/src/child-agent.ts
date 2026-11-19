import { spawn, spawnSync, type ChildProcess, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { join } from 'node:path';

const MAX_OUTPUT = 4 * 1024 * 1024;

export interface ChildAgentOptions {
  /** An absolute path to node, never a bare name a project could shadow. */
  readonly node: string;
  /** The harness entry point, absolute. */
  readonly entry: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  /** Written to the child's standard input and closed: the key hand-off, never the environment. */
  readonly stdin: string;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
  /**
   * Opens Node's IPC pipe to the child and hands each message here with a way to reply: the private channel for
   * approvals and rate limits (Phase 5 decision 2). Every message is hostile until the handler says otherwise.
   */
  readonly onMessage?: (message: unknown, reply: (message: unknown) => void) => void;
  /** Told the child's process id once it starts, so a durable child can be found again. */
  readonly onSpawn?: (pid: number) => void;
  /** Given a way to push messages to the child over the pipe (a team member's inbox), and told null when it ends. */
  readonly onPort?: (send: ((message: unknown) => void) | null) => void;
}

export interface ChildAgentResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
}

/** Stops the child and everything it started: a process group on POSIX, the whole tree on Windows. */
function killChild(child: ChildProcess): void {
  if (child.pid === undefined) return;
  if (process.platform === 'win32') {
    const taskkill = join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'taskkill.exe');
    spawnSync(taskkill, ['/T', '/F', '/PID', String(child.pid)], { stdio: 'ignore', windowsHide: true });
    return;
  }
  try {
    process.kill(-child.pid, 'SIGKILL');
  } catch {
    // Already gone.
  }
}

/**
 * Runs a child harness as its own process (slide 47): its own window and its own log, and only its report
 * crosses back. No shell is involved, so a brief is an argument, never shell text.
 */
export function runChildAgent(options: ChildAgentOptions): Promise<ChildAgentResult> {
  return new Promise((resolve) => {
    const child: ChildProcessWithoutNullStreams = spawn(options.node, ['--disable-proto=throw', options.entry, ...options.args], {
      cwd: options.cwd,
      env: options.env,
      stdio: options.onMessage === undefined ? ['pipe', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe', 'ipc'],
      serialization: 'json',
      // Detached everywhere, so a child outlives a parent that crashes (slide 57); on Windows a non-detached child sits
      // in a job object that dies with the parent. Stopping a child still kills its whole tree.
      detached: true,
      windowsHide: true,
    }) as ChildProcessWithoutNullStreams;
    if (child.pid !== undefined) options.onSpawn?.(child.pid);
    const onMessage = options.onMessage;
    if (onMessage !== undefined) {
      options.onPort?.((message) => {
        if (child.connected) child.send(message as never, (error) => void error);
      });
      child.once('close', () => options.onPort?.(null));
      child.on('message', (message) => {
        onMessage(message, (reply) => {
          if (child.connected) child.send(reply as never, (error) => void error);
        });
      });
    }
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let cancelled = false;
    child.stdout.on('data', (chunk: Buffer) => {
      if (stdout.length < MAX_OUTPUT) stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < MAX_OUTPUT) stderr += chunk.toString('utf8');
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(options.stdin);
    const timer = setTimeout(() => {
      timedOut = true;
      killChild(child);
    }, options.timeoutMs);
    const onAbort = (): void => {
      cancelled = true;
      killChild(child);
    };
    if (options.signal.aborted) onAbort();
    else options.signal.addEventListener('abort', onAbort, { once: true });
    const finish = (code: number | null): void => {
      clearTimeout(timer);
      options.signal.removeEventListener('abort', onAbort);
      resolve({ code, stdout, stderr, timedOut, cancelled });
    };
    child.once('error', (error) => {
      stderr += error.message;
      finish(null);
    });
    child.once('close', (code) => finish(code));
  });
}
