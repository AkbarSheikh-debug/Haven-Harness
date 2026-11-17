import { randomUUID } from 'node:crypto';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { basename, delimiter, dirname, isAbsolute, join } from 'node:path';
import { rgPath } from '@vscode/ripgrep';
import { scrubJobEnv, wrapChild, type ProcessSignal, type RunningProcess, type StartOptions } from './processes.ts';
import type { SafeFiles } from './safe-files.ts';
import type { ExecOptions, ExecResult, Operations, SearchRequest } from './types.ts';

/** Where the bundled ripgrep binary is, for `hn doctor`. */
export const ripgrepPath: string = rgPath;

export const GRACE_MS = 3_000;
const DRAIN_MS = 1_000;
export const MAX_CAPTURE_BYTES = 64 * 1024 * 1024;

/** An absolute path only. A bare name on Windows could run a `bash.exe` committed to the repo. */
export function findBash(env: NodeJS.ProcessEnv = process.env): string {
  const candidates =
    process.platform === 'win32'
      ? [
          // usr\bin holds the real shell. bin\bash.exe is a wrapper that hides the process tree.
          join(env['ProgramFiles'] ?? 'C:\\Program Files', 'Git', 'usr', 'bin', 'bash.exe'),
          join(env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)', 'Git', 'usr', 'bin', 'bash.exe'),
          join(env['LOCALAPPDATA'] ?? '', 'Programs', 'Git', 'usr', 'bin', 'bash.exe'),
        ]
      : ['/bin/bash', '/usr/bin/bash', '/usr/local/bin/bash'];
  const found = candidates.find((candidate) => isAbsolute(candidate) && existsSync(candidate));
  if (found === undefined) throw new Error('bash was not found. On Windows, install Git for Windows.');
  return found;
}

/** Git's tools live beside its bash. Windows spells the variable `Path`, so the real key is kept. */
function shellEnv(bash: string, extra: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  const name = Object.keys(process.env).find((key) => key.toUpperCase() === 'PATH') ?? 'PATH';
  return { ...process.env, ...extra, [name]: `${dirname(bash)}${delimiter}${process.env[name] ?? ''}` };
}

/** What a local command carries so every process it ever starts can be found again: the shell and a marker. */
interface Tracked {
  readonly bash: string;
  readonly marker: string;
}

/**
 * Git Bash detaches a child started with `&` (or a double fork, or an `exec`) from the Windows process tree,
 * so `taskkill /T` misses it and it lives on, holding the pipes. Every process the command starts inherits the
 * `HN_EXEC` marker, and MSYS shows each process's environment and Windows PID under `/proc`, so each one is
 * found by its marker and stopped by PID. The sweep's own shell carries the marker under another name.
 */
function killMarked(tracked: Tracked, taskkill: string): void {
  const script = [
    'for p in /proc/[0-9]*; do',
    '  if tr "\\0" "\\n" < "$p/environ" 2>/dev/null | grep -qx "HN_EXEC=$SWEEP"; then',
    '    w=$(cat "$p/winpid" 2>/dev/null)',
    '    [ -n "$w" ] && "$TASKKILL" //F //T //PID "$w" > /dev/null 2>&1',
    '  fi',
    'done',
  ].join('\n');
  const env = { ...shellEnv(tracked.bash), TASKKILL: taskkill, SWEEP: tracked.marker };
  spawnSync(tracked.bash, ['-c', script], { stdio: 'ignore', env, timeout: 10_000, windowsHide: true });
}

function killTree(child: ChildProcess, force: boolean, tracked?: Tracked): void {
  if (child.pid === undefined) return;
  if (process.platform === 'win32') {
    const taskkill = join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'taskkill.exe');
    spawnSync(taskkill, ['/T', ...(force ? ['/F'] : []), '/PID', String(child.pid)], { stdio: 'ignore' });
    if (force && tracked !== undefined) killMarked(tracked, taskkill);
    return;
  }
  try {
    process.kill(-child.pid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {
    // The group has already gone.
  }
}

class Capture {
  readonly #chunks: Buffer[] = [];
  #bytes = 0;
  clipped = false;

  add(chunk: Buffer): void {
    const room = MAX_CAPTURE_BYTES - this.#bytes;
    if (room <= 0) {
      this.clipped = true;
      return;
    }
    const kept = chunk.length > room ? chunk.subarray(0, room) : chunk;
    this.clipped ||= kept.length < chunk.length;
    this.#chunks.push(kept);
    this.#bytes += kept.length;
  }

  get bytes(): Buffer {
    return Buffer.concat(this.#chunks);
  }
}

/**
 * A long-running process in its own group, so a signal reaches everything it started. Windows has no
 * console signal for a process on pipes, so every signal there is a forced stop of the whole tree.
 */
function startLocal(bash: string, command: string, options: StartOptions, extra: Readonly<Record<string, string>>): RunningProcess {
  const tracked = { bash, marker: randomUUID() };
  const child = spawn(bash, ['-c', command], {
    cwd: options.cwd,
    env: { ...scrubJobEnv(shellEnv(bash, extra)), HN_EXEC: tracked.marker },
    stdio: [options.input ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
    windowsHide: true,
  });
  const signal = (kind: ProcessSignal): void => {
    if (process.platform === 'win32' || kind === 'kill' || child.pid === undefined) {
      killTree(child, true, tracked);
      return;
    }
    try {
      process.kill(-child.pid, kind === 'interrupt' ? 'SIGINT' : 'SIGTERM');
    } catch {
      // The group has already gone.
    }
  };
  return wrapChild(child, signal);
}

function execLocal(bash: string, command: string, options: ExecOptions, extra: Readonly<Record<string, string>>): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const tracked = { bash, marker: randomUUID() };
    const child = spawn(bash, ['-c', command], {
      cwd: options.cwd,
      env: { ...shellEnv(bash, extra), HN_EXEC: tracked.marker },
      stdio: ['pipe', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
      windowsHide: true,
    });
    const stdout = new Capture();
    const stderr = new Capture();
    let timedOut = false;
    let cancelled = false;
    let forceTimer: NodeJS.Timeout | undefined;
    let drainTimer: NodeJS.Timeout | undefined;

    const stop = (): void => {
      killTree(child, process.platform === 'win32', tracked);
      forceTimer = setTimeout(() => killTree(child, true, tracked), GRACE_MS);
      // A survivor could hold the pipes open forever, so the wait for them is bounded.
      drainTimer = setTimeout(() => {
        child.stdout.destroy();
        child.stderr.destroy();
      }, GRACE_MS + DRAIN_MS);
    };
    const onAbort = (): void => {
      cancelled = true;
      stop();
    };
    const timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, options.timeoutMs);

    if (options.signal.aborted) onAbort();
    else options.signal.addEventListener('abort', onAbort, { once: true });

    child.stdout.on('data', (chunk: Buffer) => stdout.add(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.add(chunk));
    // Without input the pipe closes at once, so the command reads end-of-input, as it would from nothing.
    // A command that exits without reading its input must not crash the harness.
    child.stdin.on('error', () => undefined);
    child.stdin.end(options.input ?? '');
    child.once('error', reject);
    child.once('close', (code) => {
      clearTimeout(timer);
      if (forceTimer !== undefined) clearTimeout(forceTimer);
      if (drainTimer !== undefined) clearTimeout(drainTimer);
      options.signal.removeEventListener('abort', onAbort);
      resolve({
        code,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        timedOut,
        cancelled,
        clipped: stdout.clipped || stderr.clipped,
      });
    });
  });
}

/**
 * Runs ripgrep over `root`, whose args end with the search target `.`. A missing working folder makes the spawn
 * itself fail with ENOENT, which reads as if ripgrep were missing, and so does a file used as the working folder
 * (both seen live). A file root searches just that file, from its own folder.
 */
function runRg(args: readonly string[], root: string, limit: number): Promise<string[]> {
  let info: ReturnType<typeof statSync> | undefined;
  try {
    info = statSync(root);
  } catch {
    return Promise.reject(new Error('There is no such file or folder in the project.'));
  }
  const file = info?.isFile() === true;
  return spawnRg(file ? [...args.slice(0, -1), basename(root)] : args, file ? dirname(root) : root, limit);
}

function spawnRg(args: readonly string[], cwd: string, limit: number): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const child = spawn(rgPath, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const lines: string[] = [];
    let partial = '';
    let stderr = '';
    let stopped = false;

    child.stdout.setEncoding('utf8').on('data', (chunk: string) => {
      const pieces = (partial + chunk).split(/\r?\n/);
      partial = pieces.pop() ?? '';
      lines.push(...pieces);
      if (lines.length > limit && !stopped) {
        stopped = true;
        child.kill();
      }
    });
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.once('error', reject);
    child.once('close', (code) => {
      // rg exits 1 for "no matches", which is an answer rather than a failure.
      if (!stopped && code !== null && code > 1) reject(new Error(stderr.trim() || `rg exited with ${code}`));
      else resolve(lines);
    });
  });
}

function excludeArgs(request: Pick<SearchRequest, 'excludeGlobs' | 'glob'>): string[] {
  return [
    '--hidden',
    '--glob',
    '!.git',
    ...(request.glob === undefined ? [] : ['--glob', request.glob]),
    ...request.excludeGlobs.flatMap((glob) => ['--iglob', `!${glob}`]),
  ];
}

export interface LocalOptions {
  /** When set, project files are read and written only through the native helper, which never follows a link. */
  readonly safe?: { readonly files: SafeFiles; readonly root: string };
  /**
   * Added to the environment of every command this backend starts, such as the session's own `HN_PARENT_SESSION`.
   * Per backend rather than in `process.env`, so two sessions in one process never see each other's values.
   */
  readonly env?: Readonly<Record<string, string>>;
}

/** The most one file read will return in safe mode. Bigger files are refused, not truncated. */
export const MAX_SAFE_READ_BYTES = 32 * 1024 * 1024;

export function localOperations(spillDir: string, options: LocalOptions = {}): Operations {
  const bash = findBash();
  const { safe } = options;
  const extra = options.env ?? {};
  return {
    read: { readFile: safe === undefined ? readFile : (path) => safe.files.read(safe.root, path, MAX_SAFE_READ_BYTES), realpath },
    write: {
      writeFile:
        safe === undefined
          ? (path, content) => writeFile(path, content)
          : // Parent folders are made by the helper too, one at a time, so a link cannot be slipped in between.
            (path, content) => safe.files.write(safe.root, path, content, { mkdir: true }),
      mkdir:
        safe === undefined
          ? async (path) => {
              await mkdir(path, { recursive: true });
            }
          : async () => undefined,
    },
    bash: { exec: (command, options) => execLocal(bash, command, options, extra) },
    processes: { start: (command, options) => startLocal(bash, command, options, extra) },
    search: {
      grep: (request) =>
        runRg(
          [
            '--no-config',
            '--color=never',
            '--no-heading',
            '--with-filename',
            '--line-number',
            ...(request.ignoreCase === true ? ['--ignore-case'] : []),
            ...excludeArgs(request),
            '-e',
            request.pattern,
            '--',
            '.',
          ],
          request.root,
          request.limit,
        ),
      listFiles: (request) => runRg(['--no-config', '--files', ...excludeArgs(request), '--', '.'], request.root, request.limit),
    },
    spill: {
      spill: async (name, content) => {
        await mkdir(spillDir, { recursive: true, mode: 0o700 });
        const path = join(spillDir, name);
        await writeFile(path, content, { mode: 0o600 });
        return path;
      },
    },
  };
}
