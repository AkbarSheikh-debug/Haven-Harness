import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, win32 } from 'node:path';
import { HnError } from '@hn/core';
import { wrapChild, type ProcessSignal, type RunningProcess, type StartOptions } from './processes.ts';
import type { ExecOptions, ExecResult } from './types.ts';

/**
 * The Windows native box. Every command is one `hn-sandbox run`: an AppContainer with no
 * capabilities, in a Job Object that kills everything it started when the command ends. The box sees only its own
 * folder (the copy, a home and a temp) and system folders Windows opens to every app; it has no network.
 *
 * Git Bash cannot start in an AppContainer (its runtime needs named objects the box cannot open), so the box shell is
 * Windows PowerShell, or a native POSIX shell the user pins in `~/.hn/box.json`.
 */

export interface BoxShell {
  readonly kind: 'powershell' | 'posix';
  readonly path: string;
}

/** What `hn-sandbox` read back from Windows about the process it started: the token and the job, not what was asked. */
export interface NativeReport {
  readonly appContainer: boolean;
  readonly capabilities: number;
  readonly integrity: number;
  readonly sid: string;
  readonly job: { readonly read: boolean; readonly killOnClose: boolean; readonly activeProcessLimit: number; readonly jobMemoryLimit: number };
}

export interface BoxConfig {
  readonly shell: BoxShell;
  /** Extra folders the box may read and run programs from, named by the user (never the project). */
  readonly reads: readonly string[];
}

const LOW_INTEGRITY = 0x1000;
const MAX_ENCODED_CHARS = 30_000;
export const DEFAULT_BOX_PROCESSES = 256;
export const DEFAULT_BOX_MEMORY = 4 * 1024 * 1024 * 1024;

export function powershellPath(env: NodeJS.ProcessEnv = process.env): string {
  return win32.join(env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

/**
 * `~/.hn/box.json` (user level only): `{ "shell": "C:\\tools\\busybox.exe", "sha256": "<hex>", "reads": ["C:\\tools"] }`.
 * A shell whose bytes do not match the pin is refused rather than run. Without the file the shell is PowerShell.
 */
export async function loadBoxConfig(home: string, env: NodeJS.ProcessEnv = process.env): Promise<BoxConfig> {
  const text = await readFile(join(home, 'box.json'), 'utf8').catch(() => null);
  if (text === null) return { shell: { kind: 'powershell', path: powershellPath(env) }, reads: [] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HnError('BAD_BOX_CONFIG', `${join(home, 'box.json')} is not valid JSON.`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new HnError('BAD_BOX_CONFIG', 'box.json must be an object.');
  const record = parsed as Record<string, unknown>;
  for (const key of Object.keys(record)) if (!['shell', 'sha256', 'reads'].includes(key)) throw new HnError('BAD_BOX_CONFIG', `box.json has an unknown field "${key}".`);
  const reads = record['reads'] ?? [];
  if (!Array.isArray(reads) || !reads.every((item) => typeof item === 'string' && win32.isAbsolute(item))) throw new HnError('BAD_BOX_CONFIG', 'box.json "reads" must be absolute folders.');
  if (record['shell'] === undefined) return { shell: { kind: 'powershell', path: powershellPath(env) }, reads: reads as string[] };
  const shell = record['shell'];
  const pin = record['sha256'];
  if (typeof shell !== 'string' || !win32.isAbsolute(shell)) throw new HnError('BAD_BOX_CONFIG', 'box.json "shell" must be an absolute path.');
  if (typeof pin !== 'string' || !/^[0-9a-f]{64}$/i.test(pin)) throw new HnError('BAD_BOX_CONFIG', 'box.json needs "sha256", the hash of the shell, so a swapped binary is not run.');
  const bytes = await readFile(shell).catch(() => null);
  if (bytes === null) throw new HnError('BAD_BOX_CONFIG', `The box shell ${shell} was not found.`);
  if (createHash('sha256').update(bytes).digest('hex') !== pin.toLowerCase()) throw new HnError('BOX_SHELL_CHANGED', `The box shell ${shell} does not match its pinned hash, so it is not used.`);
  return { shell: { kind: 'posix', path: shell }, reads: reads as string[] };
}

/** The program and arguments that run one shell command in the box. */
export function shellInvocation(shell: BoxShell, command: string, cwd: string): { program: string; args: string[] } {
  if (shell.kind === 'posix') {
    const busybox = /^busybox/i.test(basename(shell.path));
    return { program: shell.path, args: [...(busybox ? ['sh'] : []), '-c', command] };
  }
  // PowerShell takes the script as base64 UTF-16, so no character in it is ever re-quoted on the way in.
  const script = [
    "$ProgressPreference = 'SilentlyContinue'",
    // PowerShell walks every parent of a folder it is sent to, and the box may not see its parents; a drive rooted
    // at the folder needs none of them. Native programs it starts still get the real folder.
    `New-PSDrive -Name Box -PSProvider FileSystem -Root '${cwd.replaceAll("'", "''")}' | Out-Null`,
    'Set-Location Box:',
    `$global:LASTEXITCODE = 0`,
    command,
    'if ($LASTEXITCODE) { exit $LASTEXITCODE } elseif (-not $?) { exit 1 }',
  ].join('\n');
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  if (encoded.length > MAX_ENCODED_CHARS) {
    throw new HnError('COMMAND_TOO_LONG', 'This command is too long for the Windows box. Write it to a script file in the project and run that.');
  }
  return { program: shell.path, args: ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-OutputFormat', 'Text', '-EncodedCommand', encoded] };
}

export interface NativeBoxOptions {
  readonly helper: string;
  /** `<home>/boxes/<session>`. The box gets `box/` under it; this folder itself stays closed to the box. */
  readonly boxDir: string;
  readonly sessionId: string;
  readonly config: BoxConfig;
  readonly env?: Readonly<Record<string, string>>;
  readonly processes?: number;
  readonly memory?: number;
}

export interface RunRequest {
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
  readonly input?: string;
  /** Ask the helper for the token and job report of this run. */
  readonly report?: boolean;
}

export interface RunOutcome extends ExecResult {
  readonly report: NativeReport | null;
}

const GRACE_MS = 3_000;
const MAX_CAPTURE = 64 * 1024 * 1024;

function capture(): { add(chunk: Buffer): void; bytes(): Buffer; clipped(): boolean } {
  const chunks: Buffer[] = [];
  let size = 0;
  let clipped = false;
  return {
    add(chunk) {
      const room = MAX_CAPTURE - size;
      if (room <= 0) {
        clipped = true;
        return;
      }
      const kept = chunk.length > room ? chunk.subarray(0, room) : chunk;
      clipped ||= kept.length < chunk.length;
      chunks.push(kept);
      size += kept.length;
    },
    bytes: () => Buffer.concat(chunks),
    clipped: () => clipped,
  };
}

/** The profile name for a session: only letters, digits, dots and dashes reach Windows. */
export const boxProfileName = (sessionId: string): string => `hn.box.${sessionId.replace(/[^A-Za-z0-9-]/g, '-')}`.slice(0, 64);

export class NativeBox {
  readonly #options: NativeBoxOptions;
  readonly name: string;
  readonly root: string;
  readonly work: string;
  readonly home: string;
  readonly tmp: string;

  private constructor(options: NativeBoxOptions) {
    this.#options = options;
    this.name = boxProfileName(options.sessionId);
    this.root = join(options.boxDir, 'box');
    this.work = join(this.root, 'work');
    this.home = join(this.root, 'home');
    this.tmp = join(this.root, 'tmp');
  }

  /** Makes the box folders. The copy itself is made by the caller into `work`. */
  static async open(options: NativeBoxOptions): Promise<NativeBox> {
    if (process.platform !== 'win32') throw new HnError('NO_NATIVE_BOX', 'The native box in hn-sandbox is Windows only.');
    if (!isAbsolute(options.helper)) throw new HnError('NO_NATIVE_BOX', 'hn-sandbox must be given by absolute path.');
    const box = new NativeBox(options);
    for (const dir of [box.work, box.home, box.tmp]) await mkdir(dir, { recursive: true });
    // Windows points the box's TEMP under LOCALAPPDATA\Packages\<profile>\AC; it must exist inside the box.
    await mkdir(join(box.home, 'Packages', box.name, 'AC', 'Temp'), { recursive: true });
    return box;
  }

  get shell(): BoxShell {
    return this.#options.config.shell;
  }

  /** The whole environment of the box. Nothing is inherited from this process, so no key can leak in. */
  environment(extra: Readonly<Record<string, string>> = {}): Record<string, string> {
    const systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows';
    const path = [dirname(this.#options.config.shell.path), win32.join(systemRoot, 'System32'), systemRoot, win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0'), dirname(process.execPath), ...this.#options.config.reads];
    return {
      SystemRoot: systemRoot,
      windir: systemRoot,
      ComSpec: win32.join(systemRoot, 'System32', 'cmd.exe'),
      PATHEXT: '.COM;.EXE;.BAT;.CMD;.PS1',
      PATH: [...new Set(path)].join(';'),
      LOCALAPPDATA: this.home,
      APPDATA: this.home,
      USERPROFILE: this.home,
      HOME: this.home,
      TEMP: this.tmp,
      TMP: this.tmp,
      NUMBER_OF_PROCESSORS: process.env['NUMBER_OF_PROCESSORS'] ?? '1',
      PROCESSOR_ARCHITECTURE: process.env['PROCESSOR_ARCHITECTURE'] ?? 'AMD64',
      HN_BOX: '1',
      ...this.#options.env,
      ...extra,
    };
  }

  #args(program: string, args: readonly string[], cwd: string, report: string | null, extraEnv: Readonly<Record<string, string>>): string[] {
    const env = Object.entries(this.environment(extraEnv)).flatMap(([key, value]) => ['--env', `${key}=${value}`]);
    return [
      'run',
      '--name', this.name,
      '--grant', this.root,
      ...this.#options.config.reads.flatMap((dir) => ['--read', dir]),
      '--cwd', cwd,
      '--processes', String(this.#options.processes ?? DEFAULT_BOX_PROCESSES),
      '--memory', String(this.#options.memory ?? DEFAULT_BOX_MEMORY),
      ...(report === null ? [] : ['--report', report]),
      ...env,
      '--',
      program,
      ...args,
    ];
  }

  /** Runs one program in the box to completion. Stopping the helper closes the job, which kills everything in the box. */
  run(program: string, args: readonly string[], request: RunRequest): Promise<RunOutcome> {
    const reportPath = request.report === true ? join(dirname(this.root), `report-${randomUUID()}.json`) : null;
    return new Promise((resolve, reject) => {
      const child = spawn(this.#options.helper, this.#args(program, args, request.cwd, reportPath, { HN_EXEC: randomUUID() }), { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      const stdout = capture();
      const stderr = capture();
      let timedOut = false;
      let cancelled = false;
      let drain: NodeJS.Timeout | undefined;
      const stop = (): void => {
        child.kill();
        drain = setTimeout(() => {
          child.stdout.destroy();
          child.stderr.destroy();
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
      child.stdout.on('data', (chunk: Buffer) => stdout.add(chunk));
      child.stderr.on('data', (chunk: Buffer) => stderr.add(chunk));
      child.stdin.on('error', () => undefined);
      child.stdin.end(request.input ?? '');
      child.once('error', reject);
      child.once('close', (code) => {
        clearTimeout(timer);
        if (drain !== undefined) clearTimeout(drain);
        request.signal.removeEventListener('abort', onAbort);
        void (async () => {
          let report: NativeReport | null = null;
          if (reportPath !== null) {
            report = await readFile(reportPath, 'utf8').then((text) => JSON.parse(text) as NativeReport, () => null);
            await rm(reportPath, { force: true });
          }
          resolve({ code, stdout: stdout.bytes(), stderr: stderr.bytes(), timedOut, cancelled, clipped: stdout.clipped() || stderr.clipped(), report });
        })();
      });
    });
  }

  /** A shell command, as the `bash` tool runs it. */
  exec(command: string, options: ExecOptions): Promise<ExecResult> {
    const { program, args } = shellInvocation(this.shell, command, options.cwd);
    return this.run(program, args, { cwd: options.cwd, timeoutMs: options.timeoutMs, signal: options.signal, ...(options.input === undefined ? {} : { input: options.input }) });
  }

  /** A job or terminal. Every signal stops the helper, and with it the whole box process tree. */
  startProcess(command: string, options: StartOptions): RunningProcess {
    const { program, args } = shellInvocation(this.shell, command, options.cwd);
    const child = spawn(this.#options.helper, this.#args(program, args, options.cwd, null, { HN_EXEC: randomUUID() }), {
      stdio: [options.input ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    return wrapChild(child, (_kind: ProcessSignal) => void child.kill());
  }

  /** Removes the session's AppContainer profile. Its SID is derived from the name, so this keeps names from being reused. */
  async forget(): Promise<void> {
    await new Promise<void>((resolve) => {
      const child = spawn(this.#options.helper, ['forget', '--name', this.name], { stdio: 'ignore', windowsHide: true });
      child.once('error', () => resolve());
      child.once('close', () => resolve());
    });
  }
}

/** Why a report does not describe a real box, in plain words; empty when it does. */
export function nativeReportProblems(report: NativeReport | null): string[] {
  if (report === null) return ['The helper wrote no report of the token it started, so nothing about the box is known.'];
  const problems: string[] = [];
  if (!report.appContainer) problems.push('The process was not in an AppContainer.');
  if (report.capabilities !== 0) problems.push(`The box token has ${report.capabilities} capabilities; it must have none, or it may reach the network.`);
  if (report.integrity < 0 || report.integrity > LOW_INTEGRITY) problems.push(`The box token's integrity level is ${report.integrity}, above low.`);
  if (!report.job.read) problems.push('The job object could not be read back.');
  if (!report.job.killOnClose) problems.push('The job does not kill its processes when the box ends.');
  return problems;
}

/** Node is the canary's interpreter. It must be readable by the box, which is true for an install under Program Files. */
export const canaryInterpreter = (): string | null => (existsSync(process.execPath) ? process.execPath : null);
