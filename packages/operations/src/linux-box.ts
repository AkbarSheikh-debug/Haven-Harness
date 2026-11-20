import { spawn } from 'node:child_process';
import { accessSync, constants, existsSync } from 'node:fs';
import { delimiter, isAbsolute, join } from 'node:path';
import { HnError } from '@hn/core';
import { bwrapRun, type BwrapOptions, type OsBoxPaths } from './os-boxes.ts';
import { PosixBox, type BoxLayers } from './posix-box.ts';
import type { ProcessSignal } from './processes.ts';

/**
 * The Linux native box: every command is one `bwrap`, and, where the kernel has them, Landlock and seccomp on top
 * (`hn-sandbox confine`). Nothing is assumed. `detectLinuxSupport` asks the machine, and a layer the machine lacks is
 * left out and named, so the box is reported as a lower tier instead of a layer being claimed that is not there.
 */

export interface LinuxSupport {
  /** Absolute path of bubblewrap, or null. */
  readonly bwrap: string | null;
  /** Whether bubblewrap could really start a box with every namespace unshared here. */
  readonly namespaces: boolean;
  /** Why not, in words for the person, with the setting that changes it when it is known. */
  readonly namespaceProblem: string | null;
  /** The Landlock ABI version the kernel offers, 0 when it has none. */
  readonly landlockAbi: number;
  readonly seccomp: boolean;
  /** Why Landlock or seccomp could not be asked about (no helper). */
  readonly confineProblem: string | null;
}

/** Looks for a program by absolute path in PATH, never by a bare name that a project folder could shadow. */
export function findOnPath(name: string, env: NodeJS.ProcessEnv = process.env): string | null {
  for (const dir of (env['PATH'] ?? '').split(delimiter)) {
    if (dir === '' || !isAbsolute(dir)) continue;
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Not here.
    }
  }
  return null;
}

interface Ran {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runPlain(file: string, args: readonly string[], timeoutMs = 20_000): Promise<Ran> {
  return new Promise((resolve) => {
    const child = spawn(file, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin' } });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
    child.once('error', (error) => {
      clearTimeout(timer);
      resolve({ code: null, stdout, stderr: `${stderr}${error.message}` });
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

/** The setting that most often stops bubblewrap on a distribution that restricts user namespaces, named when the error looks like it. */
export function namespaceHint(stderr: string): string {
  if (/uid map|Operation not permitted|No permissions to create|Permission denied|setting up uid/i.test(stderr)) {
    return ' Namespaces for ordinary users may be switched off here: on Ubuntu 24.04 and later, `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` allows them; in a Docker container, bubblewrap needs a privileged container (Docker\'s default seccomp profile forbids it).';
  }
  return '';
}

/** Asks this machine what it can do. Changes nothing. */
export async function detectLinuxSupport(options: { helper?: string; env?: NodeJS.ProcessEnv } = {}): Promise<LinuxSupport> {
  const bwrap = process.platform === 'linux' ? findOnPath('bwrap', options.env) : null;
  let namespaces = false;
  let namespaceProblem: string | null = null;
  if (process.platform !== 'linux') namespaceProblem = 'bubblewrap is a Linux sandbox.';
  else if (bwrap === null) namespaceProblem = 'bubblewrap (bwrap) is not installed. Install it with your package manager (apt install bubblewrap, dnf install bubblewrap).';
  else {
    const ran = await runPlain(bwrap, ['--unshare-all', '--die-with-parent', '--ro-bind-try', '/usr', '/usr', '--ro-bind-try', '/bin', '/bin', '--ro-bind-try', '/lib', '/lib', '--ro-bind-try', '/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--', '/bin/sh', '-c', 'true']);
    namespaces = ran.code === 0;
    if (!namespaces) namespaceProblem = `bubblewrap could not start a box here: ${ran.stderr.trim().split('\n')[0] ?? 'no message'}.${namespaceHint(ran.stderr)}`;
  }
  let landlockAbi = 0;
  let seccomp = false;
  let confineProblem: string | null = null;
  if (options.helper === undefined) confineProblem = 'hn-sandbox is not available, so Landlock and seccomp cannot be applied.';
  else {
    const ran = await runPlain(options.helper, ['probe']);
    try {
      const parsed = JSON.parse(ran.stdout) as { landlock_abi?: unknown; seccomp?: unknown };
      landlockAbi = typeof parsed.landlock_abi === 'number' ? parsed.landlock_abi : 0;
      seccomp = parsed.seccomp === true;
    } catch {
      confineProblem = `hn-sandbox could not say what this kernel supports: ${ran.stderr.trim().slice(0, 200)}`;
    }
  }
  return { bwrap, namespaces, namespaceProblem, landlockAbi, seccomp, confineProblem };
}

export interface LinuxBoxOptions {
  /** `<home>/boxes/<session>`. The box gets `box/` under it; this folder itself stays closed to the box. */
  readonly boxDir: string;
  readonly support: LinuxSupport;
  /** hn-sandbox, for Landlock and seccomp. Without it the box is bubblewrap alone. */
  readonly helper?: string;
  /** Extra files or folders the box may read (the interpreter that runs the canary). */
  readonly reads?: readonly string[];
  /** Ask for fewer layers than the kernel has (a test of the lower tier). Never more. */
  readonly layers?: { readonly landlock?: boolean; readonly seccomp?: boolean };
  readonly env?: Readonly<Record<string, string>>;
  /** Changes the sandbox's command line, to build a box that leaks for a test of the check. Never set in production. */
  readonly rewriteArgs?: (args: string[]) => string[];
}

export class LinuxBox extends PosixBox {
  readonly kind = 'linux';
  readonly #bwrap: string;
  readonly #options: LinuxBoxOptions;
  readonly #confine: BwrapOptions['confine'] | undefined;
  readonly #layers: BoxLayers;
  readonly #shell: string;

  private constructor(options: LinuxBoxOptions, bwrap: string) {
    super(options.boxDir);
    this.#options = options;
    this.#bwrap = bwrap;
    const support = options.support;
    const missing: { layer: string; reason: string }[] = [];
    const applied = ['namespaces'];
    const wantLandlock = options.layers?.landlock ?? true;
    const wantSeccomp = options.layers?.seccomp ?? true;
    let landlock = false;
    let seccomp = false;
    if (options.helper === undefined) {
      if (wantLandlock) missing.push({ layer: 'landlock', reason: support.confineProblem ?? 'hn-sandbox is not available.' });
      if (wantSeccomp) missing.push({ layer: 'seccomp', reason: support.confineProblem ?? 'hn-sandbox is not available.' });
    } else {
      if (wantLandlock) {
        if (support.landlockAbi >= 1) landlock = true;
        else missing.push({ layer: 'landlock', reason: support.confineProblem ?? 'This kernel does not have Landlock enabled.' });
      }
      if (wantSeccomp) {
        if (support.seccomp) seccomp = true;
        else missing.push({ layer: 'seccomp', reason: support.confineProblem ?? 'This kernel does not have seccomp filters.' });
      }
    }
    if (landlock) applied.push('landlock');
    if (seccomp) applied.push('seccomp');
    this.#layers = { applied, missing };
    this.#confine = options.helper !== undefined && (landlock || seccomp) ? { helper: options.helper, landlock, seccomp } : undefined;
    this.#shell = existsSync('/bin/bash') ? '/bin/bash' : '/bin/sh';
  }

  /** Makes the box folders. The copy itself is made by the caller into `work`. */
  static async open(options: LinuxBoxOptions): Promise<LinuxBox> {
    if (process.platform !== 'linux') throw new HnError('NO_LINUX_BOX', 'The bubblewrap box is Linux only.');
    if (options.support.bwrap === null || !options.support.namespaces) {
      throw new HnError('NO_LINUX_BOX', options.support.namespaceProblem ?? 'bubblewrap is not available, so there is no Linux box.');
    }
    if (options.helper !== undefined && !isAbsolute(options.helper)) throw new HnError('NO_LINUX_BOX', 'hn-sandbox must be given by absolute path.');
    const box = new LinuxBox(options, options.support.bwrap);
    await box.makeFolders();
    return box;
  }

  get layers(): BoxLayers {
    return this.#layers;
  }

  get shellPath(): string {
    return this.#shell;
  }

  /** The whole environment of the box. Nothing is inherited from this process, so no key can leak in. */
  environment(extra: Readonly<Record<string, string>> = {}): Record<string, string> {
    return { HN_BOX: '1', LANG: 'C.UTF-8', ...this.#options.env, ...extra };
  }

  get #paths(): OsBoxPaths {
    return { copy: this.work, home: this.home, tmp: this.tmp, cwd: this.work };
  }

  wrap(program: string, args: readonly string[], cwd: string): { file: string; args: string[] } {
    const paths = { ...this.#paths, cwd };
    const options: BwrapOptions = { ...(this.#options.reads === undefined ? {} : { reads: this.#options.reads }), ...(this.#confine === undefined ? {} : { confine: this.#confine }) };
    const built = bwrapRun(paths, program, args, this.environment(), options);
    return { file: this.#bwrap, args: this.#options.rewriteArgs === undefined ? built : this.#options.rewriteArgs(built) };
  }

  protected spawnEnv(): NodeJS.ProcessEnv {
    return { PATH: '/usr/bin:/bin' };
  }

  /** Stopping the sandbox's own process ends the namespace's init, and with it everything inside. */
  protected signalFor(_kind: ProcessSignal): NodeJS.Signals {
    return 'SIGKILL';
  }

  /** Nothing is registered with the system for a Linux box, so there is nothing to remove. */
  async forget(): Promise<void> {
    return undefined;
  }
}
