import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import {
  NativeBox,
  NonceSinks,
  applyImport,
  baselineFromJson,
  baselineToJson,
  createCopy,
  loadBoxConfig,
  planImport,
  verifyNativeTier,
  type Baseline,
  type BashOperations,
  type ImportPlan,
  type ProcessOperations,
  type Skipped,
} from '@hn/operations';
import { ContainerSandbox, quotaProblem, type FinishReport, type SandboxOptions, type SandboxPaths } from './sandbox.ts';

/**
 * What a session needs from a box, whatever kind it is: a container (tier 4) or the Windows native box (tier 3).
 * Either way the box works on a copy, and changes come back through the import when the session ends.
 */
export interface Sandbox {
  readonly kind: 'container' | 'native';
  readonly tier: number;
  readonly copy: string;
  readonly bash: BashOperations;
  readonly processes: ProcessOperations;
  readonly alive: boolean;
  readonly quotaExceeded: string | null;
  readonly skippedOnCopy: readonly Skipped[];
  /** The shell the `bash` tool really runs. Only `bash` gets the bash parser at the gate. */
  readonly shell: 'bash' | 'powershell' | 'posix';
  stop(): Promise<void>;
  whileStopped<T>(work: () => Promise<T>): Promise<T>;
  finish(approve?: (plan: ImportPlan) => Promise<ReadonlyMap<string, string>>): Promise<FinishReport>;
}

const DISK_LIMIT = 2 * 1024 * 1024 * 1024;
const INODE_LIMIT = 200_000;

/** The Windows native box for a session: verified from outside every time it starts, never taken on trust. */
export class NativeSandbox implements Sandbox {
  readonly kind = 'native';
  readonly tier = 3;
  readonly #paths: SandboxPaths;
  readonly #box: NativeBox;
  readonly boxDir: string;
  #alive = false;
  #quota: string | null = null;
  #watchdog: NodeJS.Timeout | null = null;
  #skipped: readonly Skipped[] = [];

  private constructor(paths: SandboxPaths, box: NativeBox, boxDir: string) {
    this.#paths = paths;
    this.#box = box;
    this.boxDir = boxDir;
  }

  static async open(paths: SandboxPaths & { readonly helper: string }): Promise<NativeSandbox> {
    if (process.platform !== 'win32') throw new HnError('NO_NATIVE_BOX', 'The native sandbox is the Windows box. On Linux and macOS use --sandbox container.');
    const boxDir = join(paths.home, 'boxes', paths.sessionId);
    const box = await NativeBox.open({ helper: paths.helper, boxDir, sessionId: paths.sessionId, config: await loadBoxConfig(paths.home), env: { HN_PARENT_SESSION: paths.sessionId } });
    const sandbox = new NativeSandbox(paths, box, boxDir);
    const made = await createCopy(paths.hostRoot, box.work, { skip: (path) => path === 'node_modules' || path.endsWith('/node_modules') });
    sandbox.#skipped = made.skipped;
    // Kept beside the box, in a folder the box is never granted.
    await writeFile(join(boxDir, 'baseline.json'), baselineToJson(made.baseline), { mode: 0o600 });
    await sandbox.#start();
    return sandbox;
  }

  async #start(): Promise<void> {
    const sinks = await NonceSinks.open();
    try {
      const report = await verifyNativeTier(this.#box, sinks, { outside: this.boxDir, interpreter: process.execPath });
      if (!report.real) {
        await this.#box.forget();
        throw new HnError('SANDBOX_NOT_VERIFIED', `The Windows box did not pass the outside-in check, so it is not used:\n- ${report.evidence.join('\n- ')}`);
      }
    } finally {
      await sinks.close();
    }
    this.#alive = true;
    this.#quota = null;
    // Nothing caps a folder's size on Windows without admin rights, so the copy is measured while the box runs.
    const timer = setInterval(() => {
      void quotaProblem(this.copy, DISK_LIMIT, INODE_LIMIT).then((problem) => {
        if (problem === null) return;
        this.#quota = problem;
        this.#alive = false;
      });
    }, 5_000);
    timer.unref();
    this.#watchdog = timer;
  }

  get copy(): string {
    return this.#box.work;
  }

  get shell(): 'powershell' | 'posix' {
    return this.#box.shell.kind;
  }

  get alive(): boolean {
    return this.#alive;
  }

  get quotaExceeded(): string | null {
    return this.#quota;
  }

  get skippedOnCopy(): readonly Skipped[] {
    return this.#skipped;
  }

  #refuse(): never {
    throw new HnError(this.#quota === null ? 'BOX_STOPPED' : 'BOX_QUOTA', this.#quota ?? 'The box is stopped. Restart it before running commands.');
  }

  get bash(): BashOperations {
    return {
      exec: (command, options) => (this.#alive ? this.#box.exec(command, options) : this.#refuse()),
      shell:
        this.shell === 'powershell'
          ? 'Here it is Windows PowerShell 5.1, in the Windows box: not bash. Write PowerShell: Get-Content, Set-Content, Get-ChildItem, Rename-Item, Select-String (with -CaseSensitive), Measure-Object, ConvertFrom-Json. There is no grep, sed, awk, cat -n or ls -la; && works only in PowerShell 7, so use ; or separate calls.'
          : 'Here it is a POSIX sh (not bash) in the Windows box.',
    };
  }

  get processes(): ProcessOperations {
    return { start: (command, options) => (this.#alive ? this.#box.startProcess(command, options) : this.#refuse()) };
  }

  /** Every command is its own job object, so stopping is refusing new ones; a running one ends with its helper. */
  async stop(): Promise<void> {
    if (this.#watchdog !== null) clearInterval(this.#watchdog);
    this.#watchdog = null;
    this.#alive = false;
  }

  async whileStopped<T>(work: () => Promise<T>): Promise<T> {
    await this.stop();
    try {
      return await work();
    } finally {
      await this.#start();
    }
  }

  async finish(approve?: (plan: ImportPlan) => Promise<ReadonlyMap<string, string>>): Promise<FinishReport> {
    await this.stop();
    try {
      const baseline: Baseline = baselineFromJson(await readFile(join(this.boxDir, 'baseline.json'), 'utf8'));
      const plan = await planImport(this.#paths.hostRoot, this.copy, baseline);
      const approved = approve === undefined ? new Map<string, string>() : await approve(plan);
      const result = await applyImport(plan, { files: this.#paths.files, hostRoot: this.#paths.hostRoot, copyRoot: this.copy, baseline, approved });
      return { plan, result, skippedOnCopy: this.#skipped };
    } finally {
      await this.#box.forget();
    }
  }
}

/** Opens the box a session asked for. */
export async function openSandbox(options: SandboxOptions, paths: SandboxPaths & { readonly helper: string }): Promise<Sandbox> {
  return options.kind === 'native' ? NativeSandbox.open(paths) : ContainerSandbox.open(options, paths);
}
