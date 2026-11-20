import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import {
  LinuxBox,
  NativeBox,
  NonceSinks,
  SeatbeltBox,
  applyImport,
  baselineFromJson,
  baselineToJson,
  createCopy,
  describeOsTier,
  detectLinuxSupport,
  loadBoxConfig,
  planImport,
  verifyNativeTier,
  verifyOsBoxTier,
  type Baseline,
  type BashOperations,
  type ExecOptions,
  type ExecResult,
  type ImportPlan,
  type ProcessOperations,
  type RunningProcess,
  type Skipped,
  type StartOptions,
} from '@hn/operations';
import { ContainerSandbox, quotaProblem, type FinishReport, type SandboxOptions, type SandboxPaths } from './sandbox.ts';

/**
 * What a session needs from a box, whatever kind it is: a container (tier 4) or the native box of this OS (tier 3).
 * Either way the box works on a copy, and changes come back through the import when the session ends.
 */
export interface Sandbox {
  readonly kind: 'container' | 'native';
  /** What the person is told it is: "container", "Windows box", "Linux box" or "macOS box". */
  readonly label: string;
  /** The layers the check verified, and any this machine could not apply. Empty where the box has no layers to name. */
  readonly layers: string;
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

/** What a native box of any OS gives a session. The OS-specific part is only here; the session logic is shared. */
interface NativeBackend {
  readonly label: 'Windows box' | 'Linux box' | 'macOS box';
  readonly work: string;
  readonly shell: 'powershell' | 'posix' | 'bash';
  exec(command: string, options: ExecOptions): Promise<ExecResult>;
  startProcess(command: string, options: StartOptions): RunningProcess;
  /** The outside-in check, run every time the box starts. */
  verify(sinks: NonceSinks, outside: string): Promise<{ readonly real: boolean; readonly evidence: readonly string[]; readonly summary: string }>;
  forget(): Promise<void>;
}

function windowsBackend(box: NativeBox): NativeBackend {
  return {
    label: 'Windows box',
    work: box.work,
    shell: box.shell.kind,
    exec: (command, options) => box.exec(command, options),
    startProcess: (command, options) => box.startProcess(command, options),
    verify: async (sinks, outside) => {
      const report = await verifyNativeTier(box, sinks, { outside, interpreter: process.execPath });
      return { real: report.real, evidence: report.evidence, summary: 'Windows AppContainer and job object' };
    },
    forget: () => box.forget(),
  };
}

/** The Linux and macOS boxes are checked layer by layer, and the layers that held (or could not be applied) are named. */
function posixBackend(box: LinuxBox | SeatbeltBox, interpreter: string): NativeBackend {
  return {
    label: box.kind === 'linux' ? 'Linux box' : 'macOS box',
    work: box.work,
    shell: box.shell,
    exec: (command, options) => box.exec(command, options),
    startProcess: (command, options) => box.startProcess(command, options),
    verify: async (sinks, outside) => {
      const report = await verifyOsBoxTier(box, sinks, { outside, interpreter });
      return { real: report.real, evidence: report.evidence, summary: describeOsTier(report) };
    },
    forget: async () => undefined,
  };
}

async function openBackend(paths: SandboxPaths & { readonly helper: string }, boxDir: string): Promise<NativeBackend> {
  if (process.platform === 'win32') {
    return windowsBackend(await NativeBox.open({ helper: paths.helper, boxDir, sessionId: paths.sessionId, config: await loadBoxConfig(paths.home), env: { HN_PARENT_SESSION: paths.sessionId } }));
  }
  if (process.platform !== 'linux' && process.platform !== 'darwin') throw new HnError('NO_NATIVE_BOX', `There is no native sandbox for ${process.platform}. Use --sandbox container.`);
  // Sandboxes match real paths, and the interpreter that runs the canary is the one file of the host the box may run.
  await mkdir(boxDir, { recursive: true, mode: 0o700 });
  const real = await realpath(boxDir);
  const interpreter = await realpath(process.execPath);
  const env = { HN_PARENT_SESSION: paths.sessionId };
  if (process.platform === 'darwin') return posixBackend(await SeatbeltBox.open({ boxDir: real, reads: [interpreter], env }), interpreter);
  const support = await detectLinuxSupport({ helper: paths.helper });
  return posixBackend(await LinuxBox.open({ boxDir: real, support, helper: paths.helper, reads: [interpreter], env }), interpreter);
}

/** The native box of this OS for a session: verified from outside every time it starts, never taken on trust. */
export class NativeSandbox implements Sandbox {
  readonly kind = 'native';
  readonly tier = 3;
  readonly #paths: SandboxPaths;
  readonly #box: NativeBackend;
  readonly boxDir: string;
  #alive = false;
  #quota: string | null = null;
  #watchdog: NodeJS.Timeout | null = null;
  #skipped: readonly Skipped[] = [];
  #layers = '';

  private constructor(paths: SandboxPaths, box: NativeBackend, boxDir: string) {
    this.#paths = paths;
    this.#box = box;
    this.boxDir = boxDir;
  }

  static async open(paths: SandboxPaths & { readonly helper: string }): Promise<NativeSandbox> {
    const boxDir = join(paths.home, 'boxes', paths.sessionId);
    const box = await openBackend(paths, boxDir);
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
      const report = await this.#box.verify(sinks, this.boxDir);
      if (!report.real) {
        await this.#box.forget();
        throw new HnError('SANDBOX_NOT_VERIFIED', `The ${this.#box.label} did not pass the outside-in check, so it is not used:\n- ${report.evidence.join('\n- ')}`);
      }
      this.#layers = report.summary;
    } finally {
      await sinks.close();
    }
    this.#alive = true;
    this.#quota = null;
    // Nothing caps a folder's size without admin rights, so the copy is measured while the box runs.
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

  get label(): string {
    return this.#box.label;
  }

  get layers(): string {
    return this.#layers;
  }

  get copy(): string {
    return this.#box.work;
  }

  get shell(): 'powershell' | 'posix' | 'bash' {
    return this.#box.shell;
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
    const note =
      this.shell === 'powershell'
        ? 'Here it is Windows PowerShell 5.1, in the Windows box: not bash. Write PowerShell: Get-Content, Set-Content, Get-ChildItem, Rename-Item, Select-String (with -CaseSensitive), Measure-Object, ConvertFrom-Json. There is no grep, sed, awk, cat -n or ls -la; && works only in PowerShell 7, so use ; or separate calls.'
        : this.shell === 'posix'
          ? `Here it is a POSIX sh (not bash) in the ${this.#box.label}.`
          : undefined;
    return {
      exec: (command, options) => (this.#alive ? this.#box.exec(command, options) : this.#refuse()),
      ...(note === undefined ? {} : { shell: note }),
    };
  }

  get processes(): ProcessOperations {
    return { start: (command, options) => (this.#alive ? this.#box.startProcess(command, options) : this.#refuse()) };
  }

  /** Every command is its own sandbox, so stopping is refusing new ones; a running one ends with its sandbox. */
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
