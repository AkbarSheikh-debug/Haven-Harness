import { lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { isAbsolute, join, posix, relative, sep } from 'node:path';
import { HnError } from '@hn/core';
import {
  ContainerBox,
  NonceSinks,
  applyImport,
  assertPinned,
  baselineFromJson,
  baselineToJson,
  canaryScript,
  canaryProblems,
  createCopy,
  dockerIsUp,
  findDocker,
  hostAddresses,
  planImport,
  verifyTier,
  type Baseline,
  type BashOperations,
  type ProcessOperations,
  type ImportPlan,
  type ImportResult,
  type SafeFiles,
  type Skipped,
} from '@hn/operations';

/**
 * Where the session's tools really run, and what tier that earns. The tier is never taken on trust:
 * a container is verified from outside before it counts, and an operator's claim of an outer boundary
 * counts for less (it is capped, and never enough for yolo).
 */

export interface ContainerOptions {
  readonly kind: 'container';
  /** Must be pinned by digest. */
  readonly image: string;
  /** The most the box may write to its copy of the project. Default 2 GiB. */
  readonly diskLimitBytes?: number;
  /** The most files and folders the copy may hold. Default 200,000. */
  readonly inodeLimit?: number;
  /** How often the copy is measured while the box runs. Default 2 seconds. */
  readonly diskCheckMs?: number;
}

/** The box a session asks for: a container (tier 4), or the Windows native box (tier 3). */
export type SandboxOptions = ContainerOptions | { readonly kind: 'native' };

const DEFAULT_DISK_LIMIT = 2 * 1024 * 1024 * 1024;
const DEFAULT_INODE_LIMIT = 200_000;

/** Total size and entry count under a folder, counting without following links, and stopping once a limit is passed. */
async function measure(root: string, maxBytes: number, maxEntries: number): Promise<{ bytes: number; entries: number }> {
  let bytes = 0;
  let entries = 0;
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
      if (bytes > maxBytes || entries > maxEntries) return;
      entries += 1;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) bytes += (await lstat(path).catch(() => null))?.size ?? 0;
    }
  };
  await walk(root);
  return { bytes, entries };
}

/** Why a box's copy is over its limits, in words for the person, or null if it is within them. */
export async function quotaProblem(copy: string, bytesLimit: number, entryLimit: number): Promise<string | null> {
  const { bytes, entries } = await measure(copy, bytesLimit, entryLimit);
  if (bytes > bytesLimit) return `The box wrote more than ${bytesLimit} bytes to its copy of the project, so it was stopped.`;
  if (entries > entryLimit) return `The box created more than ${entryLimit} files, so it was stopped.`;
  return null;
}

export interface SandboxPaths {
  readonly home: string;
  readonly sessionId: string;
  readonly hostRoot: string;
  readonly files: SafeFiles;
}

export interface FinishReport {
  readonly plan: ImportPlan;
  readonly result: ImportResult;
  readonly skippedOnCopy: readonly Skipped[];
}

/** A box that can be stopped and started again, with the tier re-verified every time. */
export class ContainerSandbox {
  readonly kind = 'container';
  /** The bash tool runs bash in the container, so the gate's bash parser applies. */
  readonly shell = 'bash';
  readonly #options: ContainerOptions;
  readonly #paths: SandboxPaths;
  readonly #docker: string;
  readonly boxDir: string;
  readonly copy: string;
  #box: ContainerBox | null = null;
  #watchdog: NodeJS.Timeout | null = null;
  #quota: string | null = null;
  #baseline: Baseline = new Map();
  #copySkipped: readonly Skipped[] = [];

  private constructor(options: ContainerOptions, paths: SandboxPaths, docker: string) {
    this.#options = options;
    this.#paths = paths;
    this.#docker = docker;
    this.boxDir = join(paths.home, 'boxes', paths.sessionId);
    this.copy = join(this.boxDir, 'copy');
  }

  /** Copies the project, starts the box, and refuses unless the outside-in check passes. */
  static async open(options: ContainerOptions, paths: SandboxPaths): Promise<ContainerSandbox> {
    assertPinned(options.image);
    const docker = await findDocker();
    if (docker === null || !(await dockerIsUp(docker))) throw new HnError('NO_DOCKER', 'Docker is not running, so the container sandbox is not available. Start Docker, or run without --sandbox.');
    const sandbox = new ContainerSandbox(options, paths, docker);
    await mkdir(sandbox.boxDir, { recursive: true, mode: 0o700 });
    const made = await createCopy(paths.hostRoot, sandbox.copy, { skip: (path) => path === 'node_modules' || path.endsWith('/node_modules') });
    sandbox.#baseline = made.baseline;
    sandbox.#copySkipped = made.skipped;
    // Kept next to the copy, never inside the folder the box can write.
    await writeFile(join(sandbox.boxDir, 'baseline.json'), baselineToJson(made.baseline), { mode: 0o600 });
    await sandbox.#start();
    return sandbox;
  }

  async #start(): Promise<void> {
    const box = await ContainerBox.start({ image: this.#options.image, sessionId: this.#paths.sessionId, workDir: this.copy, docker: this.#docker });
    const sinks = await NonceSinks.open();
    try {
      const report = await verifyTier(box, sinks);
      if (!report.real) {
        await box.stop();
        throw new HnError('SANDBOX_NOT_VERIFIED', `The sandbox did not pass the outside-in check, so it is not used:\n- ${report.evidence.join('\n- ')}`);
      }
    } finally {
      await sinks.close();
    }
    this.#box = box;
    this.#quota = null;
    this.#startWatchdog();
  }

  /**
   * Docker cannot cap a bind mount, so the copy is measured while the box runs. A box that passes the limit is stopped,
   * and says why, so it cannot fill the disk it shares with you.
   */
  #startWatchdog(): void {
    const bytesLimit = this.#options.diskLimitBytes ?? DEFAULT_DISK_LIMIT;
    const entryLimit = this.#options.inodeLimit ?? DEFAULT_INODE_LIMIT;
    let checking = false;
    const timer = setInterval(() => {
      if (checking) return;
      checking = true;
      void quotaProblem(this.copy, bytesLimit, entryLimit)
        .then(async (problem) => {
          if (problem === null) return;
          this.#quota = problem;
          await this.stop();
        })
        .finally(() => {
          checking = false;
        });
    }, this.#options.diskCheckMs ?? 2_000);
    timer.unref();
    this.#watchdog = timer;
  }

  /** Why the box was stopped for using too much disk, or null. */
  get quotaExceeded(): string | null {
    return this.#quota;
  }

  get alive(): boolean {
    return this.#box !== null;
  }

  /** The tier a verified container earns. */
  readonly tier = 4;

  get skippedOnCopy(): readonly Skipped[] {
    return this.#copySkipped;
  }

  get bash(): BashOperations {
    return {
      exec: (command, options) => {
        if (this.#box === null) throw new HnError(this.#quota === null ? 'BOX_STOPPED' : 'BOX_QUOTA', this.#quota ?? 'The box is stopped. Restart it before running commands.');
        return this.#box.exec(command, { ...options, cwd: this.#inner(options.cwd) });
      },
    };
  }

  /** A folder of the project, as the box sees it: the same place under /work. Anything else is /work itself. */
  #inner(cwd: string): string {
    const rel = relative(this.#paths.hostRoot, cwd);
    return rel === '' || rel.startsWith('..') || isAbsolute(rel) ? '/work' : posix.join('/work', ...rel.split(sep));
  }

  /** Jobs and terminals run in the box, never on the host. */
  get processes(): ProcessOperations {
    return {
      start: (command, options) => {
        if (this.#box === null) throw new HnError('BOX_STOPPED', 'The box is stopped. Restart it before starting a job.');
        return this.#box.startProcess(command, { ...options, cwd: this.#inner(options.cwd) });
      },
    };
  }

  async stop(): Promise<void> {
    if (this.#watchdog !== null) clearInterval(this.#watchdog);
    this.#watchdog = null;
    const box = this.#box;
    this.#box = null;
    await box?.stop();
  }

  /** Stops the box, runs `work` while nothing can race it, then starts and re-verifies the box. Used for a rollback. */
  async whileStopped<T>(work: () => Promise<T>): Promise<T> {
    await this.stop();
    try {
      return await work();
    } finally {
      await this.#start();
    }
  }

  /**
   * Ends the session: stops the box and brings its changes back. Ordinary files go back by themselves; files
   * on the host-exec manifest go back only if `approve` returns their exact content hash. With no approver
   * (an unattended run) none of them do.
   */
  async finish(approve?: (plan: ImportPlan) => Promise<ReadonlyMap<string, string>>): Promise<FinishReport> {
    await this.stop();
    const baseline = baselineFromJson(await readFile(join(this.boxDir, 'baseline.json'), 'utf8'));
    const plan = await planImport(this.#paths.hostRoot, this.copy, baseline);
    const approved = approve === undefined ? new Map<string, string>() : await approve(plan);
    const result = await applyImport(plan, { files: this.#paths.files, hostRoot: this.#paths.hostRoot, copyRoot: this.copy, baseline, approved });
    return { plan, result, skippedOnCopy: this.#copySkipped };
  }
}

/** An external boundary an operator claims (CI, Terminal-Bench). It is capped, logged, and never counts as verified. */
export interface ExternalSandbox {
  readonly tier: 3;
  readonly asserted: true;
}

/**
 * `--external-sandbox`: needs a user-level allow entry, is refused on a host that looks like a workstation,
 * and still runs the canary, so a box that is not actually cut off from this machine is caught.
 */
export async function assertExternalSandbox(home: string, env: NodeJS.ProcessEnv, bash: BashOperations, cwd: string): Promise<ExternalSandbox> {
  const allowed = await readFile(join(home, 'external-sandbox-allowed'), 'utf8').then(
    () => true,
    () => false,
  );
  if (!allowed) throw new HnError('EXTERNAL_SANDBOX_NOT_ALLOWED', `--external-sandbox needs a user-level allow entry: create ${join(home, 'external-sandbox-allowed')}. A project cannot grant this itself.`);
  if (env['CI'] !== 'true' && env['CI'] !== '1') {
    throw new HnError('EXTERNAL_SANDBOX_WORKSTATION', 'This host looks like a workstation, not a CI machine, so a claimed outer sandbox is refused. Use --sandbox container.');
  }
  const sinks = await NonceSinks.open();
  try {
    const ran = await bash.exec(`echo ${Buffer.from(canaryScript(sinks, hostAddresses()), 'utf8').toString('base64')} | base64 -d | sh`, {
      cwd,
      timeoutMs: 60_000,
      signal: new AbortController().signal,
    });
    await new Promise((resolve) => setTimeout(resolve, 400));
    if (sinks.hits.length > 0) throw new HnError('EXTERNAL_SANDBOX_LEAKS', `The claimed sandbox is not cut off from this machine: ${sinks.hits.length} connection(s) reached it.`);
    const untested = canaryProblems(ran.stdout.toString('utf8'));
    if (untested.length > 0) throw new HnError('EXTERNAL_SANDBOX_UNTESTED', `The claimed sandbox could not be checked, so it is refused: ${untested.join(' ')}`);
  } finally {
    await sinks.close();
  }
  return { tier: 3, asserted: true };
}
