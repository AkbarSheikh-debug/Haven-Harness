import { wrapChild, type RunningProcess, type StartOptions } from './processes.ts';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { HnError } from '@hn/core';
import type { BashOperations, ExecOptions, ExecResult } from './types.ts';

/**
 * Tier 4: one container per session. The box is small (it works on a copy of the project, never
 * the host tree), observable and deterministic (a pinned image). The tier is never taken on
 * trust: after it starts, `docker inspect` is read back and checked against what was asked for.
 */

/** A digest pin (name@sha256:...), or a local image ID (sha256:...), which is content-addressed too. */
const DIGEST = /(@|^)sha256:[0-9a-f]{64}$/;

/** A refusal about the box, as an `HnError` so the command line exits with the refusal code instead of a crash. */
export class ContainerError extends HnError {}

export interface BoxLimits {
  readonly memory: string;
  readonly cpus: string;
  readonly pids: number;
}

export const DEFAULT_LIMITS: BoxLimits = { memory: '1g', cpus: '2', pids: 256 };

export interface BoxOptions {
  /** Must end in `@sha256:<64 hex>`. A tag can be moved, so it is refused. */
  readonly image: string;
  readonly sessionId: string;
  /** A host folder that holds a COPY of the project. It is mounted at /work and is the only mount. */
  readonly workDir: string;
  readonly limits?: Partial<BoxLimits>;
  /** Absolute path to the docker binary. Never looked up through PATH from the project. */
  readonly docker: string;
  /** The shell inside the image. Default `sh`, because a minimal image may not have bash. */
  readonly shell?: string;
  readonly user?: string;
}

export function assertPinned(image: string): void {
  if (!DIGEST.test(image)) {
    throw new ContainerError('IMAGE_NOT_PINNED', `The image must be pinned by digest (name@sha256:...). "${image}" can change under you.`);
  }
}

const SAFE_NAME = /^[A-Za-z0-9_.-]{1,64}$/;

/** Docker on Linux checks the copy's owner, so the box takes this account's ids there (never root); elsewhere, nobody. */
export function boxUser(platform: string = process.platform, uid = process.getuid?.(), gid = process.getgid?.()): string {
  return platform === 'linux' && uid !== undefined && gid !== undefined && uid !== 0 ? `${uid}:${gid}` : '65534:65534';
}

/** The arguments to `docker run`. Pure, so every flag is visible to a test. */
export function containerRunArgs(options: BoxOptions): string[] {
  assertPinned(options.image);
  if (!SAFE_NAME.test(options.sessionId)) throw new ContainerError('BAD_SESSION_ID', 'The session id is not safe to use in a container name.');
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const user = options.user ?? boxUser();
  const [uid, gid] = user.split(':');
  return [
    'run',
    '--detach',
    '--init',
    '--pull=never',
    '--name',
    `hn-${options.sessionId}`,
    '--label',
    `hn.session=${options.sessionId}`,
    '--network',
    'none',
    '--read-only',
    '--user',
    user,
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    String(limits.pids),
    '--memory',
    limits.memory,
    '--memory-swap',
    limits.memory,
    '--cpus',
    limits.cpus,
    '--ulimit',
    'nofile=1024:1024',
    // The only writable places besides the project copy: scratch space, not the image.
    '--tmpfs',
    '/tmp:rw,nosuid,size=256m',
    '--tmpfs',
    `/home/hn:rw,nosuid,size=128m,uid=${uid},gid=${gid}`,
    '--env',
    'HOME=/home/hn',
    '--workdir',
    '/work',
    '--mount',
    `type=bind,source=${options.workDir},target=/work`,
    '--entrypoint',
    options.shell ?? 'sh',
    options.image,
    '-c',
    'while :; do sleep 3600; done',
  ];
}

export interface RuntimeReport {
  readonly ok: boolean;
  /** One line per thing that is not as asked. Empty when `ok`. */
  readonly failures: readonly string[];
  readonly facts: {
    readonly networkMode: string;
    readonly readonlyRootfs: boolean;
    readonly user: string;
    readonly capDrop: readonly string[];
    readonly capAdd: readonly string[];
    readonly privileged: boolean;
    readonly securityOpt: readonly string[];
    readonly mounts: readonly string[];
  };
}

const asText = (value: unknown): string => (typeof value === 'string' ? value : '');
const asList = (value: unknown): string[] => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : []);
/**
 * Host paths that must never be the project copy: credential folders, the Docker socket, the filesystem
 * root, system folders and a bare home folder. A copy that merely lives somewhere under a home folder is fine.
 */
function isSensitiveMount(source: string): boolean {
  const path = source.replaceAll('\\', '/').toLowerCase().replace(/\/+$/, '') || '/';
  if (/(^|\/)(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.azure)(\/|$)/.test(path)) return true;
  if (path.includes('docker.sock') || path.includes('docker_engine')) return true;
  if (['/', '/etc', '/root', '/var', '/var/run', '/usr', '/bin', '/proc', '/sys', '/dev'].includes(path)) return true;
  return /^\/home\/[^/]+$/.test(path) || /^\/users\/[^/]+$/.test(path) || /^[a-z]:\/users\/[^/]+$/.test(path) || /^[a-z]:$/.test(path);
}

/**
 * Reads `docker inspect` output and says whether the box is what was asked for. Anything missing or
 * unexpected is a failure: a field Docker did not report is not assumed safe.
 */
export function verifyRuntime(inspect: unknown): RuntimeReport {
  const failures: string[] = [];
  const entry = (Array.isArray(inspect) ? inspect[0] : inspect) as Record<string, unknown> | undefined;
  const host = (entry?.['HostConfig'] ?? {}) as Record<string, unknown>;
  const config = (entry?.['Config'] ?? {}) as Record<string, unknown>;
  const mountList = Array.isArray(entry?.['Mounts']) ? (entry?.['Mounts'] as Record<string, unknown>[]) : [];

  const networkMode = asText(host['NetworkMode']);
  const readonlyRootfs = host['ReadonlyRootfs'] === true;
  const user = asText(config['User']);
  const capDrop = asList(host['CapDrop']);
  const capAdd = asList(host['CapAdd']);
  const privileged = host['Privileged'] === true;
  const securityOpt = asList(host['SecurityOpt']);
  const mounts = mountList.map((mount) => `${asText(mount['Source'])} -> ${asText(mount['Destination'])}`);

  if (entry === undefined) failures.push('docker inspect returned nothing.');
  if (networkMode !== 'none') failures.push(`The network is "${networkMode}", not "none".`);
  if (!readonlyRootfs) failures.push('The root filesystem is writable.');
  if (user === '' || user === '0' || user.startsWith('0:') || user === 'root' || user.startsWith('root:')) failures.push(`The box runs as "${user || 'root (default)'}", not an unprivileged user.`);
  if (!capDrop.map((cap) => cap.toUpperCase()).includes('ALL')) failures.push('Capabilities are not dropped (no --cap-drop ALL).');
  if (capAdd.length > 0) failures.push(`Capabilities were added: ${capAdd.join(', ')}.`);
  if (privileged) failures.push('The container is privileged.');
  if (!securityOpt.some((opt) => opt.startsWith('no-new-privileges'))) failures.push('no-new-privileges is not set.');
  if (!(Number(host['PidsLimit']) > 0)) failures.push('There is no process limit.');
  if (!(Number(host['Memory']) > 0)) failures.push('There is no memory limit.');
  if (!(Number(host['NanoCpus']) > 0) && !(Number(host['CpuQuota']) > 0)) failures.push('There is no CPU limit.');
  if (asText(host['PidMode']) !== '') failures.push(`The process namespace is shared (${asText(host['PidMode'])}).`);
  if (asText(host['IpcMode']) === 'host') failures.push('The IPC namespace is the host\'s.');
  if (asText(host['UsernsMode']) === 'host') failures.push('The user namespace is the host\'s.');
  if (asList(host['Devices']).length > 0 || (Array.isArray(host['Devices']) && host['Devices'].length > 0)) failures.push('Host devices are passed in.');
  if (mountList.length !== 1) failures.push(`Expected exactly one mount (the project copy), found ${mountList.length}.`);
  for (const mount of mountList) {
    const source = asText(mount['Source']);
    const destination = asText(mount['Destination']);
    if (isSensitiveMount(source)) failures.push(`A sensitive host path is mounted: ${source}.`);
    if (destination.includes('docker.sock') || source.includes('docker.sock')) failures.push('The Docker socket is mounted.');
    if (destination !== '/work') failures.push(`A mount other than /work: ${source} -> ${destination}.`);
  }

  return { ok: failures.length === 0, failures, facts: { networkMode, readonlyRootfs, user, capDrop, capAdd, privileged, securityOpt, mounts } };
}

interface Captured {
  readonly code: number | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
}

function docker(binary: string, args: readonly string[], timeoutMs = 60_000): Promise<Captured> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => out.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => err.push(chunk));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err) });
    });
  });
}

const MAX_CAPTURE = 64 * 1024 * 1024;
const GRACE_MS = 3_000;

/** A shell script that signals every process in the box carrying this command's marker. */
function markerKill(marker: string, signal: 'INT' | 'TERM' | 'KILL'): string {
  return `for p in /proc/[0-9]*; do if tr '\\0' '\\n' < $p/environ 2>/dev/null | grep -qx 'HN_EXEC=${marker}'; then kill -${signal} \${p#/proc/} 2>/dev/null; fi; done`;
}

export class ContainerBox {
  readonly #docker: string;
  readonly #shell: string;
  readonly id: string;
  readonly report: RuntimeReport;

  private constructor(dockerBinary: string, shell: string, id: string, report: RuntimeReport) {
    this.#docker = dockerBinary;
    this.#shell = shell;
    this.id = id;
    this.report = report;
  }

  /** Starts the box and reads its configuration back. A box that is not as asked is removed and refused. */
  static async start(options: BoxOptions): Promise<ContainerBox> {
    // A bare name could be satisfied by a `docker.exe` planted in the project, and Windows looks in the current folder first.
    if (!isAbsolute(options.docker)) throw new ContainerError('DOCKER_NOT_ABSOLUTE', `The docker program must be given as an absolute path, not "${options.docker}".`);
    const args = containerRunArgs(options);
    const started = await docker(options.docker, args);
    if (started.code !== 0) throw new ContainerError('START_FAILED', `The box did not start: ${started.stderr.toString('utf8').trim().slice(0, 400)}`);
    const id = started.stdout.toString('utf8').trim();
    const inspected = await docker(options.docker, ['inspect', id]);
    let report: RuntimeReport;
    try {
      report = verifyRuntime(JSON.parse(inspected.stdout.toString('utf8')));
    } catch {
      report = verifyRuntime(undefined);
    }
    if (!report.ok) {
      await docker(options.docker, ['rm', '-f', id]).catch(() => undefined);
      throw new ContainerError('NOT_AS_ASKED', `The box is not what was asked for, so it was removed:\n- ${report.failures.join('\n- ')}`);
    }
    return new ContainerBox(options.docker, options.shell ?? 'sh', id, report);
  }

  /** Runs a command inside the box, with the same result shape the local backend gives. */
  exec(command: string, options: ExecOptions): Promise<ExecResult> {
    return new Promise((resolve, reject) => {
      const inner = /^\/work(\/|$)/.test(options.cwd) ? options.cwd : '/work';
      // Every process this command starts inherits the marker, so only they are stopped if it must be.
      const marker = randomUUID();
      const child = spawn(this.#docker, ['exec', '--interactive', '--env', `HN_EXEC=${marker}`, '--workdir', inner, this.id, this.#shell, '-c', command], {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });
      child.stdin.on('error', () => undefined);
      child.stdin.end(options.input ?? '');
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      let size = 0;
      let clipped = false;
      let timedOut = false;
      let cancelled = false;
      const keep = (list: Buffer[]) => (chunk: Buffer) => {
        if (size >= MAX_CAPTURE) {
          clipped = true;
          return;
        }
        size += chunk.length;
        list.push(chunk);
      };
      child.stdout.on('data', keep(out));
      child.stderr.on('data', keep(err));

      /** Killing the client leaves its processes running in the box, so find and stop the ones that carry this command's marker. */
      let cleanup: Promise<unknown> = Promise.resolve();
      const stop = (): void => {
        child.kill();
        cleanup = docker(this.#docker, ['exec', this.id, this.#shell, '-c', markerKill(marker, 'KILL')], GRACE_MS).catch(() => undefined);
      };
      const timer = setTimeout(() => {
        timedOut = true;
        stop();
      }, options.timeoutMs);
      const onAbort = (): void => {
        cancelled = true;
        stop();
      };
      if (options.signal.aborted) onAbort();
      else options.signal.addEventListener('abort', onAbort, { once: true });

      child.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        options.signal.removeEventListener('abort', onAbort);
        // The result is only reported once the strays are gone, so the next command never races the cleanup.
        void cleanup.then(() => resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err), timedOut, cancelled, clipped }));
      });
    });
  }

  /**
   * A job or terminal in the box. Its environment is the box's own: nothing of the harness's is passed in
   * but the marker, so a job finds no socket, token or key that leads back to the harness.
   */
  startProcess(command: string, options: StartOptions): RunningProcess {
    const inner = /^\/work(\/|$)/.test(options.cwd) ? options.cwd : '/work';
    const marker = randomUUID();
    const flags = [...(options.input ? ['--interactive'] : []), '--env', `HN_EXEC=${marker}`, '--workdir', inner];
    const child = spawn(this.#docker, ['exec', ...flags, this.id, this.#shell, '-c', command], {
      stdio: [options.input ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    return wrapChild(child, (kind) => {
      const name = kind === 'interrupt' ? 'INT' : kind === 'terminate' ? 'TERM' : 'KILL';
      void docker(this.#docker, ['exec', this.id, this.#shell, '-c', markerKill(marker, name)], GRACE_MS).catch(() => undefined);
      if (kind === 'kill') child.kill();
    });
  }

  /** The configuration as Docker reports it now. */
  async inspect(): Promise<RuntimeReport> {
    const result = await docker(this.#docker, ['inspect', this.id]);
    try {
      return verifyRuntime(JSON.parse(result.stdout.toString('utf8')));
    } catch {
      return verifyRuntime(undefined);
    }
  }

  async stop(): Promise<void> {
    await docker(this.#docker, ['rm', '-f', this.id]).catch(() => undefined);
  }

  get bash(): BashOperations {
    return { exec: (command, options) => this.exec(command, options) };
  }
}

/** An absolute path to docker. A bare name could be satisfied by a `docker.exe` committed to the project. */
export async function findDocker(env: NodeJS.ProcessEnv = process.env): Promise<string | null> {
  const { access } = await import('node:fs/promises');
  const candidates =
    process.platform === 'win32'
      ? [env['HN_DOCKER_BIN'], `${env['ProgramFiles'] ?? 'C:/Program Files'}/Docker/Docker/resources/bin/docker.exe`]
      : [env['HN_DOCKER_BIN'], '/usr/bin/docker', '/usr/local/bin/docker', '/opt/homebrew/bin/docker'];
  for (const candidate of candidates) {
    if (candidate === undefined || candidate === '') continue;
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next place.
    }
  }
  return null;
}

/** Whether the Docker daemon answers. A missing or stopped daemon means no container tier. */
export async function dockerIsUp(binary: string): Promise<boolean> {
  try {
    return (await docker(binary, ['info', '--format', '{{.ServerVersion}}'], 15_000)).code === 0;
  } catch {
    return false;
  }
}

/** Boxes this program started that are still running, by name. After a crash these are what `hn doctor` reports. */
export async function strayBoxes(dockerBinary: string): Promise<string[]> {
  try {
    const result = await docker(dockerBinary, ['ps', '--filter', 'label=hn.session', '--format', '{{.Names}}'], 15_000);
    return result.code === 0 ? result.stdout.toString('utf8').split('\n').map((name) => name.trim()).filter((name) => name !== '') : [];
  } catch {
    return [];
  }
}

/** The container engine's version, or null if it cannot be read. */
export async function engineVersion(dockerBinary: string): Promise<string | null> {
  try {
    const result = await docker(dockerBinary, ['info', '--format', '{{.ServerVersion}}'], 15_000);
    return result.code === 0 ? result.stdout.toString('utf8').trim() : null;
  } catch {
    return null;
  }
}
