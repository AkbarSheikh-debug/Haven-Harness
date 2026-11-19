import { execFile } from 'node:child_process';
import { copyFile, lstat, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertPinned } from './container.ts';

/**
 * `hn prepare` (decision 10): installs a project's dependencies without letting the install reach anything. Only the
 * manifests and lockfiles go in (never `.npmrc`, which can hold tokens or point at another registry). Installs run with
 * scripts off, on an `--internal` Docker network whose only other member is the harness's package proxy, which reads
 * from two fixed registries and nothing else. Packages that want install scripts are listed; running them needs a
 * person and happens in a separate step with no network at all.
 */

export type Manager = 'npm' | 'pnpm' | 'yarn' | 'pip';

/** Files that describe dependencies. Nothing else of the project is copied in. */
export const MANIFESTS: Readonly<Record<Manager, readonly string[]>> = {
  npm: ['package.json', 'package-lock.json'],
  pnpm: ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml'],
  yarn: ['package.json', 'yarn.lock'],
  pip: ['requirements.txt', 'requirements-dev.txt', 'pyproject.toml'],
};

const LOCKFILES: readonly [string, Manager][] = [['pnpm-lock.yaml', 'pnpm'], ['package-lock.json', 'npm'], ['yarn.lock', 'yarn'], ['requirements.txt', 'pip']];

const isPlainFile = async (path: string): Promise<boolean> => {
  const info = await lstat(path).catch(() => null);
  return info !== null && info.isFile() && !info.isSymbolicLink() && info.nlink === 1;
};

export async function detectManager(root: string): Promise<Manager | null> {
  for (const [file, manager] of LOCKFILES) if (await isPlainFile(join(root, file))) return manager;
  return null;
}

/** Copies the manifests and lockfiles alone into `out`. Links and hard links are refused. */
export async function copyManifests(root: string, manager: Manager, out: string): Promise<string[]> {
  await mkdir(out, { recursive: true });
  const copied: string[] = [];
  for (const file of MANIFESTS[manager]) {
    if (!(await isPlainFile(join(root, file)))) continue;
    await copyFile(join(root, file), join(out, file));
    copied.push(file);
  }
  return copied;
}

/** The install command, scripts off, pointed at the proxy. pip takes wheels only, so no package's setup code runs. */
export function installCommand(manager: Manager, proxy: string): string[] {
  switch (manager) {
    case 'npm':
      return ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', `--registry=${proxy}/npm/`];
    case 'pnpm':
      return ['pnpm', 'install', '--frozen-lockfile', '--ignore-scripts', `--registry=${proxy}/npm/`];
    case 'yarn':
      return ['yarn', 'install', '--frozen-lockfile', '--ignore-scripts', '--non-interactive', `--registry=${proxy}/npm/`];
    case 'pip':
      return ['pip', 'install', '--only-binary=:all:', '--no-cache-dir', '--target', '/work/.deps', '--index-url', `${proxy}/pypi/simple/`, '-r', 'requirements.txt'];
  }
}

/** Packages whose install would run their own scripts, from the lockfile. Running those needs a person. */
export async function scriptPackages(root: string, manager: Manager): Promise<string[]> {
  if (manager === 'npm') {
    const lock = await readFile(join(root, 'package-lock.json'), 'utf8').then((text) => JSON.parse(text) as { packages?: Record<string, { hasInstallScript?: boolean }> }, () => null);
    return Object.entries(lock?.packages ?? {})
      .filter(([, entry]) => entry.hasInstallScript === true)
      .map(([path]) => path.replace(/^.*node_modules\//, ''))
      .sort();
  }
  if (manager === 'pnpm') {
    const text = await readFile(join(root, 'pnpm-lock.yaml'), 'utf8').catch(() => '');
    const found: string[] = [];
    let current = '';
    for (const line of text.split(/\r?\n/)) {
      const key = /^ {2}'?\/?([^\s':]+(?:@[^\s':]+)?)'?:\s*$/.exec(line);
      if (key !== null) current = key[1] as string;
      if (/^\s+requiresBuild: true/.test(line) && current !== '') found.push(current);
    }
    return [...new Set(found)].sort();
  }
  return [];
}

/** The proxy script, mounted read-only into the proxy container. */
export const REGISTRY_PROXY_PATH = fileURLToPath(new URL('./registry-proxy.mjs', import.meta.url));

export interface PreparePlanInput {
  readonly id: string;
  readonly manager: Manager;
  /** The folder holding only the copied manifests; the install writes its output here. */
  readonly workDir: string;
  /** Pinned images: one with Node for the proxy, one with the package manager for the install. */
  readonly proxyImage: string;
  readonly installImage: string;
  /** True only when a person approved running install scripts, after seeing the list. */
  readonly runScripts: boolean;
}

export interface DockerStep {
  readonly why: string;
  readonly args: readonly string[];
}

const HARDENED = ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '512', '--memory', '2g'];

/** Every docker command `prepare` runs, in order. Pure, so each flag is visible to a test. */
export function preparePlan(input: PreparePlanInput): DockerStep[] {
  assertPinned(input.proxyImage);
  assertPinned(input.installImage);
  if (!/^[a-z0-9]{6,32}$/.test(input.id)) throw new Error('A prepare id is 6 to 32 lowercase letters or digits.');
  const network = `hn-prep-${input.id}`;
  const proxy = `hn-prep-proxy-${input.id}`;
  const base = `http://${proxy}:8080`;
  const steps: DockerStep[] = [
    { why: 'a network with no route out: no gateway, no host, no engine', args: ['network', 'create', '--internal', network] },
    {
      why: 'the package proxy, the only member that can reach the internet, and only two registries through it',
      args: ['run', '-d', '--rm', '--name', proxy, ...HARDENED, '--network', 'bridge', '-v', `${REGISTRY_PROXY_PATH}:/proxy/registry-proxy.mjs:ro`, '-e', `HN_PROXY_PUBLIC=${base}`, '-e', 'HN_PROXY_PORT=8080', input.proxyImage, 'node', '/proxy/registry-proxy.mjs'],
    },
    { why: 'the proxy joins the closed network', args: ['network', 'connect', network, proxy] },
    {
      why: 'the install: manifests only, scripts off, on the closed network',
      args: ['run', '--rm', ...HARDENED, '--tmpfs', '/tmp', '--network', network, '--user', '1000:1000', '-e', 'HOME=/tmp', '-v', `${input.workDir}:/work`, '-w', '/work', input.installImage, ...installCommand(input.manager, base)],
    },
  ];
  if (input.runScripts && input.manager !== 'pip') {
    steps.push({
      why: 'install scripts a person approved, with no network at all',
      args: ['run', '--rm', ...HARDENED, '--tmpfs', '/tmp', '--network', 'none', '--user', '1000:1000', '-e', 'HOME=/tmp', '-v', `${input.workDir}:/work`, '-w', '/work', input.installImage, input.manager, 'rebuild'],
    });
  }
  steps.push({ why: 'stop the proxy', args: ['stop', proxy] }, { why: 'remove the closed network', args: ['network', 'rm', network] });
  return steps;
}

/** Runs one docker step with a small fixed environment. */
export function runDockerStep(docker: string, step: DockerStep): Promise<{ code: number; output: string }> {
  const env: NodeJS.ProcessEnv = {};
  for (const name of ['PATH', 'Path', 'SystemRoot', 'USERPROFILE', 'HOME', 'TEMP', 'TMP', 'ProgramData', 'APPDATA', 'LOCALAPPDATA']) if (process.env[name] !== undefined) env[name] = process.env[name];
  return new Promise((resolve) => {
    execFile(docker, [...step.args], { env, maxBuffer: 16 * 1024 * 1024, windowsHide: true, timeout: 30 * 60 * 1000 }, (error, stdout, stderr) => {
      resolve({ code: error === null ? 0 : typeof error.code === 'number' ? error.code : 1, output: `${stdout}${stderr}` });
    });
  });
}

/** The oldest Docker Desktop allowed: 4.44.3 fixed CVE-2025-9074, where a container could reach the engine API. */
export const MIN_DOCKER_DESKTOP = [4, 44, 3] as const;

/** Why a Docker Desktop platform name (`Docker Desktop 4.44.3 (202357)`) is too old, or null. Docker Engine without Desktop is not affected. */
export function dockerDesktopProblem(platformName: string): string | null {
  const match = /Docker Desktop (\d+)\.(\d+)\.(\d+)/.exec(platformName);
  if (match === null) return null;
  const version = [Number(match[1]), Number(match[2]), Number(match[3])];
  for (let i = 0; i < 3; i += 1) {
    if ((version[i] as number) > (MIN_DOCKER_DESKTOP[i] as number)) return null;
    if ((version[i] as number) < (MIN_DOCKER_DESKTOP[i] as number)) return `Docker Desktop ${version.join('.')} is older than ${MIN_DOCKER_DESKTOP.join('.')}, which fixed CVE-2025-9074 (a container could reach the engine API). Update Docker Desktop.`;
  }
  return null;
}

/** The engine's platform name, such as `Docker Desktop 4.44.3 (202357)`, or null when the engine is not running. */
export function dockerPlatformName(docker: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(docker, ['version', '--format', '{{.Server.Platform.Name}}'], { windowsHide: true, timeout: 15_000 }, (error, stdout) => resolve(error === null ? stdout.trim() : null));
  });
}
