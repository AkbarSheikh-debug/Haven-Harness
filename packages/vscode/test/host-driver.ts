import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lastContent, startFakeOpenAI, withTempDir } from '@hn/testkit';

/**
 * Drives a REAL VS Code: its extension host, diff editor and workspace trust, with a real `hn acp` process behind the
 * extension and a fake model. A VS Code must be on this machine: HN_VSCODE names its executable, or it is found in the
 * usual place. Without one the tests are skipped with that reason, and fail instead when HN_REQUIRE_VSCODE=1 (CI).
 */

const here = (path: string): string => fileURLToPath(new URL(path, import.meta.url));
export const launcher = here('../../surfaces/bin/hn.mjs');
export const hostDir = here('./host');

export function findVsCode(): string | null {
  const candidates = [
    process.env['HN_VSCODE'],
    process.env['LOCALAPPDATA'] === undefined ? undefined : join(process.env['LOCALAPPDATA'], 'Programs', 'Microsoft VS Code', 'Code.exe'),
    '/Applications/Visual Studio Code.app/Contents/MacOS/Code',
    '/Applications/Visual Studio Code.app/Contents/MacOS/Electron',
    '/usr/share/code/code',
  ];
  return candidates.find((path): path is string => path !== undefined && path !== '' && existsSync(path)) ?? null;
}

export const vscodeExe = findVsCode();
export const requireVsCode = process.env['HN_REQUIRE_VSCODE'] === '1';
export const skipWithoutVsCode: string | false = vscodeExe === null && !requireVsCode ? 'No VS Code found. Set HN_VSCODE to its executable (CI sets HN_REQUIRE_VSCODE=1 to make this a failure).' : false;

/** VS Code's own command line, which is its Electron binary running cli.js as plain Node (what bin/code does). */
export async function findCli(exe: string): Promise<string> {
  const base = dirname(exe);
  const candidates = [join(base, 'resources', 'app', 'out', 'cli.js'), join(base, '..', 'Resources', 'app', 'out', 'cli.js')];
  for (const entry of await readdir(base).catch(() => [] as string[])) candidates.push(join(base, entry, 'resources', 'app', 'out', 'cli.js'));
  const found = candidates.find((path) => existsSync(path));
  if (found === undefined) throw new Error(`Could not find VS Code's cli.js next to ${exe}.`);
  return found;
}

/** Runs VS Code's command line (for example --install-extension) and returns what it printed. */
export function runCli(exe: string, cli: string, args: readonly string[], timeoutMs = 180_000): { status: number | null; output: string } {
  const env: NodeJS.ProcessEnv = { ...process.env, ELECTRON_RUN_AS_NODE: '1' };
  const run = spawnSync(exe, [cli, ...args], { env, encoding: 'utf8', timeout: timeoutMs });
  return { status: run.status, output: `${run.stdout}${run.stderr}` };
}

const repoRoot = here('../../../');

/** Runs one of the repository's developer scripts as its own process, the way a person would, and returns what it printed. */
function script(name: string, args: readonly string[] = []): string {
  const ran = spawnSync(process.execPath, ['--disable-proto=throw', join(repoRoot, 'scripts', name), ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (ran.status !== 0) throw new Error(`scripts/${name} failed:\n${ran.stdout}${ran.stderr}`);
  return ran.stdout;
}

/** Compiles the extension (scripts/build-vscode.ts). */
export function buildExtension(): void {
  script('build-vscode.ts');
}

export interface Packed {
  readonly path: string;
  readonly sha256: string;
  readonly files: readonly string[];
}

/** Packs the extension (scripts/pack-vsix.ts) and reads back what it printed: the file, its hash, and the files in it. */
export function packVsix(version: string, out: string): Packed {
  const lines = script('pack-vsix.ts', ['--version', version, '--out', out]).split('\n').map((line) => line.trim()).filter(Boolean);
  const [path = '', hash = '', ...files] = lines;
  return { path, sha256: hash.replace(/^sha256 /, ''), files };
}

export const toolResults =(request: { messages: readonly { role: string; content?: unknown }[] }): string[] => {
  const lastUser = request.messages.map((message) => message.role).lastIndexOf('user');
  return request.messages.slice(lastUser + 1).filter((message) => message.role === 'tool').map((message) => String(message.content));
};

export interface HostRun {
  readonly suite: string;
  /** False leaves VS Code's workspace trust switched on, so the folder is not trusted. */
  readonly trusted: boolean;
  /** An extensions folder with the extension installed in it. Without one, extensions are disabled. */
  readonly extensionsDir?: string;
  /** Written into the suite's config. */
  readonly extra?: Record<string, unknown>;
}

export async function runHost(options: HostRun, modelUrl: string, top: string, project: string): Promise<{ ok: boolean; error?: string; output: string }> {
  const exe = vscodeExe as string;
  const config = join(top, 'config.json');
  const result = join(top, 'result.json');
  await rm(result, { force: true });
  await writeFile(config, JSON.stringify({ node: process.execPath, launcher, modelUrl, home: join(top, 'hn-home'), ...options.extra }));
  const env: NodeJS.ProcessEnv = { ...process.env, HN_HOST_CONFIG: config, HN_HOST_RESULT: result, HN_HOST_SUITE: options.suite };
  // Set by the editor that hosts a shell like this one; it turns the editor's own executable into plain Node.
  delete env['ELECTRON_RUN_AS_NODE'];
  const flags = [
    project,
    `--extensionDevelopmentPath=${join(hostDir, 'ext')}`,
    `--extensionTestsPath=${join(hostDir, 'run.cjs')}`,
    `--user-data-dir=${join(top, 'user-data')}`,
    `--extensions-dir=${options.extensionsDir ?? join(top, 'extensions')}`,
    ...(options.extensionsDir === undefined ? ['--disable-extensions'] : []),
    '--skip-welcome',
    '--skip-release-notes',
    ...(options.trusted ? ['--disable-workspace-trust'] : []),
    ...(process.platform === 'linux' ? ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'] : []),
  ];
  // A Linux machine with no display (CI) needs a virtual one.
  const virtual = process.platform === 'linux' && (process.env['DISPLAY'] ?? '') === '' && spawnSync('which', ['xvfb-run']).status === 0;
  const child = spawn(virtual ? 'xvfb-run' : exe, virtual ? ['-a', exe, ...flags] : flags, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
  child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString()));
  const timer = setTimeout(() => child.kill(), 240_000);
  await new Promise((resolve) => child.once('close', resolve));
  clearTimeout(timer);
  try {
    return { ...(JSON.parse(await readFile(result, 'utf8')) as { ok: boolean; error?: string }), output };
  } catch {
    return { ok: false, error: 'The suite wrote no result: VS Code did not get as far as running it.', output };
  }
}

/** A temporary project and a fake model that answers the prompts the suites use. */
export async function withProject(use: (top: string, project: string, modelUrl: string, requests: () => number) => Promise<void>): Promise<void> {
  const model = await startFakeOpenAI(async (request) => {
    const prompt = lastContent(request, 'user');
    const results = toolResults(request);
    if (prompt.startsWith('EDIT ')) {
      const name = prompt.slice(5).trim();
      if (results.length === 0) return { calls: [{ id: 'r1', name: 'read_file', args: { path: name } }] };
      if (results.length === 1) return { calls: [{ id: 'e1', name: 'edit_file', args: { path: name, old_string: 'beta', new_string: 'gamma' } }] };
      return { text: 'edited' };
    }
    if (prompt.startsWith('SLOW')) {
      await new Promise((resolve) => setTimeout(resolve, 20_000));
      return { text: 'too late' };
    }
    return { text: 'hello from hn' };
  });
  try {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const project = join(top, 'project');
      await mkdir(project);
      try {
        await use(top, project, model.url, () => model.requests.length);
      } finally {
        await rm(join(top, 'user-data'), { recursive: true, force: true }).catch(() => undefined);
      }
    });
  } finally {
    await model.close();
  }
}
