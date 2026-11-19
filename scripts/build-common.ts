// Shared by the release builders (the per-platform release and the npm package): the compiled workspace,
// the vendored third-party closure, and the file walker. Developer tools only; never shipped.
import { spawnSync } from 'node:child_process';
import { realpath, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { stat } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { checkNpmIntegrity, readTar, type SbomComponent, type TarFile } from '../packages/release/src/index.ts';

export const ROOT = fileURLToPath(new URL('../', import.meta.url));
const PRODUCT = 'haven-harness';
/** Workspace packages that are developer tools only and never ship. */
export const DEV_ONLY = new Set(['testkit', 'evals']);

export const toPosix = (path: string): string => path.split('\\').join('/');

export async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      out.push(...(await walk(full)));
    } else if (entry.isFile()) out.push(full);
  }
  return out.sort();
}

/** Points a runtime file reference at the compiled file: `new URL('./x.ts', ...)` becomes `./x.js`. */
export const rewriteUrls = (text: string): string => text.replace(/(new URL\(\s*['`]\.{1,2}\/[^'`]*?)\.ts(['`])/g, '$1.js$2');

export interface Vendored {
  readonly name: string;
  readonly version: string;
  readonly license?: string;
  readonly dir: string;
}

/**
 * Every third-party package the shipped workspace packages need at run time, following pnpm's resolution: a
 * package's own dependencies sit beside it in its store folder, `<store>/<id>/node_modules/<dep>`.
 */
export async function thirdParty(packages: readonly string[]): Promise<Vendored[]> {
  const found = new Map<string, Vendored>();
  const visit = async (dir: string): Promise<void> => {
    const pkg = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8')) as { name: string; version: string; license?: string; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> };
    const seen = found.get(pkg.name);
    if (seen !== undefined) {
      if (seen.version !== pkg.version) throw new Error(`Two versions of ${pkg.name} are needed (${seen.version} and ${pkg.version}); the flat layout cannot hold both.`);
      return;
    }
    found.set(pkg.name, { name: pkg.name, version: pkg.version, ...(typeof pkg.license === 'string' ? { license: pkg.license } : {}), dir });
    const store = pkg.name.startsWith('@') ? join(dir, '..', '..') : join(dir, '..');
    for (const dep of Object.keys(pkg.dependencies ?? {})) await visit(await realpath(join(store, dep)));
    // Optional dependencies carry the platform's native parts (ripgrep's binary): the one installed here ships.
    for (const dep of Object.keys(pkg.optionalDependencies ?? {})) {
      const found = await realpath(join(store, dep)).catch(() => null);
      if (found !== null) await visit(found);
    }
  };
  for (const name of packages) {
    const pkg = JSON.parse(await readFile(join(ROOT, 'packages', name, 'package.json'), 'utf8')) as { dependencies?: Record<string, string> };
    for (const [dep, spec] of Object.entries(pkg.dependencies ?? {})) if (!spec.startsWith('workspace:')) await visit(await realpath(join(ROOT, 'packages', name, 'node_modules', dep)));
  }
  return [...found.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
}


/** The shipped workspace packages, compiled to JavaScript with the repository's own tsc, under `<prefix>/@hn/<name>`. */
export async function compileWorkspace(version: string, prefix: string): Promise<{ files: TarFile[]; shipped: string[] }> {
  const shipped = (await readdir(join(ROOT, 'packages'))).filter((name) => !DEV_ONLY.has(name)).sort();
  const emit = await mkdtemp(join(tmpdir(), 'hn-release-emit-'));
  const files: TarFile[] = [];
  try {
    const tsc = spawnSync(process.execPath, [join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(ROOT, 'tsconfig.json'), '--noEmit', 'false', '--outDir', emit, '--rootDir', join(ROOT, 'packages'), '--rewriteRelativeImportExtensions', '--declaration', 'false', '--sourceMap', 'false', '--newLine', 'lf'], { cwd: ROOT, encoding: 'utf8' });
    if (tsc.status !== 0) throw new Error(`The TypeScript build failed:
${tsc.stdout}${tsc.stderr}`);
    for (const name of shipped) {
      const pkg = JSON.parse(await readFile(join(ROOT, 'packages', name, 'package.json'), 'utf8')) as { name: string; dependencies?: Record<string, string> };
      const base = `${prefix}/${pkg.name}`;
      const manifest = { name: pkg.name, version, private: true, license: 'Apache-2.0', type: 'module', exports: './src/index.js', ...(pkg.dependencies === undefined ? {} : { dependencies: Object.fromEntries(Object.entries(pkg.dependencies).map(([dep, spec]) => [dep, spec.startsWith('workspace:') ? version : spec])) }) };
      files.push({ path: `${base}/package.json`, data: Buffer.from(`${JSON.stringify(manifest, null, 2)}
`) });
      for (const file of await walk(join(emit, name, 'src'))) files.push({ path: `${base}/src/${toPosix(relative(join(emit, name, 'src'), file))}`, data: Buffer.from(rewriteUrls(await readFile(file, 'utf8'))) });
      for (const file of await walk(join(ROOT, 'packages', name, 'src'))) {
        if (file.endsWith('.mjs')) files.push({ path: `${base}/src/${toPosix(relative(join(ROOT, 'packages', name, 'src'), file))}`, data: await readFile(file) });
      }
    }
  } finally {
    await rm(emit, { recursive: true, force: true });
  }
  return { files, shipped };
}

/** Every third-party package the shipped packages need, copied under `<prefix>/<name>`, with an SBOM entry each. */
export async function vendorClosure(shipped: readonly string[], prefix: string, skip: (name: string) => boolean = () => false): Promise<{ files: TarFile[]; components: SbomComponent[]; vendored: Vendored[] }> {
  const files: TarFile[] = [];
  const components: SbomComponent[] = [];
  const vendored = (await thirdParty(shipped)).filter((dep) => !skip(dep.name));
  for (const dep of vendored) {
    const hash = createHash('sha256');
    for (const file of await walk(dep.dir)) {
      const path = `${prefix}/${dep.name}/${toPosix(relative(dep.dir, file))}`;
      const data = await readFile(file);
      hash.update(path).update(data);
      files.push({ path, data, executable: process.platform !== 'win32' && ((await stat(file)).mode & 0o111) !== 0 });
    }
    components.push({ name: dep.name, version: dep.version, hash: hash.digest('hex'), ...(dep.license === undefined ? {} : { license: dep.license }) });
  }
  return { files, components, vendored };
}

/** The platforms hn ships for (the same six the sandbox helper is built for), as ripgrep names them. */
export const RIPGREP_PLATFORMS = ['win32-x64', 'win32-arm64', 'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'] as const;

/**
 * ripgrep's platform packages for those six, fetched from the registry and checked against the sha512 the lockfile
 * pins, so the binaries that ship are exactly the ones this repository resolved. npm will not fetch the optional
 * dependencies of a bundled package, which is why they are carried in the package rather than resolved at install.
 */
export async function ripgrepPlatforms(version: string, prefix: string): Promise<{ files: TarFile[]; names: string[] }> {
  const lock = await readFile(join(ROOT, 'pnpm-lock.yaml'), 'utf8');
  const files: TarFile[] = [];
  const names: string[] = [];
  for (const platform of RIPGREP_PLATFORMS) {
    const name = `@vscode/ripgrep-${platform}`;
    const at = lock.indexOf(`'${name}@${version}':`);
    const entry = at < 0 ? null : /integrity: (sha512-[A-Za-z0-9+/=]+)/.exec(lock.slice(at, at + 400));
    if (entry === null) throw new Error(`${name}@${version} is not pinned in pnpm-lock.yaml.`);
    const response = await fetch(`https://registry.npmjs.org/${name}/-/ripgrep-${platform}-${version}.tgz`, { signal: AbortSignal.timeout(120_000) });
    if (!response.ok) throw new Error(`Fetching ${name}@${version} answered ${response.status}.`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (!checkNpmIntegrity(bytes, entry[1] as string)) throw new Error(`${name}@${version} does not match the hash pinned in pnpm-lock.yaml.`);
    for (const file of readTar(gunzipSync(bytes))) {
      if (!file.path.startsWith('package/')) throw new Error(`${name} holds ${file.path}, outside package/.`);
      files.push({ path: `${prefix}/${name}/${file.path.slice('package/'.length)}`, data: file.data, executable: file.path.includes('/bin/') });
    }
    names.push(name);
  }
  return { files, names };
}
