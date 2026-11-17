// Builds a signed, reproducible release. A developer tool, not part of hn.
//
//   node --disable-proto=throw scripts/release.ts --version 0.8.0 --key <ed25519 private key .pem> --key-id <id> --out <folder>
//   node --disable-proto=throw scripts/release.ts --keygen <folder>     (writes release-key.pem, which never enters the repo, and release-key.pub.pem)
//
// The tree: bin/hn.mjs (the launcher), bin/hn-sandbox[.exe], lib/node_modules/@hn/* (the TypeScript compiled to
// JavaScript, since Node will not strip types under node_modules), lib/node_modules/<every runtime dependency> copied
// from the lockfile's resolution, RELEASE-KEY.json (the public key that later updates must be signed with), the
// licence files and sbom.cdx.json. Times come from SOURCE_DATE_EPOCH, or the commit time, so two builds of one
// commit are byte-identical.

import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { gzipSync } from 'node:zlib';
import { MANIFEST_PATH, buildManifest, cycloneDx, manifestBytes, signManifest, writeTar, type SbomComponent, type TarFile } from '../packages/release/src/index.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const PRODUCT = 'haven-harness';
/** Workspace packages that are developer tools only and never ship. */
const DEV_ONLY = new Set(['testkit', 'evals']);

const toPosix = (path: string): string => path.split('\\').join('/');

async function walk(dir: string): Promise<string[]> {
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
const rewriteUrls = (text: string): string => text.replace(/(new URL\(\s*['`]\.{1,2}\/[^'`]*?)\.ts(['`])/g, '$1.js$2');

interface Vendored {
  readonly name: string;
  readonly version: string;
  readonly license?: string;
  readonly dir: string;
}

/**
 * Every third-party package the shipped workspace packages need at run time, following pnpm's resolution: a
 * package's own dependencies sit beside it in its store folder, `<store>/<id>/node_modules/<dep>`.
 */
async function thirdParty(packages: readonly string[]): Promise<Vendored[]> {
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

function launcher(): string {
  return [
    '#!/usr/bin/env node',
    '// Haven Harness launcher: every run gets --disable-proto=throw, which cannot be turned on after startup.',
    "import { spawnSync } from 'node:child_process';",
    "import { existsSync } from 'node:fs';",
    "import { fileURLToPath } from 'node:url';",
    '',
    "const main = fileURLToPath(new URL('../lib/node_modules/@hn/surfaces/src/main.js', import.meta.url));",
    "const helper = fileURLToPath(new URL(process.platform === 'win32' ? './hn-sandbox.exe' : './hn-sandbox', import.meta.url));",
    "const env = { ...process.env, ...(process.env.HN_SANDBOX_BIN === undefined && existsSync(helper) ? { HN_SANDBOX_BIN: helper } : {}), HN_RELEASE_ROOT: fileURLToPath(new URL('../', import.meta.url)) };",
    "const result = spawnSync(process.execPath, ['--disable-proto=throw', '--no-warnings', main, ...process.argv.slice(2)], { stdio: 'inherit', env });",
    'process.exit(result.status ?? 1);',
    '',
  ].join('\n');
}

async function build(options: { version: string; key: string; keyId: string; out: string; epoch: number }): Promise<string> {
  const created = new Date(options.epoch * 1000).toISOString();
  const shipped = (await readdir(join(ROOT, 'packages'))).filter((name) => !DEV_ONLY.has(name)).sort();
  const emit = await mkdtemp(join(tmpdir(), 'hn-release-emit-'));
  const files: TarFile[] = [];
  try {
    const tsc = spawnSync(process.execPath, [join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(ROOT, 'tsconfig.json'), '--noEmit', 'false', '--outDir', emit, '--rootDir', join(ROOT, 'packages'), '--rewriteRelativeImportExtensions', '--declaration', 'false', '--sourceMap', 'false', '--newLine', 'lf'], { cwd: ROOT, encoding: 'utf8' });
    if (tsc.status !== 0) throw new Error(`The TypeScript build failed:\n${tsc.stdout}${tsc.stderr}`);
    for (const name of shipped) {
      const pkg = JSON.parse(await readFile(join(ROOT, 'packages', name, 'package.json'), 'utf8')) as { name: string; dependencies?: Record<string, string> };
      const base = `lib/node_modules/${pkg.name}`;
      const manifest = { name: pkg.name, version: options.version, private: true, license: 'Apache-2.0', type: 'module', exports: './src/index.js', ...(pkg.dependencies === undefined ? {} : { dependencies: Object.fromEntries(Object.entries(pkg.dependencies).map(([dep, spec]) => [dep, spec.startsWith('workspace:') ? options.version : spec])) }) };
      files.push({ path: `${base}/package.json`, data: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) });
      for (const file of await walk(join(emit, name, 'src'))) files.push({ path: `${base}/src/${toPosix(relative(join(emit, name, 'src'), file))}`, data: Buffer.from(rewriteUrls(await readFile(file, 'utf8'))) });
      for (const file of await walk(join(ROOT, 'packages', name, 'src'))) {
        if (file.endsWith('.mjs')) files.push({ path: `${base}/src/${toPosix(relative(join(ROOT, 'packages', name, 'src'), file))}`, data: await readFile(file) });
      }
    }
  } finally {
    await rm(emit, { recursive: true, force: true });
  }
  const components: SbomComponent[] = [];
  for (const dep of await thirdParty(shipped)) {
    const hash = createHash('sha256');
    for (const file of await walk(dep.dir)) {
      const path = `lib/node_modules/${dep.name}/${toPosix(relative(dep.dir, file))}`;
      const data = await readFile(file);
      hash.update(path).update(data);
      files.push({ path, data, executable: process.platform !== 'win32' && ((await stat(file)).mode & 0o111) !== 0 });
    }
    components.push({ name: dep.name, version: dep.version, hash: hash.digest('hex'), ...(dep.license === undefined ? {} : { license: dep.license }) });
  }
  const helperName = process.platform === 'win32' ? 'hn-sandbox.exe' : 'hn-sandbox';
  const helper = join(ROOT, 'native', 'hn-sandbox', 'target', 'release', helperName);
  if (!existsSync(helper)) throw new Error(`Build the helper first: pnpm build:sandbox (${helper} is missing).`);
  files.push({ path: `bin/${helperName}`, data: await readFile(helper), executable: true });
  files.push({ path: 'bin/hn.mjs', data: Buffer.from(launcher()), executable: true });
  for (const name of ['LICENSE', 'NOTICE', 'README.md']) if (existsSync(join(ROOT, name))) files.push({ path: name, data: await readFile(join(ROOT, name)) });
  const privateKey = createPrivateKey(await readFile(options.key));
  const publicPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  files.push({ path: 'RELEASE-KEY.json', data: Buffer.from(`${JSON.stringify({ [options.keyId]: publicPem }, null, 2)}\n`) });
  const sbom = Buffer.from(`${JSON.stringify(cycloneDx({ name: PRODUCT, version: options.version, created }, components), null, 2)}\n`);
  files.push({ path: 'sbom.cdx.json', data: sbom });
  const platform = `${process.platform}-${process.arch}`;
  const manifest = buildManifest(files, { name: PRODUCT, version: options.version, platform, created });
  const archive = gzipSync(writeTar([...files, { path: MANIFEST_PATH, data: manifestBytes(manifest) }]), { level: 9 });
  await mkdir(options.out, { recursive: true });
  const stem = join(options.out, `${PRODUCT}-${options.version}-${platform}`);
  await writeFile(`${stem}.tgz`, archive);
  await writeFile(`${stem}.sig.json`, `${JSON.stringify(signManifest(manifest, options.keyId, privateKey), null, 2)}\n`);
  await writeFile(`${stem}.sbom.cdx.json`, sbom);
  return `${stem}.tgz`;
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { version: { type: 'string' }, key: { type: 'string' }, 'key-id': { type: 'string' }, out: { type: 'string' }, keygen: { type: 'string' } } });
  if (values.keygen !== undefined) {
    const pair = generateKeyPairSync('ed25519');
    await mkdir(values.keygen, { recursive: true });
    await writeFile(join(values.keygen, 'release-key.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    await writeFile(join(values.keygen, 'release-key.pub.pem'), pair.publicKey.export({ type: 'spki', format: 'pem' }), { flag: 'wx' });
    process.stdout.write(`Wrote ${join(values.keygen, 'release-key.pem')} (keep it offline; never commit it) and release-key.pub.pem.\n`);
    return;
  }
  if (values.version === undefined || values.key === undefined || values['key-id'] === undefined || values.out === undefined) throw new Error('release.ts --version <x.y.z> --key <private .pem> --key-id <id> --out <folder>');
  const epochText = process.env['SOURCE_DATE_EPOCH'] ?? spawnSync('git', ['log', '-1', '--format=%ct'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim();
  const epoch = Number(epochText);
  if (!Number.isInteger(epoch) || epoch <= 0) throw new Error('No SOURCE_DATE_EPOCH and no commit time.');
  process.stdout.write(`${await build({ version: values.version, key: values.key, keyId: values['key-id'], out: values.out, epoch })}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
