// Builds the npm package (Phase 9, decisions 1 and 7). A developer tool, not part of hn.
//
//   node --disable-proto=throw scripts/pack-npm.ts --version 0.9.0 --key <ed25519 private key .pem> --key-id <id> --out <folder>
//
// The package carries no scripts and no compiler need: the workspace compiled to JavaScript and every pure-JavaScript
// dependency are bundled under node_modules (bundleDependencies), ripgrep's binaries for the six supported
// platforms are bundled too, each checked against the lockfile's hash, and the native sandbox helper is not in it at all (it is fetched and verified on
// first use). The tarball is written by the same deterministic writer as the release archive, so two builds of one
// commit are byte-identical, and its files are listed in a manifest signed with the release key (manifest.sig.json).

import { spawnSync } from 'node:child_process';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { gzipSync } from 'node:zlib';
import { MANIFEST_PATH, SIGNATURE_PATH, buildManifest, cycloneDx, manifestBytes, signManifest, writeTar, type TarFile } from '../packages/release/src/index.ts';
import { ROOT, compileWorkspace, ripgrepPlatforms, trustFiles, vendorClosure } from './build-common.ts';

const PRODUCT = 'haven-harness';
const REPO = 'https://github.com/AkbarSheikh-debug/Haven-Harness';

function launcher(): string {
  return [
    '#!/usr/bin/env node',
    '// Haven Harness launcher: every run gets --disable-proto=throw, which cannot be turned on after startup.',
    "import { spawnSync } from 'node:child_process';",
    "import { fileURLToPath } from 'node:url';",
    '',
    "const main = fileURLToPath(new URL('../node_modules/@hn/surfaces/src/main.js', import.meta.url));",
    "const env = { ...process.env, HN_RELEASE_ROOT: fileURLToPath(new URL('../', import.meta.url)) };",
    "const result = spawnSync(process.execPath, ['--disable-proto=throw', '--no-warnings', main, ...process.argv.slice(2)], { stdio: 'inherit', env });",
    'process.exit(result.status ?? 1);',
    '',
  ].join('\n');
}

export async function packNpm(options: { version: string; key: string; keyId: string; out: string; epoch: number; root?: string; rootId?: string; roster?: string }): Promise<string> {
  const created = new Date(options.epoch * 1000).toISOString();
  const { files, shipped } = await compileWorkspace(options.version, 'node_modules');
  // npm does not fetch the optional dependencies of a bundled package (found by installing the packed tarball with
  // npm), and ripgrep's binary is per machine, so the six platform packages are carried in the package, each checked
  // against the hash the lockfile pins. A platform outside those six has no helper either, so it is unsupported.
  const vendor = await vendorClosure(shipped, 'node_modules', (name) => name.startsWith('@vscode/ripgrep-'));
  files.push(...vendor.files);
  const ripgrepVersion = vendor.vendored.find((dep) => dep.name === '@vscode/ripgrep')?.version;
  if (ripgrepVersion === undefined) throw new Error('@vscode/ripgrep is not a dependency any more; revisit how the package gets its search tool.');
  const platforms = await ripgrepPlatforms(ripgrepVersion, 'node_modules');
  files.push(...platforms.files);
  const dependencies: Record<string, string> = {};
  for (const name of shipped) dependencies[`@hn/${name}`] = options.version;
  for (const dep of vendor.vendored) dependencies[dep.name] = dep.version;
  const sorted = (record: Record<string, string>): Record<string, string> => Object.fromEntries(Object.entries(record).sort(([a], [b]) => (a < b ? -1 : 1)));
  const optional = Object.fromEntries(platforms.names.map((name) => [name, ripgrepVersion]));
  const packageJson = {
    name: PRODUCT,
    version: options.version,
    description: 'Haven Harness: an open-source coding agent that is powerful and provably contained.',
    license: 'Apache-2.0',
    type: 'module',
    bin: { hn: 'bin/hn.mjs', [PRODUCT]: 'bin/hn.mjs' },
    engines: { node: '>=24.14.0' },
    keywords: ['agent', 'coding-agent', 'sandbox', 'cli', 'llm'],
    repository: { type: 'git', url: `git+${REPO}.git` },
    homepage: REPO,
    bugs: { url: `${REPO}/issues` },
    publishConfig: { access: 'public' },
    dependencies: sorted(dependencies),
    optionalDependencies: sorted(optional),
    bundleDependencies: [...Object.keys(dependencies), ...platforms.names].sort(),
  };
  files.push({ path: 'package.json', data: Buffer.from(`${JSON.stringify(packageJson, null, 2)}\n`) });
  files.push({ path: 'bin/hn.mjs', data: Buffer.from(launcher()), executable: true });
  for (const name of ['LICENSE', 'NOTICE', 'README.md']) if (existsSync(join(ROOT, name))) files.push({ path: name, data: await readFile(join(ROOT, name)) });
  const privateKey = createPrivateKey(await readFile(options.key));
  files.push({ path: 'RELEASE-KEY.json', data: Buffer.from(`${JSON.stringify({ [options.keyId]: createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString() }, null, 2)}\n`) });
  files.push(...(await trustFiles({ ...(options.root === undefined ? {} : { root: options.root }), ...(options.rootId === undefined ? {} : { rootId: options.rootId }), ...(options.roster === undefined ? {} : { roster: options.roster }), keyId: options.keyId, publicPem: createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString() })));
  const sbom = Buffer.from(`${JSON.stringify(cycloneDx({ name: PRODUCT, version: options.version, created }, vendor.components), null, 2)}\n`);
  files.push({ path: 'sbom.cdx.json', data: sbom });
  const manifest = buildManifest(files, { name: PRODUCT, version: options.version, platform: 'any', created });
  const signature = `${JSON.stringify(signManifest(manifest, options.keyId, privateKey), null, 2)}\n`;
  const all: TarFile[] = [...files, { path: MANIFEST_PATH, data: manifestBytes(manifest) }, { path: SIGNATURE_PATH, data: Buffer.from(signature) }];
  // npm unpacks a tarball's single top folder, called `package`.
  const archive = gzipSync(writeTar(all.map((file) => ({ ...file, path: `package/${file.path}` }))), { level: 9 });
  await mkdir(options.out, { recursive: true });
  const stem = join(options.out, `${PRODUCT}-${options.version}`);
  await writeFile(`${stem}.tgz`, archive);
  await writeFile(`${stem}.sig.json`, signature);
  await writeFile(`${stem}.sbom.cdx.json`, sbom);
  return `${stem}.tgz`;
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { version: { type: 'string' }, key: { type: 'string' }, 'key-id': { type: 'string' }, out: { type: 'string' }, root: { type: 'string' }, 'root-id': { type: 'string' }, roster: { type: 'string' } } });
  if (values.version === undefined || values.key === undefined || values['key-id'] === undefined || values.out === undefined) throw new Error('pack-npm.ts --version <x.y.z> --key <private .pem> --key-id <id> --out <folder>');
  const epochText = process.env['SOURCE_DATE_EPOCH'] ?? spawnSync('git', ['log', '-1', '--format=%ct'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim();
  const epoch = Number(epochText);
  if (!Number.isInteger(epoch) || epoch <= 0) throw new Error('No SOURCE_DATE_EPOCH and no commit time.');
  process.stdout.write(`${await packNpm({ version: values.version, key: values.key, keyId: values['key-id'], out: values.out, epoch, ...(values.root === undefined ? {} : { root: values.root }), ...(values['root-id'] === undefined ? {} : { rootId: values['root-id'] }), ...(values.roster === undefined ? {} : { roster: values.roster }) })}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
