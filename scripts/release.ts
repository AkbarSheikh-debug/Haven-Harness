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
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { gzipSync } from 'node:zlib';
import { MANIFEST_PATH, buildManifest, cycloneDx, manifestBytes, signManifest, writeTar, type SbomComponent } from '../packages/release/src/index.ts';

import { ROOT, compileWorkspace, vendorClosure } from './build-common.ts';
const PRODUCT = 'haven-harness';

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
  const { files, shipped } = await compileWorkspace(options.version, 'lib/node_modules');
  const vendor = await vendorClosure(shipped, 'lib/node_modules');
  files.push(...vendor.files);
  const components: SbomComponent[] = vendor.components;
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
