// Hashes and signs the sandbox helpers of one release. A developer tool, not part of hn.
//
//   node --disable-proto=throw scripts/sandbox-manifest.ts --version 0.9.0 --binaries <folder> --key <private .pem> --key-id <id> [--out <folder>] [--allow-partial]
//
// The folder holds one `hn-sandbox-<version>-<platform>[.exe]` per platform, as the release workflow's build jobs
// leave them. The manifest lists every platform with its size and SHA-256 and is signed with the release key, which
// stays with its owner (offline, or a CI secret they choose to add). A release must cover all six platforms unless
// --allow-partial is given, so a missing build cannot ship by accident. The output is checked with the same verifier
// hn uses, against the public key derived from the private one, before it is written.

import { createPrivateKey, createPublicKey } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { HELPER_PLATFORMS, buildHelperManifest, helperAssetName, helperManifestBytes, helperManifestName, helperSignatureName, signHelperManifest, verifyHelperManifest } from '../packages/release/src/index.ts';

export async function signHelpers(options: { version: string; binaries: string; key: string; keyId: string; out: string; allowPartial: boolean; created: string }): Promise<string[]> {
  const present = new Set(await readdir(options.binaries));
  const found: { platform: string; data: Buffer }[] = [];
  const missing: string[] = [];
  for (const platform of HELPER_PLATFORMS) {
    const name = helperAssetName(options.version, platform);
    if (present.has(name)) found.push({ platform, data: await readFile(join(options.binaries, name)) });
    else missing.push(platform);
  }
  if (missing.length > 0 && !options.allowPartial) throw new Error(`No helper for ${missing.join(', ')} in ${options.binaries}. Every platform must be built, or pass --allow-partial.`);
  const manifest = buildHelperManifest(found, { version: options.version, created: options.created });
  const privateKey = createPrivateKey(await readFile(options.key));
  const signature = signHelperManifest(manifest, options.keyId, privateKey);
  const bytes = helperManifestBytes(manifest);
  // The same check an installed hn makes, against the key that would be pinned.
  verifyHelperManifest(bytes, signature, new Map([[options.keyId, createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString()]]), options.version);
  await mkdir(options.out, { recursive: true });
  await writeFile(join(options.out, helperManifestName(options.version)), bytes);
  await writeFile(join(options.out, helperSignatureName(options.version)), `${JSON.stringify(signature)}\n`);
  return found.map((entry) => `${entry.platform} ${manifest.binaries[entry.platform]?.sha256}`);
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { version: { type: 'string' }, binaries: { type: 'string' }, key: { type: 'string' }, 'key-id': { type: 'string' }, out: { type: 'string' }, 'allow-partial': { type: 'boolean' } } });
  if (values.version === undefined || values.binaries === undefined || values.key === undefined || values['key-id'] === undefined) throw new Error('sandbox-manifest.ts --version <x.y.z> --binaries <folder> --key <private .pem> --key-id <id> [--out <folder>] [--allow-partial]');
  const lines = await signHelpers({ version: values.version, binaries: values.binaries, key: values.key, keyId: values['key-id'], out: values.out ?? values.binaries, allowPartial: values['allow-partial'] === true, created: new Date().toISOString() });
  process.stdout.write(`${lines.join('\n')}\nSigned ${lines.length} helper(s).\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
