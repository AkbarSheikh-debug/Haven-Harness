import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { buildManifest, manifestBytes, signManifest, verifyInstalledTree, type TarFile } from '@hn/release';
import { withTempDir } from '@hn/testkit';

/**
 * The installed-tree check on a small signed package. The full npm package is checked in npm-package.test.ts; this
 * builds a tree of a few files so each way a tree can be wrong gets its own test, in milliseconds.
 */

const signer = generateKeyPairSync('ed25519');
const pem = (key: typeof signer.publicKey): string => key.export({ type: 'spki', format: 'pem' }).toString();
const META = { name: 'haven-harness', version: '0.9.0', platform: 'any', created: '2026-11-18T00:00:00.000Z' };
const FILES: TarFile[] = [
  // The real package signs its own pinned key along with everything else.
  { path: 'RELEASE-KEY.json', data: Buffer.from(JSON.stringify({ 'rel-1': pem(signer.publicKey) })) },
  { path: 'bin/hn.mjs', data: Buffer.from('launcher\n') },
  { path: 'node_modules/@hn/core/index.js', data: Buffer.from('export const core = 1;\n') },
  { path: 'node_modules/left-pad/index.js', data: Buffer.from('third party\n') },
  { path: 'package.json', data: Buffer.from('{}\n') },
];

async function put(root: string, path: string, data: Buffer | string): Promise<void> {
  const target = join(root, ...path.split('/'));
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, data);
}

/** Writes a package under `root`: the listed files, the manifest bytes and a signature over `signed`. */
async function build(root: string, options: { listed?: readonly TarFile[]; written?: readonly TarFile[]; manifest?: Buffer; sign?: Buffer } = {}): Promise<void> {
  const listed = options.listed ?? FILES;
  for (const file of options.written ?? listed) await put(root, file.path, file.data);
  const manifest = buildManifest(listed, META);
  const bytes = options.manifest ?? manifestBytes(manifest);
  await put(root, 'manifest.json', bytes);
  const signature = options.sign === undefined ? signManifest(manifest, 'rel-1', signer.privateKey) : { keyId: 'rel-1', signature: sign(null, options.sign, signer.privateKey).toString('base64') };
  await put(root, 'manifest.sig.json', JSON.stringify(signature));
}

describe('verifyInstalledTree', () => {
  it('accepts exactly what was signed and counts the files it checked', async () => {
    await withTempDir(async (root) => {
      await build(root);
      const result = await verifyInstalledTree(root);
      assert.equal(result.ok, true, result.problems.join('; '));
      assert.equal(result.checked, FILES.length);
      assert.equal(result.version, '0.9.0');
    });
  });

  it('refuses a file that was deleted, and says which', async () => {
    await withTempDir(async (root) => {
      await build(root);
      await rm(join(root, 'node_modules', '@hn', 'core', 'index.js'));
      const result = await verifyInstalledTree(root);
      assert.equal(result.ok, false);
      assert.deepEqual(result.problems, ['node_modules/@hn/core/index.js is missing']);
    });
  });

  it('refuses a file that was changed, including one inside a third-party package', async () => {
    await withTempDir(async (root) => {
      await build(root);
      await put(root, 'node_modules/left-pad/index.js', 'changed\n');
      const result = await verifyInstalledTree(root);
      assert.equal(result.ok, false);
      assert.deepEqual(result.problems, ['node_modules/left-pad/index.js was changed']);
    });
  });

  it('refuses a manifest that is valid JSON and correctly signed but not in its canonical form', async () => {
    await withTempDir(async (root) => {
      const manifest = buildManifest(FILES, META);
      // The same content, indented: a person with the key could sign it, but it is not the one form the release writes.
      const indented = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
      assert.notDeepEqual(indented, manifestBytes(manifest));
      await build(root, { manifest: indented, sign: indented });
      const result = await verifyInstalledTree(root);
      assert.equal(result.ok, false);
      assert.match(result.problems.join(), /not in its signed form/);
    });
  });

  it('refuses a signed manifest that lists a path outside the package, and never reads it', async () => {
    for (const bad of ['../outside.js', '/etc/passwd', 'a/../../b.js', 'C:/Windows/x.dll', 'a\\b.js']) {
      await withTempDir(async (root) => {
        const listed = [...FILES, { path: bad, data: Buffer.from('x') }];
        await build(root, { listed, written: FILES });
        const result = await verifyInstalledTree(root);
        assert.equal(result.ok, false, bad);
        assert.ok(result.problems.includes(`${bad} is not a path inside the package`), `${bad}: ${result.problems.join('; ')}`);
      });
    }
  });

  it('reports a file added where only signed files belong: the launcher folder, our own code, the top level', async () => {
    for (const extra of ['bin/extra.mjs', 'node_modules/@hn/core/planted.js', 'planted.txt']) {
      await withTempDir(async (root) => {
        await build(root);
        await put(root, extra, 'x');
        const result = await verifyInstalledTree(root);
        assert.equal(result.ok, false, extra);
        assert.deepEqual(result.problems, [`${extra} is not part of the signed release`]);
      });
    }
  });

  it('does not judge npm\'s own files, or extra files inside third-party packages', async () => {
    await withTempDir(async (root) => {
      await build(root);
      await put(root, 'node_modules/.package-lock.json', '{}');
      await put(root, 'node_modules/left-pad/package-lock.json', '{}');
      const result = await verifyInstalledTree(root);
      assert.equal(result.ok, true, result.problems.join('; '));
    });
  });

  it('refuses a signature made by another key, and a signature naming a key the package does not pin', async () => {
    await withTempDir(async (root) => {
      await build(root);
      const manifest = buildManifest(FILES, META);
      await put(root, 'manifest.sig.json', JSON.stringify(signManifest(manifest, 'rel-1', generateKeyPairSync('ed25519').privateKey)));
      const foreign = await verifyInstalledTree(root);
      assert.equal(foreign.ok, false);
      assert.match(foreign.problems.join(), /signature does not match/);
      await put(root, 'manifest.sig.json', JSON.stringify(signManifest(manifest, 'unknown-id', signer.privateKey)));
      const unknown = await verifyInstalledTree(root);
      assert.equal(unknown.ok, false);
      assert.match(unknown.problems.join(), /does not pin/);
    });
  });

  it('refuses an unsigned, mis-signed or unreadable package', async () => {
    await withTempDir(async (root) => {
      await build(root);
      await put(root, 'manifest.json', Buffer.concat([manifestBytes(buildManifest(FILES, META)), Buffer.from(' ')]));
      assert.equal((await verifyInstalledTree(root)).ok, false);
    });
    await withTempDir(async (root) => {
      assert.match((await verifyInstalledTree(root)).problems.join(), /missing or unreadable/);
    });
  });
});
