import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { HELPER_PLATFORMS, helperAssetName, helperManifestName, helperSignatureName, verifyHelperManifest } from '@hn/release';
import { withTempDir } from '@hn/testkit';

const run = promisify(execFile);
const script = fileURLToPath(new URL('../../../scripts/sandbox-manifest.ts', import.meta.url));
const VERSION = '0.9.0';
const pair = generateKeyPairSync('ed25519');

async function folder(dir: string, platforms: readonly string[]): Promise<Map<string, Buffer>> {
  const made = new Map<string, Buffer>();
  await mkdir(join(dir, 'bins'), { recursive: true });
  for (const platform of platforms) {
    const data = randomBytes(1000 + platform.length);
    made.set(platform, data);
    await writeFile(join(dir, 'bins', helperAssetName(VERSION, platform)), data);
  }
  await writeFile(join(dir, 'key.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  return made;
}

const sign = (dir: string, extra: string[] = []): Promise<{ stdout: string; stderr: string }> => run(process.execPath, ['--disable-proto=throw', script, '--version', VERSION, '--binaries', join(dir, 'bins'), '--key', join(dir, 'key.pem'), '--key-id', 'rel-1', '--out', join(dir, 'out'), ...extra]);

describe('scripts/sandbox-manifest.ts', () => {
  it('signs all six platforms into a manifest that an installed hn accepts, with the right hashes', async () => {
    await withTempDir(async (dir) => {
      const made = await folder(dir, HELPER_PLATFORMS);
      const result = await sign(dir);
      assert.match(result.stdout, /Signed 6 helper\(s\)/);
      const bytes = await readFile(join(dir, 'out', helperManifestName(VERSION)));
      const signature = JSON.parse(await readFile(join(dir, 'out', helperSignatureName(VERSION)), 'utf8')) as unknown;
      const pinned = new Map([['rel-1', pair.publicKey.export({ type: 'spki', format: 'pem' }).toString()]]);
      const manifest = verifyHelperManifest(bytes, signature, pinned, VERSION);
      assert.deepEqual(Object.keys(manifest.binaries).sort(), [...HELPER_PLATFORMS].sort());
      for (const [platform, data] of made) assert.equal(manifest.binaries[platform]?.size, data.length);
    });
  });

  it('refuses a release with a platform missing unless told it is partial, and then lists only what is there', async () => {
    await withTempDir(async (dir) => {
      await folder(dir, HELPER_PLATFORMS.filter((platform) => platform !== 'darwin-arm64'));
      await assert.rejects(sign(dir), (error: { stderr: string }) => /No helper for darwin-arm64/.test(error.stderr));
      assert.match((await sign(dir, ['--allow-partial'])).stdout, /Signed 5 helper\(s\)/);
    });
  });

  it('refuses without a key, and a key that is not a private key', async () => {
    await withTempDir(async (dir) => {
      await folder(dir, HELPER_PLATFORMS);
      await assert.rejects(run(process.execPath, ['--disable-proto=throw', script, '--version', VERSION, '--binaries', join(dir, 'bins')]), (error: { stderr: string }) => /sandbox-manifest\.ts --version/.test(error.stderr));
      await writeFile(join(dir, 'key.pem'), 'not a key');
      await assert.rejects(sign(dir));
    });
  });
});
