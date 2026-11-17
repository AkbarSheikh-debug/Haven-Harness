import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { describe, it } from 'node:test';
import { MANIFEST_PATH, buildManifest, compareVersions, installRelease, manifestBytes, readTar, signManifest, verifyRelease, writeTar, type TarFile } from '@hn/release';
import { withTempDir } from '@hn/testkit';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const signer = generateKeyPairSync('ed25519');
const other = generateKeyPairSync('ed25519');
const pem = (key: typeof signer.publicKey): string => key.export({ type: 'spki', format: 'pem' }).toString();
const pinned = new Map([['rel-1', pem(signer.publicKey)]]);
const PLATFORM = 'test-x64';

function release(version: string, files: TarFile[] = [{ path: 'bin/hn.mjs', data: Buffer.from('// hn'), executable: true }, { path: 'lib/a.js', data: Buffer.from('export {};') }], key = signer.privateKey): { archive: Buffer; signature: unknown; tar: Buffer } {
  const manifest = buildManifest(files, { name: 'haven-harness', version, platform: PLATFORM, created: '2026-11-17T00:00:00.000Z' });
  const tar = writeTar([...files, { path: MANIFEST_PATH, data: manifestBytes(manifest) }]);
  return { archive: gzipSync(tar), signature: signManifest(manifest, 'rel-1', key), tar };
}

describe('the deterministic tar', () => {
  it('writes the same bytes for the same files in any order, and reads them back, long paths included', () => {
    const long = `lib/node_modules/${'deep/'.repeat(40)}file.js`;
    const files = [{ path: 'b.txt', data: Buffer.from('b') }, { path: long, data: Buffer.from('x'.repeat(1000)) }, { path: 'a.txt', data: Buffer.from('a'), executable: true }];
    const one = writeTar(files);
    assert.ok(one.equals(writeTar([...files].reverse())));
    assert.deepEqual(readTar(one).map((file) => [file.path, file.data.length, file.executable]), [['a.txt', 1, true], ['b.txt', 1, false], [long, 1000, false]]);
  });

  it('refuses paths that would leave the folder, links, duplicates and a bad checksum', () => {
    for (const path of ['../x', '/etc/passwd', 'a/../../x', 'C:/x', 'a\\b', 'a//b', '']) assert.throws(() => writeTar([{ path, data: Buffer.alloc(0) }]), /not a path/, path);
    assert.throws(() => writeTar([{ path: 'A.txt', data: Buffer.alloc(0) }, { path: 'a.txt', data: Buffer.alloc(0) }]), /twice/);
    const good = writeTar([{ path: 'a.txt', data: Buffer.from('hi') }]);
    const link = Buffer.from(good);
    link[156] = '2'.charCodeAt(0);
    let sum = 0;
    for (let index = 0; index < 512; index += 1) sum += index >= 148 && index < 156 ? 32 : (link[index] as number);
    link.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
    assert.throws(() => readTar(link), /only regular files/);
    const sneaky = Buffer.from(good);
    sneaky.write('../evil.txt\0', 0, 'utf8');
    assert.throws(() => readTar(sneaky), /checksum/);
  });
});

describe('the signed manifest', () => {
  it('accepts a release signed by the pinned key and refuses every kind of change', () => {
    const { tar, signature } = release('0.8.0');
    assert.equal(verifyRelease(tar, signature, pinned).manifest.version, '0.8.0');
    assert.throws(() => verifyRelease(tar, { keyId: 'nobody', signature: 'x' }, pinned), /does not trust/);
    assert.throws(() => verifyRelease(tar, release('0.8.0', undefined, other.privateKey).signature, pinned), /changed or signed by someone else/);
    assert.throws(() => verifyRelease(tar, null, pinned), /no signature/);
    const entries = readTar(tar);
    const swap = (path: string, data: Buffer): Buffer => writeTar(entries.map((entry) => (entry.path === path ? { ...entry, data } : entry)));
    assert.throws(() => verifyRelease(swap('lib/a.js', Buffer.from('evil()')), signature, pinned), /does not match its hash/);
    assert.throws(() => verifyRelease(writeTar([...entries, { path: 'lib/extra.js', data: Buffer.from('x') }]), signature, pinned), /does not list/);
    assert.throws(() => verifyRelease(writeTar(entries.filter((entry) => entry.path !== 'lib/a.js')), signature, pinned), /missing lib\/a\.js/);
    const manifest = JSON.parse(entries.find((entry) => entry.path === MANIFEST_PATH)!.data.toString()) as object;
    assert.throws(() => verifyRelease(swap(MANIFEST_PATH, Buffer.from(JSON.stringify(manifest, null, 2))), signature, pinned), /signed form/);
  });

  it('compares versions as numbers and refuses anything else', () => {
    assert.ok(compareVersions('0.10.0', '0.9.9') > 0);
    assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
    assert.throws(() => compareVersions('1.2', '1.2.3'), /Not a version/);
    assert.throws(() => compareVersions('1.2.3-beta', '1.2.3'), /Not a version/);
  });
});

describe('the update verifier', () => {
  const key = randomBytes(32);

  it('installs a newer signed release, and refuses a reinstall, a downgrade, another platform and an edited record', async () => {
    await withTempDir(async (dir) => {
      const appDir = join(dir, 'app');
      const install = (version: string, extra: Partial<Parameters<typeof installRelease>[0]> = {}) => {
        const { archive, signature } = release(version);
        return installRelease({ archive, signature, pinned, appDir, key, running: '0.7.0', platform: PLATFORM, ...extra });
      };
      await assert.rejects(install('0.6.0'), /no downgrade/);
      const first = await install('0.8.0');
      assert.equal(await readFile(join(first.root, 'lib', 'a.js'), 'utf8'), 'export {};');
      assert.equal(JSON.parse(await readFile(join(first.root, 'manifest.json'), 'utf8')).version, '0.8.0');
      await assert.rejects(install('0.8.0'), /no downgrade, no reinstall/);
      await assert.rejects(install('0.7.5'), /0\.8\.0 is already installed/);
      await assert.rejects(install('0.9.0', { platform: 'other-arm64' }), /for test-x64, not other-arm64/);
      await assert.rejects(install('0.9.0', { pinned: new Map([['rel-1', pem(other.publicKey)]]) }), /changed or signed by someone else/);
      // Editing the record to an old version to make a downgrade look new is caught by its HMAC.
      const record = JSON.parse(await readFile(join(appDir, 'highest.json'), 'utf8')) as { version: string; mac: string };
      await writeFile(join(appDir, 'highest.json'), JSON.stringify({ ...record, version: '0.1.0' }));
      await assert.rejects(install('0.7.9'), /record of the highest installed version was changed/);
      await writeFile(join(appDir, 'highest.json'), JSON.stringify(record));
      assert.equal((await install('0.9.0')).manifest.version, '0.9.0');
      assert.ok((await readdir(appDir)).every((name) => !name.startsWith('.staging-')), 'no staging folder is left');
    });
  });

  it('a hostile archive (bad gzip, a path out of the folder) installs nothing and does not move the floor', async () => {
    await withTempDir(async (dir) => {
      const appDir = join(dir, 'app');
      await assert.rejects(installRelease({ archive: Buffer.from('not gzip'), signature: {}, pinned, appDir, key, running: '0.7.0', platform: PLATFORM }), /not a gzip file/);
      const { signature } = release('0.8.0');
      const hostile = Buffer.from(writeTar([{ path: 'x.txt', data: Buffer.from('x') }]));
      hostile.write('../../escape.txt\0', 0, 'utf8');
      await assert.rejects(installRelease({ archive: gzipSync(hostile), signature, pinned, appDir, key, running: '0.7.0', platform: PLATFORM }));
      await assert.rejects(readFile(join(dir, 'escape.txt')));
      await assert.rejects(readFile(join(appDir, 'highest.json')));
    });
  });
});

describe('a real release build', () => {
  it('builds byte-identical twice from one commit, installs, runs, and hn update refuses a reinstall and a call from inside a session', { timeout: 600_000 }, async () => {
    await withTempDir(async (dir) => {
      const keys = join(dir, 'keys');
      const script = join(ROOT, 'scripts', 'release.ts');
      await run(process.execPath, ['--disable-proto=throw', script, '--keygen', keys]);
      const env = { ...process.env, SOURCE_DATE_EPOCH: '1763337600' };
      const build = async (out: string): Promise<string> => (await run(process.execPath, ['--disable-proto=throw', script, '--version', '0.8.0', '--key', join(keys, 'release-key.pem'), '--key-id', 'test', '--out', join(dir, out)], { env, cwd: ROOT, maxBuffer: 16 * 1024 * 1024 })).stdout.trim();
      const a = await build('a');
      const b = await build('b');
      assert.ok((await readFile(a)).equals(await readFile(b)), 'two builds of one commit are byte-identical');
      const sbom = JSON.parse(await readFile(a.replace(/\.tgz$/, '.sbom.cdx.json'), 'utf8')) as { components: { name: string }[] };
      assert.ok(sbom.components.some((component) => component.name === '@anthropic-ai/sdk'));

      const publicPem = await readFile(join(keys, 'release-key.pub.pem'), 'utf8');
      const installed = await installRelease({ archive: await readFile(a), signature: JSON.parse(await readFile(a.replace(/\.tgz$/, '.sig.json'), 'utf8')), pinned: new Map([['test', publicPem]]), appDir: join(dir, 'app'), key: randomBytes(32), running: '0.0.1' });
      const hn = join(installed.root, 'bin', 'hn.mjs');
      const home: NodeJS.ProcessEnv = { ...process.env, HN_HOME: join(dir, 'home') };
      delete home['HN_PARENT_SESSION'];
      assert.equal((await run(process.execPath, [hn, '--version'], { env: home })).stdout.trim(), 'hn 0.8.0');
      const reinstall = await run(process.execPath, [hn, 'update', a], { env: home }).catch((error: { stderr: string }) => error);
      assert.match(String((reinstall as { stderr: string }).stderr), /no downgrade, no reinstall/);
      const nested = await run(process.execPath, [hn, 'update', a], { env: { ...home, HN_PARENT_SESSION: 'some-session' } }).catch((error: { stderr: string }) => error);
      assert.match(String((nested as { stderr: string }).stderr), /cannot be run from inside an hn session/);
    });
  });
});
