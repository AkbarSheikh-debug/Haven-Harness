import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, sep } from 'node:path';
import { promisify } from 'node:util';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { buildHelperManifest, helperAssetName, helperManifestBytes, helperManifestName, helperSignatureName, readTar, signHelperManifest, verifyInstalledTree, type TarFile } from '@hn/release';
import { withTempDir } from '@hn/testkit';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const built = join(ROOT, 'native', 'hn-sandbox', 'target', 'release', process.platform === 'win32' ? 'hn-sandbox.exe' : 'hn-sandbox');
const platform = `${process.platform}-${process.arch}`;
const signer = generateKeyPairSync('ed25519');
const VERSION = '0.9.0';
const EPOCH = 1_700_000_000;
const offline = process.env['HN_OFFLINE'] === '1';

/** The packer is a developer script; it is run as the release workflow runs it. */
async function packNpm(options: { version: string; key: string; keyId: string; out: string; epoch: number }): Promise<string> {
  const result = await run(process.execPath, ['--disable-proto=throw', join(ROOT, 'scripts', 'pack-npm.ts'), '--version', options.version, '--key', options.key, '--key-id', options.keyId, '--out', options.out], { env: { ...process.env, SOURCE_DATE_EPOCH: String(options.epoch) }, maxBuffer: 1 << 26, timeout: 600_000 });
  return result.stdout.trim();
}

const pkgText = (files: readonly TarFile[], path: string): string => (files.find((file) => file.path === path) as TarFile).data.toString('utf8');

describe('the npm package', { skip: offline ? 'HN_OFFLINE=1' : false, timeout: 900_000 }, () => {
  let dir = '';
  let tgz = '';
  let files: TarFile[] = [];

  before(async () => {
    dir = await mkdtemp(join(tmpdir(), 'hn-npm-pack-'));
    const key = join(dir, 'key.pem');
    await writeFile(key, signer.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    tgz = await packNpm({ version: VERSION, key, keyId: 'rel-1', out: join(dir, 'one'), epoch: EPOCH });
    files = readTar(gunzipSync(await readFile(tgz)));
  });

  after(async () => {
    if (dir !== '') await rm(dir, { recursive: true, force: true });
  });

  it('is byte-identical when built twice from one commit, with its signature and SBOM', async () => {
    const key = join(dir, 'key.pem');
    const again = await packNpm({ version: VERSION, key, keyId: 'rel-1', out: join(dir, 'two'), epoch: EPOCH });
    assert.ok((await readFile(tgz)).equals(await readFile(again)), 'the two archives differ');
    for (const suffix of ['sig.json', 'sbom.cdx.json']) assert.ok((await readFile(join(dir, 'one', `haven-harness-${VERSION}.${suffix}`))).equals(await readFile(join(dir, 'two', `haven-harness-${VERSION}.${suffix}`))), suffix);
  });

  it('runs no install script, in itself or in anything it carries, and has no native build', () => {
    const top = JSON.parse(pkgText(files, 'package/package.json')) as Record<string, unknown>;
    assert.equal(top['scripts'], undefined);
    assert.equal(top['gypfile'], undefined);
    assert.deepEqual(top['bin'], { hn: 'bin/hn.mjs', 'haven-harness': 'bin/hn.mjs' });
    const manifests = files.filter((file) => file.path.endsWith('/package.json'));
    assert.ok(manifests.length > 20, 'the carried packages were not found');
    // The hooks npm runs when it installs a package. (`prepare` is for the package's own developers: npm does not run it
    // for an installed dependency, and one bundled package, standardwebhooks, declares it.)
    const hooks = ['preinstall', 'install', 'postinstall'];
    for (const manifest of manifests) {
      const parsed = JSON.parse(manifest.data.toString('utf8')) as { scripts?: Record<string, string>; gypfile?: boolean };
      for (const hook of hooks) assert.equal(parsed.scripts?.[hook], undefined, `${manifest.path} runs ${hook}`);
      assert.notEqual(parsed.gypfile, true, `${manifest.path} builds native code`);
    }
    assert.equal(files.filter((file) => /binding\.gyp$|\.node$/.test(file.path)).length, 0, 'native addons or build files are carried');
  });

  it('bundles the workspace and its dependencies, ships ripgrep for the six supported platforms, and leaves the sandbox helper out', () => {
    const top = JSON.parse(pkgText(files, 'package/package.json')) as { bundleDependencies: string[]; optionalDependencies: Record<string, string>; license: string; engines: { node: string } };
    for (const name of ['@hn/surfaces', '@hn/release', '@anthropic-ai/sdk', '@vscode/ripgrep', '@vscode/tree-sitter-wasm']) assert.ok(top.bundleDependencies.includes(name), name);
    for (const name of top.bundleDependencies) assert.ok(files.some((file) => file.path.startsWith(`package/node_modules/${name}/`)), `${name} is declared but not in the archive`);
    assert.deepEqual(Object.keys(top.optionalDependencies).sort(), ['win32-x64', 'win32-arm64', 'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'].map((entry) => `@vscode/ripgrep-${entry}`).sort());
    assert.equal(top.license, 'Apache-2.0');
    assert.ok(files.some((file) => file.path === 'package/node_modules/@vscode/ripgrep-linux-x64/bin/rg' && file.executable === true));
    assert.ok(!files.some((file) => /hn-sandbox(\.exe)?$/.test(file.path)), 'the native helper must not be in the package');
    assert.ok(!files.some((file) => file.path.startsWith('package/node_modules/@hn/') && file.path.endsWith('.ts')), 'our own code is carried as compiled JavaScript only');
    assert.equal(top.engines.node, '>=24.14.0');
  });

  it('carries a manifest signed by the pinned key, which verifies once unpacked and refuses an edit, a missing file and another key', async () => {
    await withTempDir(async (target) => {
      for (const file of files) {
        const path = join(target, ...file.path.replace(/^package\//, '').split('/'));
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, file.data);
      }
      const good = await verifyInstalledTree(target);
      // The launcher passes the package root with a trailing separator; it must make no difference.
      assert.equal((await verifyInstalledTree(`${target}${sep}`)).ok, true);
      assert.equal(good.ok, true, good.problems.join('; '));
      assert.equal(good.version, VERSION);
      assert.ok(good.checked > 1000, `only ${good.checked} files were checked`);
      const victim = join(target, 'node_modules', '@hn', 'security', 'src', 'index.js');
      const original = await readFile(victim);
      await writeFile(victim, Buffer.concat([original, Buffer.from('\n// edited\n')]));
      const edited = await verifyInstalledTree(target);
      assert.equal(edited.ok, false);
      assert.match(edited.problems.join(), /@hn\/security\/src\/index\.js was changed/);
      await writeFile(victim, original);
      assert.equal((await verifyInstalledTree(target)).ok, true);
      // A file added where only signed files belong is reported: the launcher folder, our own code, the top level.
      for (const extra of ['bin/extra.mjs', 'node_modules/@hn/security/src/planted.js', 'planted.txt']) {
        await writeFile(join(target, ...extra.split('/')), 'x');
        assert.ok((await verifyInstalledTree(target)).problems.join().includes(`${extra} is not part of the signed release`), extra);
        await rm(join(target, ...extra.split('/')));
        assert.equal((await verifyInstalledTree(target)).ok, true, `${extra} left behind`);
      }
      // npm's own files inside third-party packages are not judged.
      await writeFile(join(target, 'node_modules', '.package-lock.json'), '{}');
      assert.equal((await verifyInstalledTree(target)).ok, true);
      await writeFile(join(target, 'RELEASE-KEY.json'), JSON.stringify({ 'rel-1': generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString() }));
      assert.match((await verifyInstalledTree(target)).problems.join(), /signature does not match/);
      await writeFile(join(target, 'manifest.sig.json'), JSON.stringify({ keyId: 'other', signature: 'AAAA' }));
      assert.match((await verifyInstalledTree(target)).problems.join(), /does not pin/);
      assert.equal((await verifyInstalledTree(join(target, 'nothing'))).ok, false);
    });
  });

  it('installs with npm into a clean prefix, starts, passes its own integrity check, and fetches a verified helper on first use', { skip: existsSync(built) ? false : 'hn-sandbox is not built' }, async () => {
    await withTempDir(async (target) => {
      const prefix = join(target, 'prefix');
      const home = join(target, 'home');
      await mkdir(prefix);
      await mkdir(home);
      const installed = await run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['install', '-g', '--foreground-scripts', '--prefix', prefix, tgz], { shell: process.platform === 'win32', timeout: 600_000 });
      assert.doesNotMatch(`${installed.stdout}${installed.stderr}`, /^> \S+@\S+ \S*(pre|post)?install/m, 'npm ran an install script');
      const hn = process.platform === 'win32' ? join(prefix, 'hn.cmd') : join(prefix, 'bin', 'hn');
      const binary = await readFile(built);
      const manifest = buildHelperManifest([{ platform, data: binary }], { version: VERSION, created: '2026-11-18T00:00:00.000Z' });
      const served = new Map<string, Buffer>([
        [helperManifestName(VERSION), helperManifestBytes(manifest)],
        [helperSignatureName(VERSION), Buffer.from(JSON.stringify(signHelperManifest(manifest, 'rel-1', signer.privateKey)))],
        [helperAssetName(VERSION, platform), binary],
      ]);
      const server = createServer((req, res) => {
        const data = served.get((req.url ?? '').slice(1));
        if (data === undefined) res.writeHead(404).end();
        else res.writeHead(200, { 'content-length': data.length }).end(data);
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      try {
        const env: NodeJS.ProcessEnv = { ...process.env, HN_HOME: home, HN_RELEASE_URL: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
        delete env['HN_SANDBOX_BIN'];
        delete env['HN_RELEASE_ROOT'];
        const exec = (args: string[]): Promise<{ stdout: string; stderr: string }> => run(hn, args, { env, shell: process.platform === 'win32' });
        assert.equal((await exec(['--version'])).stdout.trim(), `hn ${VERSION}`);
        const before = await exec(['doctor']).catch((error: { stdout: string }) => error);
        assert.match(before.stdout, /ok\s+release integrity\s+\d+ files match the manifest signed for 0\.9\.0/);
        assert.match(before.stdout, /ok\s+ripgrep/);
        assert.match(before.stdout, /ok\s+__proto__ disabled/, 'the launcher must start hn with --disable-proto=throw');
        assert.match(before.stdout, /warn\s+hn-sandbox helper\s+not installed yet/);
        const setup = await exec(['setup']);
        assert.match(setup.stdout, /fetching hn-sandbox 0\.9\.0/);
        assert.match(setup.stdout, /is ready and verified/);
        // A file of the installed package edited after install is reported by the real command.
        const victim = join(prefix, 'node_modules', 'haven-harness', 'node_modules', '@hn', 'security', 'src', 'index.js');
        const original = await readFile(victim);
        await writeFile(victim, Buffer.concat([original, Buffer.from('\n// edited\n')]));
        const tampered = await exec(['doctor']).catch((error: { stdout: string }) => error);
        assert.match(tampered.stdout, /FAIL\s+release integrity\s+[^\n]*security\/src\/index\.js was changed/);
        await writeFile(victim, original);
        const afterSetup = await exec(['doctor']).catch((error: { stdout: string }) => error);
        assert.match(afterSetup.stdout, /ok\s+hn-sandbox helper[^\n]*reads and writes work/);
      } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });
  });
});
