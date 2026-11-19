import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildHelperManifest, helperAssetName, helperManifestBytes, helperManifestName, helperSignatureName, signHelperManifest } from '@hn/release';
import { resolveHelper, runSetupCommand } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

const run = promisify(execFile);
const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));
const built = join(repoRoot, 'native', 'hn-sandbox', 'target', 'release', process.platform === 'win32' ? 'hn-sandbox.exe' : 'hn-sandbox');
const have = existsSync(built);
const platform = `${process.platform}-${process.arch}`;
const VERSION = '0.9.0';
const signer = generateKeyPairSync('ed25519');
const stranger = generateKeyPairSync('ed25519');

/** An installed copy: a release root holding its version and the key it pins. */
async function installedCopy(dir: string): Promise<{ root: string; home: string }> {
  const root = join(dir, 'pkg');
  await mkdir(root, { recursive: true });
  await writeFile(join(root, 'manifest.json'), JSON.stringify({ version: VERSION }));
  await writeFile(join(root, 'RELEASE-KEY.json'), JSON.stringify({ 'rel-1': signer.publicKey.export({ type: 'spki', format: 'pem' }).toString() }));
  const home = join(dir, 'home');
  await mkdir(home, { recursive: true });
  return { root, home };
}

interface Mirror {
  readonly url: string;
  readonly asked: string[];
  readonly server: Server;
}

async function mirror(files: Map<string, Buffer>): Promise<Mirror> {
  const asked: string[] = [];
  const server = createServer((req, res) => {
    asked.push(req.url ?? '');
    const data = files.get((req.url ?? '').slice(1));
    if (data === undefined) res.writeHead(404).end();
    else res.writeHead(200, { 'content-length': data.length }).end(data);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, asked, server };
}

const stop = (server: Server): Promise<void> =>
  new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });

/** The release's helper files for this platform, signed by `key`. */
function releaseFiles(binary: Buffer, key = signer.privateKey): Map<string, Buffer> {
  const manifest = buildHelperManifest([{ platform, data: binary }], { version: VERSION, created: '2026-11-18T00:00:00.000Z' });
  return new Map([
    [helperManifestName(VERSION), helperManifestBytes(manifest)],
    [helperSignatureName(VERSION), Buffer.from(JSON.stringify(signHelperManifest(manifest, 'rel-1', key)))],
    [helperAssetName(VERSION, platform), binary],
  ]);
}

describe('the sandbox helper in an installed copy', { skip: have ? false : 'hn-sandbox is not built' }, () => {
  it('is fetched on first use, verified, run, and not fetched again', async () => {
    await withTempDir(async (dir) => {
      const { root, home } = await installedCopy(dir);
      const site = await mirror(releaseFiles(await readFile(built)));
      const log: string[] = [];
      try {
        const env = { HN_RELEASE_ROOT: root, HN_RELEASE_URL: site.url };
        const path = await resolveHelper({ env, home, log: (text) => log.push(text) });
        assert.equal(path, join(home, 'bin', VERSION, process.platform === 'win32' ? 'hn-sandbox.exe' : 'hn-sandbox'));
        assert.match((await run(path as string, ['version'])).stdout, /^hn-sandbox /);
        assert.match(log.join(''), /fetching hn-sandbox 0\.9\.0 for .* from http:\/\/127\.0\.0\.1:\d+ .*verified and installed/s);
        const requests = site.asked.length;
        assert.equal(await resolveHelper({ env, home, log: (text) => log.push(text) }), path);
        assert.equal(site.asked.length, requests, 'the second use fetched nothing');
      } finally {
        await stop(site.server);
      }
    });
  });

  it('refuses a helper whose bytes differ from the signed hash, and runs and keeps nothing', async () => {
    await withTempDir(async (dir) => {
      const { root, home } = await installedCopy(dir);
      const files = releaseFiles(await readFile(built));
      const real = files.get(helperAssetName(VERSION, platform)) as Buffer;
      files.set(helperAssetName(VERSION, platform), Buffer.concat([real.subarray(0, real.length - 1), Buffer.from([(real[real.length - 1] as number) ^ 1])]));
      const site = await mirror(files);
      try {
        await assert.rejects(resolveHelper({ env: { HN_RELEASE_ROOT: root, HN_RELEASE_URL: site.url }, home, log: () => undefined }), /could not be installed, and nothing was run: .*SHA-256/);
        await assert.rejects(readdir(join(home, 'bin')), /ENOENT/);
      } finally {
        await stop(site.server);
      }
    });
  });

  it('refuses a release signed by a key the package does not pin, even with a matching hash', async () => {
    await withTempDir(async (dir) => {
      const { root, home } = await installedCopy(dir);
      const site = await mirror(releaseFiles(await readFile(built), stranger.privateKey));
      try {
        await assert.rejects(resolveHelper({ env: { HN_RELEASE_ROOT: root, HN_RELEASE_URL: site.url }, home, log: () => undefined }), /someone else/);
        assert.ok(!site.asked.some((path) => path.includes(helperAssetName(VERSION, platform))), 'the binary was never requested');
      } finally {
        await stop(site.server);
      }
    });
  });

  it('refuses a stored helper that was swapped, fetches a fresh one, and says why', async () => {
    await withTempDir(async (dir) => {
      const { root, home } = await installedCopy(dir);
      const site = await mirror(releaseFiles(await readFile(built)));
      const log: string[] = [];
      try {
        const env = { HN_RELEASE_ROOT: root, HN_RELEASE_URL: site.url };
        const path = (await resolveHelper({ env, home, log: () => undefined })) as string;
        await writeFile(path, randomBytes(2000));
        assert.equal(await resolveHelper({ env, home, download: false, log: () => undefined }), null, 'doctor-style lookup does not run it');
        assert.equal(await resolveHelper({ env, home, log: (text) => log.push(text) }), path);
        assert.match(log.join(''), /stored hn-sandbox failed its check/);
        assert.match((await run(path, ['version'])).stdout, /^hn-sandbox /);
      } finally {
        await stop(site.server);
      }
    });
  });

  it('never fetches when HN_NO_DOWNLOAD is set, and installs from a folder with the same checks', async () => {
    await withTempDir(async (dir) => {
      const { root, home } = await installedCopy(dir);
      const site = await mirror(new Map());
      try {
        const env = { HN_RELEASE_ROOT: root, HN_RELEASE_URL: site.url, HN_NO_DOWNLOAD: '1' };
        await assert.rejects(resolveHelper({ env, home, log: () => undefined }), /HN_NO_DOWNLOAD is set/);
        assert.equal(site.asked.length, 0);
        const folder = join(dir, 'offline');
        await mkdir(folder);
        const out: string[] = [];
        await assert.rejects(runSetupCommand({ positionals: ['setup'], from: folder, home, env, out: (text) => out.push(text) }), /is not in/);
        // A folder where the release's files should be is not a file: it gets the same plain refusal, not a read error.
        const trap = join(dir, 'trap');
        await mkdir(join(trap, helperManifestName(VERSION)), { recursive: true });
        // Everything else is present and valid, so the folder is the only thing wrong (otherwise a missing file's error wins the race).
        for (const [name, data] of releaseFiles(await readFile(built))) if (name !== helperManifestName(VERSION)) await writeFile(join(trap, name), data);
        await assert.rejects(runSetupCommand({ positionals: ['setup'], from: trap, home, env, out: (text) => out.push(text) }), /is not in/);
        for (const [name, data] of releaseFiles(await readFile(built), stranger.privateKey)) await writeFile(join(folder, name), data);
        await assert.rejects(runSetupCommand({ positionals: ['setup'], from: folder, home, env, out: (text) => out.push(text) }), /someone else/);
        // A file larger than the size it must have is refused without being read.
        await writeFile(join(folder, helperAssetName(VERSION, platform)), Buffer.alloc((await readFile(built)).length + 1, 1));
        for (const [name, data] of releaseFiles(await readFile(built))) if (name !== helperAssetName(VERSION, platform)) await writeFile(join(folder, name), data);
        await assert.rejects(runSetupCommand({ positionals: ['setup'], from: folder, home, env, out: (text) => out.push(text) }), /more than the \d+ it can be/);
        for (const [name, data] of releaseFiles(await readFile(built))) await writeFile(join(folder, name), data);
        assert.equal(await runSetupCommand({ positionals: ['setup'], from: folder, home, env, out: (text) => out.push(text) }), 0);
        assert.match(out.join(''), /Installed hn-sandbox 0\.9\.0/);
        assert.notEqual(await resolveHelper({ env, home, download: false }), null);
        assert.equal(await runSetupCommand({ positionals: ['other'], home, env, out: () => undefined }), null);
      } finally {
        await stop(site.server);
      }
    });
  });

  it('works through the real command line: hn setup fetches, hn doctor then reports it verified', async () => {
    await withTempDir(async (dir) => {
      const { root, home } = await installedCopy(dir);
      const site = await mirror(releaseFiles(await readFile(built)));
      try {
        const env: NodeJS.ProcessEnv = { ...process.env, HN_HOME: home, HN_RELEASE_ROOT: root, HN_RELEASE_URL: site.url };
        delete env['HN_SANDBOX_BIN'];
        const doctor = async (): Promise<string> => String(((await run(process.execPath, [launcher, 'doctor'], { env }).catch((error: unknown) => error)) as { stdout: string }).stdout);
        assert.match(await doctor(), /hn-sandbox helper.*not installed yet/s);
        const setup = await run(process.execPath, [launcher, 'setup'], { env });
        assert.match(setup.stdout, /is ready and verified/);
        assert.match(await doctor(), /hn-sandbox helper[^\n]*reads and writes work/);
      } finally {
        await stop(site.server);
      }
    });
  });
});

describe('hn setup from source', () => {
  it('says it applies to an installed release', async () => {
    const out: string[] = [];
    assert.equal(await runSetupCommand({ positionals: ['setup'], home: '/nowhere', env: {}, out: (text) => out.push(text) }), 0);
    assert.match(out.join(''), /runs from source/);
  });
});
