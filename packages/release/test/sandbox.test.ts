import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import {
  MAX_REDIRECTS,
  allowedDownloadUrl,
  buildHelperManifest,
  checkNpmIntegrity,
  cachedHelperName,
  downloadHelper,
  fetchBounded,
  helperAssetName,
  helperEntry,
  helperManifestBytes,
  helperManifestName,
  helperSignatureName,
  installHelper,
  signHelperManifest,
  verifyCachedHelper,
  verifyHelperManifest,
  type HelperEntry,
  type HelperManifest,
} from '@hn/release';
import { withTempDir } from '@hn/testkit';

const signer = generateKeyPairSync('ed25519');
const stranger = generateKeyPairSync('ed25519');
const pem = (key: typeof signer.publicKey): string => key.export({ type: 'spki', format: 'pem' }).toString();
const pinned = new Map([['rel-1', pem(signer.publicKey)]]);
const VERSION = '0.9.0';
const PLATFORM = 'linux-x64';
const CREATED = '2026-11-18T00:00:00.000Z';

const binaries = [
  { platform: 'linux-x64', data: randomBytes(5000) },
  { platform: 'win32-x64', data: randomBytes(7000) },
  { platform: 'darwin-arm64', data: randomBytes(6000) },
];

function signed(version = VERSION, list = binaries, key = signer.privateKey): { manifest: HelperManifest; bytes: Buffer; signature: { keyId: string; signature: string } } {
  const manifest = buildHelperManifest(list, { version, created: CREATED });
  return { manifest, bytes: helperManifestBytes(manifest), signature: signHelperManifest(manifest, 'rel-1', key) };
}

describe('the helper manifest', () => {
  it('lists each platform with its size and hash under names that are never paths', () => {
    const { manifest } = signed();
    assert.deepEqual(Object.keys(manifest.binaries), ['darwin-arm64', 'linux-x64', 'win32-x64']);
    assert.equal(manifest.binaries['win32-x64']?.file, 'hn-sandbox-0.9.0-win32-x64.exe');
    assert.equal(manifest.binaries['linux-x64']?.size, 5000);
    assert.equal(helperAssetName('0.9.0', 'darwin-arm64'), 'hn-sandbox-0.9.0-darwin-arm64');
    assert.throws(() => buildHelperManifest([{ platform: '../x', data: Buffer.from('a') }], { version: VERSION, created: CREATED }), /not a platform/);
    assert.throws(() => buildHelperManifest([{ platform: 'linux-x64', data: Buffer.from('a') }, { platform: 'linux-x64', data: Buffer.from('b') }], { version: VERSION, created: CREATED }), /twice/);
    assert.throws(() => buildHelperManifest([], { version: VERSION, created: CREATED }), /at least one/);
    assert.throws(() => buildHelperManifest([{ platform: 'linux-x64', data: Buffer.alloc(0) }], { version: VERSION, created: CREATED }), /impossible size/);
    assert.throws(() => buildHelperManifest(binaries, { version: '0.9', created: CREATED }), /three whole numbers/);
  });

  it('verifies against the pinned key and refuses a missing, unknown, foreign or broken signature', () => {
    const { bytes, signature } = signed();
    assert.equal(verifyHelperManifest(bytes, signature, pinned, VERSION).version, VERSION);
    assert.throws(() => verifyHelperManifest(bytes, null, pinned, VERSION), /no signature/);
    assert.throws(() => verifyHelperManifest(bytes, { keyId: 'nobody', signature: signature.signature }, pinned, VERSION), /does not trust/);
    assert.throws(() => verifyHelperManifest(bytes, signed(VERSION, binaries, stranger.privateKey).signature, pinned, VERSION), /changed or signed by someone else/);
    assert.throws(() => verifyHelperManifest(bytes, { keyId: 'rel-1', signature: 'AAAA' }, pinned, VERSION), /does not match/);
  });

  it('refuses an edited manifest, even one with only its spacing changed, and one that is not JSON', () => {
    const { manifest, signature } = signed();
    const entry = manifest.binaries['linux-x64'] as HelperEntry;
    const edited = helperManifestBytes({ ...manifest, binaries: { ...manifest.binaries, 'linux-x64': { ...entry, sha256: 'a'.repeat(64) } } });
    assert.throws(() => verifyHelperManifest(edited, signature, pinned, VERSION), /does not match/);
    const spaced = Buffer.from(JSON.stringify(manifest, null, 2));
    assert.throws(() => verifyHelperManifest(spaced, signature, pinned, VERSION), /not in its signed form/);
    assert.throws(() => verifyHelperManifest(Buffer.from('nope'), signature, pinned, VERSION), /not JSON/);
  });

  it('never finds a platform through the object prototype', () => {
    const { manifest } = signed();
    for (const name of ['constructor', 'toString', '__proto__', 'hasOwnProperty', 'darwin-x64']) assert.throws(() => helperEntry(manifest, name), /no hn-sandbox for/, name);
  });

  it('refuses an older or newer manifest than the running version, so an old helper cannot be replayed', () => {
    const old = signed('0.8.0');
    assert.throws(() => verifyHelperManifest(old.bytes, old.signature, pinned, VERSION), /for 0\.8\.0, but this is 0\.9\.0/);
    const next = signed('0.9.1');
    assert.throws(() => verifyHelperManifest(next.bytes, next.signature, pinned, VERSION), /refused/);
  });

  it('refuses a signed manifest whose entries are malformed: a path as a file name, a bad hash, a size out of range', () => {
    const base = signed().manifest;
    for (const change of [{ file: '../../evil.exe' }, { sha256: 'xyz' }, { size: -1 }, { size: 1e12 }]) {
      const bad = { ...base, binaries: { ...base.binaries, 'linux-x64': { ...(base.binaries['linux-x64'] as object), ...change } } } as HelperManifest;
      const bytes = helperManifestBytes(bad);
      const signature = signHelperManifest(bad, 'rel-1', signer.privateKey);
      assert.throws(() => verifyHelperManifest(bytes, signature, pinned, VERSION), /malformed/, JSON.stringify(change));
    }
    const unknown = { ...base, binaries: { 'plan9-x64': base.binaries['linux-x64'] as object } } as unknown as HelperManifest;
    assert.throws(() => verifyHelperManifest(helperManifestBytes(unknown), signHelperManifest(unknown, 'rel-1', signer.privateKey), pinned, VERSION), /not a platform/);
  });
});

describe('installing and re-checking a helper', () => {
  it('writes a verified helper, and verifies it again on every use', async () => {
    await withTempDir(async (home) => {
      const install = { dir: join(home, VERSION), version: VERSION, platform: PLATFORM, pinned };
      const { bytes, signature } = signed();
      const path = await installHelper(install, bytes, signature, binaries[0]?.data as Buffer);
      assert.equal(path, join(home, VERSION, cachedHelperName(PLATFORM)));
      assert.deepEqual(await verifyCachedHelper(install), { ok: true, path });
      assert.deepEqual((await readdir(install.dir)).sort(), ['hn-sandbox', 'manifest.json', 'manifest.sig.json']);
    });
  });

  it('refuses wrong bytes, a wrong size and a platform the release lacks, and leaves nothing under the final name', async () => {
    await withTempDir(async (home) => {
      const { bytes, signature } = signed();
      const install = { dir: join(home, VERSION), version: VERSION, platform: PLATFORM, pinned };
      const flipped = Buffer.from(binaries[0]?.data as Buffer);
      flipped[100] = (flipped[100] as number) ^ 1;
      await assert.rejects(installHelper(install, bytes, signature, flipped), /does not match its signed SHA-256/);
      await assert.rejects(installHelper(install, bytes, signature, flipped.subarray(0, 4999)), /bytes, but the signed manifest says 5000/);
      await assert.rejects(installHelper({ ...install, platform: 'linux-arm64' }, bytes, signature, flipped), /no hn-sandbox for linux-arm64/);
      await assert.rejects(installHelper(install, bytes, signed(VERSION, binaries, stranger.privateKey).signature, binaries[0]?.data as Buffer), /someone else/);
      await assert.rejects(readdir(install.dir), /ENOENT/);
    });
  });

  it('refuses a cached helper that was swapped or edited after the download, and a manifest swapped for another key', async () => {
    await withTempDir(async (home) => {
      const install = { dir: join(home, VERSION), version: VERSION, platform: PLATFORM, pinned };
      const { bytes, signature } = signed();
      const path = await installHelper(install, bytes, signature, binaries[0]?.data as Buffer);
      await writeFile(path, Buffer.concat([binaries[0]?.data as Buffer, Buffer.from('x')]));
      const swapped = await verifyCachedHelper(install);
      assert.equal(swapped.ok, false);
      assert.match(swapped.ok ? '' : swapped.detail, /bytes, but the signed manifest says/);
      await writeFile(path, binaries[0]?.data as Buffer);
      assert.equal((await verifyCachedHelper(install)).ok, true);
      await writeFile(join(install.dir, 'manifest.sig.json'), JSON.stringify(signed(VERSION, binaries, stranger.privateKey).signature));
      const resigned = await verifyCachedHelper(install);
      assert.equal(resigned.ok, false);
      assert.match(resigned.ok ? '' : resigned.detail, /someone else/);
      assert.equal((await verifyCachedHelper({ ...install, dir: join(home, 'nothing') })).ok, false);
    });
  });
});

describe('bounded downloads', () => {
  it('follows only https, or http to this machine, and never an address with credentials', () => {
    assert.equal(allowedDownloadUrl(new URL('https://github.com/x')), true);
    assert.equal(allowedDownloadUrl(new URL('http://127.0.0.1:8080/x')), true);
    assert.equal(allowedDownloadUrl(new URL('http://localhost/x')), true);
    assert.equal(allowedDownloadUrl(new URL('http://[::1]/x')), true);
    for (const bad of ['http://github.com/x', 'http://127.0.0.1.evil.com/x', 'ftp://127.0.0.1/x', 'file:///etc/passwd', 'https://user:pw@github.com/x', 'http://user@127.0.0.1/x']) assert.equal(allowedDownloadUrl(new URL(bad)), false, bad);
  });

  const reply = (body: Buffer | string | ReadableStream<Uint8Array>, init: ResponseInit = {}): Response => new Response(body, init);

  it('refuses a redirect to plain http, too many redirects, an oversize body (declared or streamed) and a bad status', async () => {
    await assert.rejects(fetchBounded('https://example.test/a', 100, { fetch: async () => reply('', { status: 302, headers: { location: 'http://example.test/b' } }) }), /only https/);
    let hops = 0;
    await assert.rejects(
      fetchBounded('https://example.test/a', 100, {
        fetch: async () => {
          hops += 1;
          return reply('', { status: 302, headers: { location: '/again' } });
        },
      }),
      /Too many redirects/,
    );
    assert.equal(hops, MAX_REDIRECTS + 1, 'it must stop after the cap, not after some larger number of requests');
    await assert.rejects(fetchBounded('https://example.test/a', 100, { fetch: async () => reply('', { status: 302 }) }), /redirected nowhere/);
    await assert.rejects(fetchBounded('https://example.test/a', 100, { fetch: async () => reply(Buffer.alloc(500), { headers: { 'content-length': '500' } }) }), /larger than the 100 bytes/);
    // 50 chunks of 60 bytes, not an endless stream: with no cap this must fail at once, not loop until memory runs out.
    let pulled = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        if (pulled > 50) controller.close();
        else controller.enqueue(new Uint8Array(60));
      },
    });
    await assert.rejects(fetchBounded('https://example.test/a', 100, { fetch: async () => reply(stream) }), /larger than the 100 bytes/);
    assert.ok(pulled < 10, `the body was still being read long after the cap (${pulled} chunks)`);
    await assert.rejects(fetchBounded('https://example.test/a', 100, { fetch: async () => reply('no', { status: 404 }) }), /answered 404/);
    await assert.rejects(fetchBounded('not an address', 100), /not an address/);
    await assert.rejects(
      fetchBounded('https://example.test/a', 100, {
        fetch: async () => {
          throw new Error('offline');
        },
      }),
      /Could not fetch.*offline/,
    );
    assert.equal(MAX_REDIRECTS, 5);
  });

  it('refuses a body whose declared length is too big before reading a single byte of it', async () => {
    let reads = 0;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          reads += 1;
          controller.enqueue(new Uint8Array(10));
        },
      },
      { highWaterMark: 0 },
    );
    await assert.rejects(fetchBounded('https://example.test/a', 100, { fetch: async () => reply(stream, { headers: { 'content-length': '500' } }) }), /larger than the 100 bytes/);
    assert.equal(reads, 0, 'the body was read although its declared size was already too big');
  });

  it('follows a normal redirect chain over https to the end', async () => {
    const seen: string[] = [];
    const body = await fetchBounded('https://a.test/x', 100, {
      fetch: async (input) => {
        const url = String(input);
        seen.push(url);
        return url === 'https://a.test/x' ? reply('', { status: 302, headers: { location: 'https://cdn.test/y' } }) : reply('payload');
      },
    });
    assert.equal(body.toString(), 'payload');
    assert.deepEqual(seen, ['https://a.test/x', 'https://cdn.test/y']);
  });
});

/** A release folder served over loopback http: a mirror, which is how the download is exercised end to end. */
async function serve(files: Map<string, Buffer>, onRequest?: (path: string) => void, extra?: (req: IncomingMessage, res: ServerResponse) => boolean): Promise<{ url: string; server: Server }> {
  const server = createServer((req, res) => {
    onRequest?.(req.url ?? '');
    if (extra?.(req, res) === true) return;
    const data = files.get((req.url ?? '').slice(1));
    if (data === undefined) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-length': data.length }).end(data);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
}

const closeServer = (server: Server): Promise<void> =>
  new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });

function release(list = binaries, key = signer.privateKey): Map<string, Buffer> {
  const { bytes, signature } = signed(VERSION, list, key);
  const files = new Map<string, Buffer>([
    [helperManifestName(VERSION), bytes],
    [helperSignatureName(VERSION), Buffer.from(JSON.stringify(signature))],
  ]);
  for (const { platform, data } of list) files.set(helperAssetName(VERSION, platform), data);
  return files;
}

describe('the helper download', () => {
  it('fetches the manifest first, then the one binary for this platform, and installs it verified', async () => {
    await withTempDir(async (home) => {
      const asked: string[] = [];
      const { url, server } = await serve(release(), (path) => asked.push(path));
      try {
        const path = await downloadHelper({ baseUrl: `${url}/`, dir: join(home, VERSION), version: VERSION, platform: PLATFORM, pinned });
        assert.deepEqual(await readFile(path), binaries[0]?.data);
        assert.ok(asked.includes(`/${helperAssetName(VERSION, PLATFORM)}`));
        assert.ok(!asked.includes(`/${helperAssetName(VERSION, 'win32-x64')}`), 'only this platform is downloaded');
      } finally {
        await closeServer(server);
      }
    });
  });

  it('refuses a swapped binary, a release signed by another key and a missing platform, and never asks for the binary after a bad manifest', async () => {
    await withTempDir(async (home) => {
      const install = { dir: join(home, VERSION), version: VERSION, platform: PLATFORM, pinned };
      const swapped = release();
      swapped.set(helperAssetName(VERSION, PLATFORM), randomBytes(5000));
      const one = await serve(swapped);
      try {
        await assert.rejects(downloadHelper({ ...install, baseUrl: one.url }), /does not match its signed SHA-256/);
      } finally {
        await closeServer(one.server);
      }
      const asked: string[] = [];
      const two = await serve(release(binaries, stranger.privateKey), (path) => asked.push(path));
      try {
        await assert.rejects(downloadHelper({ ...install, baseUrl: two.url }), /someone else/);
        assert.ok(!asked.some((path) => path.includes('hn-sandbox-0.9.0-linux')), 'the binary was never requested');
      } finally {
        await closeServer(two.server);
      }
      const three = await serve(release(binaries.filter((entry) => entry.platform !== PLATFORM)));
      try {
        await assert.rejects(downloadHelper({ ...install, baseUrl: three.url }), /no hn-sandbox for linux-x64/);
      } finally {
        await closeServer(three.server);
      }
      await assert.rejects(readdir(install.dir), /ENOENT/);
    });
  });

  it('refuses a server that sends more than the signed size, and a cut connection, leaving nothing behind', async () => {
    await withTempDir(async (home) => {
      const install = { dir: join(home, VERSION), version: VERSION, platform: PLATFORM, pinned };
      const files = release();
      const binaryName = helperAssetName(VERSION, PLATFORM);
      const big = await serve(files, undefined, (req, res) => {
        if (req.url !== `/${binaryName}`) return false;
        res.writeHead(200).end(Buffer.alloc(50_000, 1));
        return true;
      });
      try {
        await assert.rejects(downloadHelper({ ...install, baseUrl: big.url }), /larger than the 5000 bytes/);
      } finally {
        await closeServer(big.server);
      }
      const cut = await serve(files, undefined, (req, res) => {
        if (req.url !== `/${binaryName}`) return false;
        res.writeHead(200, { 'content-length': 5000 });
        res.write(Buffer.alloc(100));
        setTimeout(() => res.destroy(), 20);
        return true;
      });
      try {
        await assert.rejects(downloadHelper({ ...install, baseUrl: cut.url }));
      } finally {
        await closeServer(cut.server);
      }
      await assert.rejects(readdir(install.dir), /ENOENT/);
    });
  });

  it('refuses a mirror that redirects the binary to a plain-http address that is not this machine', async () => {
    await withTempDir(async (home) => {
      const files = release();
      const { url, server } = await serve(files, undefined, (req, res) => {
        if (req.url !== `/${helperAssetName(VERSION, PLATFORM)}`) return false;
        res.writeHead(302, { location: 'http://evil.example/hn-sandbox' }).end();
        return true;
      });
      try {
        await assert.rejects(downloadHelper({ baseUrl: url, dir: join(home, VERSION), version: VERSION, platform: PLATFORM, pinned }), /only https/);
      } finally {
        await closeServer(server);
      }
    });
  });
});

describe('npm integrity strings', () => {
  it('accept the bytes they describe and refuse anything else', () => {
    const bytes = randomBytes(500);
    const good = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
    assert.equal(checkNpmIntegrity(bytes, good), true);
    assert.equal(checkNpmIntegrity(bytes, `sha256-${createHash('sha256').update(bytes).digest('base64')}`), true);
    const changed = Buffer.from(bytes);
    changed[0] = (changed[0] as number) ^ 1;
    assert.equal(checkNpmIntegrity(changed, good), false);
    for (const bad of ['', 'sha512-', 'md5-AAAA', good.slice(0, -4), `${good}AAAA`, 'sha512-not base64!!']) assert.equal(checkNpmIntegrity(bytes, bad), false, bad);
  });
});
