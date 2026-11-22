import assert from 'node:assert/strict';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { gzipSync } from 'node:zlib';
import { MANIFEST_PATH, buildManifest, manifestBytes, signManifest, verifyHelperManifest, verifyInstalledTree, writeTar, buildHelperManifest, helperManifestBytes, signHelperManifest } from '@hn/release';
import { RosterError, TrustRecordError, signRoster } from '@hn/security';
import { readReleaseInfo, runTrustCommand, runUpdateCommand } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

const pair = (): { priv: KeyObject; pem: string } => {
  const made = generateKeyPairSync('ed25519');
  return { priv: made.privateKey, pem: made.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};
const root = pair();
const rel1 = pair();
const rel2 = pair();
const PLATFORM = `${process.platform}-${process.arch}`;

const roster = (serial: number, keys: Record<string, string>, revoked: string[] = [], purpose = 'release', by = root.priv, id = 'root-1') =>
  signRoster({ format: 1, purpose, serial, issued: '2026-11-22T00:00:00Z', keys: Object.entries(keys).map(([keyId, publicKey]) => ({ keyId, publicKey })), revoked: revoked.map((keyId) => ({ keyId, reason: 'leaked' })) }, id, by);

/** An installed release root (version 0.8.0) that pins `root` and the key rel-1, with or without a root. */
async function installed(dir: string, withRoot = true): Promise<{ env: NodeJS.ProcessEnv; home: string; pkg: string }> {
  const pkg = join(dir, 'pkg');
  const home = join(dir, 'home');
  await mkdir(pkg, { recursive: true });
  await mkdir(home, { recursive: true });
  await writeFile(join(pkg, 'manifest.json'), JSON.stringify({ version: '0.8.0' }));
  await writeFile(join(pkg, 'RELEASE-KEY.json'), JSON.stringify({ 'rel-1': rel1.pem }));
  if (withRoot) await writeFile(join(pkg, 'RELEASE-ROOT.json'), JSON.stringify({ keyId: 'root-1', publicKey: root.pem }));
  return { env: { HN_RELEASE_ROOT: pkg, HN_HOME: home }, home, pkg };
}

/** A signed release archive for this platform, written with its signature beside it. */
async function writeArchive(dir: string, version: string, keyId: string, key: KeyObject): Promise<string> {
  const files = [{ path: 'bin/hn.mjs', data: Buffer.from('// hn'), executable: true }, { path: 'lib/a.js', data: Buffer.from('export {};') }];
  const manifest = buildManifest(files, { name: 'haven-harness', version, platform: PLATFORM, created: '2026-11-22T00:00:00.000Z' });
  const tgz = join(dir, `haven-harness-${version}.tgz`);
  await writeFile(tgz, gzipSync(writeTar([...files, { path: MANIFEST_PATH, data: manifestBytes(manifest) }])));
  await writeFile(join(dir, `haven-harness-${version}.sig.json`), JSON.stringify(signManifest(manifest, keyId, key)));
  return tgz;
}

const trust = async (env: NodeJS.ProcessEnv, ...rest: string[]): Promise<{ code: number | null; text: string }> => {
  let text = '';
  const code = await runTrustCommand({ positionals: ['trust', ...rest], env, out: (chunk) => void (text += chunk) });
  return { code, text };
};
const update = async (home: string, env: NodeJS.ProcessEnv, source: string, rosterFile?: string): Promise<string> => {
  let text = '';
  await runUpdateCommand({ positionals: ['update', source], ...(rosterFile === undefined ? {} : { roster: rosterFile }), home, logKey: join(home, 'log.key'), env, out: (chunk) => void (text += chunk) });
  return text;
};

describe('hn trust: making and signing a roster', () => {
  it('makes a root key, signs a draft whose keys are files, and the result verifies', async () => {
    await withTempDir(async (dir) => {
      const made = await trust({}, 'keygen-root', join(dir, 'root'));
      assert.match(made.text, /Suggested root key id: root-[0-9a-f]{16}/);
      await assert.rejects(trust({}, 'keygen-root', join(dir, 'root')), /EEXIST/);
      await writeFile(join(dir, 'rel-2.pub.pem'), rel2.pem);
      await writeFile(join(dir, 'draft.json'), JSON.stringify({ purpose: 'release', serial: 1, keys: [{ keyId: 'rel-1', publicKey: rel1.pem }, { keyId: 'rel-2', publicKeyFile: 'rel-2.pub.pem' }] }));
      const out = join(dir, 'roster.json');
      const signed = await trust({}, 'sign', join(dir, 'draft.json'), join(dir, 'root', 'root-key.pem'), 'root-x', out);
      assert.match(signed.text, /Signed a release roster, serial 1, with 2 key\(s\)/);
      const body = JSON.parse(await readFile(out, 'utf8')) as { rootKeyId: string; roster: { keys: { publicKey: string }[] } };
      assert.equal(body.rootKeyId, 'root-x');
      assert.match(body.roster.keys[1]?.publicKey ?? '', /BEGIN PUBLIC KEY/);
    });
  });

  it('will not sign a roster that is malformed', async () => {
    await withTempDir(async (dir) => {
      await trust({}, 'keygen-root', join(dir, 'root'));
      await writeFile(join(dir, 'draft.json'), JSON.stringify({ purpose: 'release', serial: 0, keys: [{ keyId: 'a', publicKey: rel1.pem }] }));
      await assert.rejects(trust({}, 'sign', join(dir, 'draft.json'), join(dir, 'root', 'root-key.pem'), 'r', join(dir, 'o.json')), RosterError);
    });
  });
});

describe('hn trust: a release follows rosters', () => {
  it('shows the pinned keys, then a rotation, then a revoke, each applied by hn trust update', async () => {
    await withTempDir(async (dir) => {
      const { env } = await installed(dir);
      const before = await trust(env, 'show');
      assert.equal(before.code, 0);
      assert.match(before.text, /trusted: rel-1/);
      assert.match(before.text, /no roster applied yet/);
      await writeFile(join(dir, 'r1.json'), JSON.stringify(roster(1, { 'rel-1': rel1.pem, 'rel-2': rel2.pem })));
      const added = await trust(env, 'update', join(dir, 'r1.json'));
      assert.match(added.text, /Applied the release roster \(serial 1\)/);
      assert.match(added.text, /trusted: rel-2/);
      assert.equal((await trust(env, 'update', join(dir, 'r1.json'))).text.startsWith('The release roster (serial 1) was already in force'), true);
      await writeFile(join(dir, 'r2.json'), JSON.stringify(roster(2, { 'rel-2': rel2.pem }, ['rel-1'])));
      const revoked = await trust(env, 'update', join(dir, 'r2.json'));
      assert.match(revoked.text, /REVOKED: rel-1: leaked/);
      assert.doesNotMatch(revoked.text, /trusted: rel-1/);
      const info = await readReleaseInfo(env);
      assert.deepEqual([...(info?.pinned.keys() ?? [])], ['rel-2']);
      assert.ok(info?.revoked.has('rel-1'));
    });
  });

  it('refuses a roster signed by a signing key, an older roster, and one for a purpose it cannot hold', async () => {
    await withTempDir(async (dir) => {
      const { env } = await installed(dir);
      await writeFile(join(dir, 'forged.json'), JSON.stringify(roster(5, { 'rel-1': rel1.pem, 'rel-2': rel2.pem }, [], 'release', rel1.priv, 'rel-1')));
      await assert.rejects(trust(env, 'update', join(dir, 'forged.json')), /not the root this machine pins/);
      await writeFile(join(dir, 'new.json'), JSON.stringify(roster(3, { 'rel-1': rel1.pem, 'rel-2': rel2.pem })));
      await trust(env, 'update', join(dir, 'new.json'));
      await writeFile(join(dir, 'old.json'), JSON.stringify(roster(2, { 'rel-1': rel1.pem })));
      await assert.rejects(trust(env, 'update', join(dir, 'old.json')), /older than serial 3/);
      await writeFile(join(dir, 'policy.json'), JSON.stringify(roster(1, { p: rel1.pem }, [], 'policy')));
      await assert.rejects(trust(env, 'update', join(dir, 'policy.json')), /not logged in to a team broker/);
      await writeFile(join(dir, 'junk.json'), '{"hello":1}');
      await assert.rejects(trust(env, 'update', join(dir, 'junk.json')), /not a signed roster/);
      assert.deepEqual([...((await readReleaseInfo(env))?.pinned.keys() ?? [])].sort(), ['rel-1', 'rel-2']);
    });
  });

  it('a release without a root behaves as before and cannot take a roster', async () => {
    await withTempDir(async (dir) => {
      const { env, home } = await installed(dir, false);
      const info = await readReleaseInfo(env);
      assert.equal(info?.trust, null);
      assert.deepEqual([...(info?.pinned.keys() ?? [])], ['rel-1']);
      await assert.rejects(trust(env, 'update', join(dir, 'none.json')), /ENOENT/);
      await writeFile(join(dir, 'r.json'), JSON.stringify(roster(1, { 'rel-1': rel1.pem })));
      await assert.rejects(trust(env, 'update', join(dir, 'r.json')), /pins no root key/);
      const tgz = await writeArchive(dir, '0.9.0', 'rel-1', rel1.priv);
      await assert.rejects(update(home, env, tgz, join(dir, 'r.json')), /pins no root/);
      assert.match(await update(home, env, tgz), /Installed haven-harness 0\.9\.0/);
    });
  });

  it('a damaged trust record stops everything instead of falling back to the package keys', async () => {
    await withTempDir(async (dir) => {
      const { env, home } = await installed(dir);
      await writeFile(join(dir, 'r1.json'), JSON.stringify(roster(1, { 'rel-2': rel2.pem }, ['rel-1'])));
      await trust(env, 'update', join(dir, 'r1.json'));
      const path = join(home, 'trust', 'release.trust.json');
      const record = JSON.parse(await readFile(path, 'utf8')) as { state: { revoked: Record<string, unknown> } };
      record.state.revoked = {};
      await writeFile(path, JSON.stringify(record));
      await assert.rejects(readReleaseInfo(env), TrustRecordError);
      await assert.rejects(trust(env, 'show'), TrustRecordError);
    });
  });
});

describe('a rotation and a revocation reach hn update, the installed tree and the helper', () => {
  it('rotation: an archive signed by the new key installs once the roster sits beside it', async () => {
    await withTempDir(async (dir) => {
      const { env, home } = await installed(dir);
      const tgz = await writeArchive(dir, '0.9.0', 'rel-2', rel2.priv);
      await assert.rejects(update(home, env, tgz), /does not trust/);
      await writeFile(join(dir, 'haven-harness-0.9.0.roster.json'), JSON.stringify(roster(1, { 'rel-1': rel1.pem, 'rel-2': rel2.pem })));
      const text = await update(home, env, tgz);
      assert.match(text, /Applied the release key roster \(serial 1\)/);
      assert.match(text, /Installed haven-harness 0\.9\.0/);
    });
  });

  it('a roster beside the archive that is forged stops the update, and an explicit missing roster is an error', async () => {
    await withTempDir(async (dir) => {
      const { env, home } = await installed(dir);
      const tgz = await writeArchive(dir, '0.9.0', 'rel-2', rel2.priv);
      await writeFile(join(dir, 'haven-harness-0.9.0.roster.json'), JSON.stringify(roster(1, { 'rel-1': rel1.pem, 'rel-2': rel2.pem }, [], 'release', rel2.priv, 'rel-2')));
      await assert.rejects(update(home, env, tgz), RosterError);
      await assert.rejects(update(home, env, tgz, join(dir, 'missing.json')), /ENOENT/);
    });
  });

  it('attack: revoked_release_key_refused - the revoked key signs an archive, an installed tree and a helper manifest, and all three are refused', async () => {
    await withTempDir(async (dir) => {
      const { env, home, pkg } = await installed(dir);
      // An installed tree signed by rel-1, which passes today.
      const files = [{ path: 'bin/hn.mjs', data: Buffer.from('// hn') }, { path: 'RELEASE-KEY.json', data: await readFile(join(pkg, 'RELEASE-KEY.json')) }, { path: 'RELEASE-ROOT.json', data: await readFile(join(pkg, 'RELEASE-ROOT.json')) }];
      await mkdir(join(pkg, 'bin'), { recursive: true });
      await mkdir(join(pkg, 'node_modules', '@hn'), { recursive: true });
      await writeFile(join(pkg, 'bin', 'hn.mjs'), files[0]?.data ?? '');
      const manifest = buildManifest(files, { name: 'haven-harness', version: '0.8.0', platform: PLATFORM, created: '2026-11-22T00:00:00.000Z' });
      await writeFile(join(pkg, MANIFEST_PATH), manifestBytes(manifest));
      await writeFile(join(pkg, 'manifest.sig.json'), JSON.stringify(signManifest(manifest, 'rel-1', rel1.priv)));
      const helper = buildHelperManifest([{ platform: PLATFORM, data: Buffer.from('helper') }], { version: '0.8.0', created: '2026-11-22T00:00:00.000Z' });
      const helperSig = signHelperManifest(helper, 'rel-1', rel1.priv);
      const before = await readReleaseInfo(env);
      const good = await verifyInstalledTree(pkg, { keys: before?.pinned ?? new Map(), revoked: before?.revoked ?? new Set() });
      assert.equal(good.ok, true, good.problems.join('; '));
      assert.equal(verifyHelperManifest(helperManifestBytes(helper), helperSig, before?.pinned ?? new Map(), '0.8.0').version, '0.8.0');
      const tgz = await writeArchive(dir, '0.9.0', 'rel-1', rel1.priv);

      await writeFile(join(dir, 'revoke.json'), JSON.stringify(roster(1, { 'rel-2': rel2.pem }, ['rel-1'])));
      await trust(env, 'update', join(dir, 'revoke.json'));

      const after = await readReleaseInfo(env);
      const tree = await verifyInstalledTree(pkg, { keys: after?.pinned ?? new Map(), revoked: after?.revoked ?? new Set() });
      assert.equal(tree.ok, false);
      assert.match(tree.problems.join(' '), /which has been revoked/);
      assert.throws(() => verifyHelperManifest(helperManifestBytes(helper), helperSig, after?.pinned ?? new Map(), '0.8.0'), /does not trust/);
      await assert.rejects(update(home, env, tgz), /does not trust/);
    });
  });
});
