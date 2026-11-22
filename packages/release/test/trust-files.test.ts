import assert from 'node:assert/strict';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { trustFiles } from '@hn/release';
import { signRoster } from '@hn/security';
import { withTempDir } from '@hn/testkit';

const pair = (): { priv: KeyObject; pem: string } => {
  const made = generateKeyPairSync('ed25519');
  return { priv: made.privateKey, pem: made.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};
const root = pair();
const rel = pair();
const rel2 = pair();

const rosterBody = (extra: Record<string, unknown> = {}, purpose = 'release'): Record<string, unknown> => ({
  format: 1,
  purpose,
  serial: 1,
  issued: '2026-11-22T00:00:00Z',
  keys: [{ keyId: 'rel-1', publicKey: rel.pem }, { keyId: 'rel-2', publicKey: rel2.pem }],
  revoked: [],
  ...extra,
});

async function setup(dir: string, body: Record<string, unknown>, by = root.priv, id = 'root-1'): Promise<{ root: string; roster: string }> {
  await writeFile(join(dir, 'root.pem'), root.pem);
  await writeFile(join(dir, 'roster.json'), JSON.stringify(signRoster(body, id, by)));
  return { root: join(dir, 'root.pem'), roster: join(dir, 'roster.json') };
}

describe('the trust files a release ships', () => {
  it('adds nothing for a release without a root, and refuses a half-given set', async () => {
    assert.deepEqual(await trustFiles({ keyId: 'rel-1', publicPem: rel.pem }), []);
    await assert.rejects(trustFiles({ keyId: 'rel-1', publicPem: rel.pem, root: 'x' }), /go together/);
  });

  it('ships the root and the signed roster when they agree with the release key', async () => {
    await withTempDir(async (dir) => {
      const made = await setup(dir, rosterBody());
      const files = await trustFiles({ keyId: 'rel-1', publicPem: rel.pem, root: made.root, rootId: 'root-1', roster: made.roster });
      assert.deepEqual(files.map((file) => file.path), ['RELEASE-ROOT.json', 'RELEASE-ROSTER.json']);
      assert.equal((JSON.parse(files[0]?.data.toString() ?? '') as { keyId: string }).keyId, 'root-1');
    });
  });

  it('refuses a roster that would make the release refuse itself, or that is not what it says', async () => {
    await withTempDir(async (dir) => {
      const input = (made: { root: string; roster: string }, extra: Record<string, unknown> = {}) => ({ keyId: 'rel-1', publicPem: rel.pem, root: made.root, rootId: 'root-1', roster: made.roster, ...extra });
      await assert.rejects(trustFiles(input(await setup(dir, rosterBody({ keys: [{ keyId: 'rel-2', publicKey: rel2.pem }] })))), /does not list this release's signing key/);
      await assert.rejects(trustFiles(input(await setup(dir, rosterBody({ revoked: [{ keyId: 'rel-1', reason: 'x' }] })))), /revokes "rel-1"/);
      await assert.rejects(trustFiles(input(await setup(dir, rosterBody({}, 'policy')))), /policy roster/);
      await assert.rejects(trustFiles(input(await setup(dir, rosterBody()), { rootId: 'root-9' })), /not "root-9"/);
      await assert.rejects(trustFiles(input(await setup(dir, rosterBody(), rel.priv))), /signature does not match/);
    });
  });
});
