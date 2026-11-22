import assert from 'node:assert/strict';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { RosterError, TrustRecordError, activeKeys, loadTrust, offerRoster, readTrustRecord, signRoster, type TrustSource } from '@hn/security';

const pair = (): { priv: KeyObject; pem: string } => {
  const made = generateKeyPairSync('ed25519');
  return { priv: made.privateKey, pem: made.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};
const root = pair();
const k1 = pair();
const k2 = pair();
const key = Buffer.from('machine-log-key');
const source = (extra: Partial<TrustSource> = {}): TrustSource => ({ purpose: 'release', root: { keyId: 'root-1', publicKey: root.pem }, pins: { k1: k1.pem }, ...extra });
const roster = (serial: number, keys: Record<string, string>, revoked: string[] = []): ReturnType<typeof signRoster> =>
  signRoster({ format: 1, purpose: 'release', serial, issued: '2026-11-22T00:00:00Z', keys: Object.entries(keys).map(([keyId, publicKey]) => ({ keyId, publicKey })), revoked: revoked.map((keyId) => ({ keyId, reason: 'leaked' })) }, 'root-1', root.priv);

let dir = '';
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'hn-trust-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('the trust record', () => {
  it('starts from the pinned keys and writes a record', async () => {
    const state = await loadTrust(dir, key, source());
    assert.deepEqual([...activeKeys(state).keys()], ['k1']);
    assert.equal((await readTrustRecord(dir, 'release', key))?.serial, 0);
  });

  it('applies a roster, keeps it across a restart, and the package pins cannot undo a revoke', async () => {
    await offerRoster(dir, key, source(), roster(1, { k1: k1.pem, k2: k2.pem }));
    await offerRoster(dir, key, source(), roster(2, { k2: k2.pem }, ['k1']));
    const later = await loadTrust(dir, key, source());
    assert.deepEqual([...activeKeys(later).keys()], ['k2']);
    assert.equal(later.serial, 2);
  });

  it('a shipped roster is applied when newer, ignored when older', async () => {
    const first = await loadTrust(dir, key, source({ shipped: roster(3, { k2: k2.pem }) }));
    assert.deepEqual([...activeKeys(first).keys()], ['k2']);
    const second = await loadTrust(dir, key, source({ shipped: roster(1, { k1: k1.pem }) }));
    assert.equal(second.serial, 3);
    assert.deepEqual([...activeKeys(second).keys()], ['k2']);
  });

  it('a refused roster leaves the record as it was', async () => {
    await offerRoster(dir, key, source(), roster(2, { k1: k1.pem, k2: k2.pem }));
    await assert.rejects(offerRoster(dir, key, source(), roster(1, { k1: k1.pem })), RosterError);
    assert.equal((await readTrustRecord(dir, 'release', key))?.serial, 2);
  });

  it('attack: trust_record_edited - refuses an edited record instead of falling back to the package keys', async () => {
    await offerRoster(dir, key, source(), roster(1, { k2: k2.pem }, ['k1']));
    const path = join(dir, 'release.trust.json');
    const record = JSON.parse(await readFile(path, 'utf8')) as { state: { revoked: Record<string, unknown> } };
    record.state.revoked = {};
    await writeFile(path, JSON.stringify(record));
    await assert.rejects(loadTrust(dir, key, source()), TrustRecordError);
  });

  it('refuses a record under another machine key, a truncated file and a file for another purpose', async () => {
    await loadTrust(dir, key, source());
    await assert.rejects(loadTrust(dir, Buffer.from('other-machine'), source()), TrustRecordError);
    const path = join(dir, 'release.trust.json');
    const text = await readFile(path, 'utf8');
    await writeFile(path, text.slice(0, 20));
    await assert.rejects(loadTrust(dir, key, source()), /not valid JSON/);
    await writeFile(path, JSON.stringify({ state: { purpose: 'policy' }, mac: 'aa' }));
    await assert.rejects(loadTrust(dir, key, source()), /is for policy/);
  });

  it('a package that pins a different root is a re-pin and keeps every revocation', async () => {
    await offerRoster(dir, key, source(), roster(1, { k2: k2.pem }, ['k1']));
    const root2 = pair();
    const again = await loadTrust(dir, key, source({ root: { keyId: 'root-9', publicKey: root2.pem }, pins: { k1: k1.pem, k2: k2.pem } }));
    assert.equal(again.root.keyId, 'root-9');
    assert.deepEqual([...activeKeys(again).keys()], ['k2']);
  });

  it('a root that moved on by successor is still the same machine', async () => {
    const next = pair();
    const moved = signRoster({ format: 1, purpose: 'release', serial: 1, issued: '2026-11-22T00:00:00Z', keys: [{ keyId: 'k1', publicKey: k1.pem }], revoked: [], successor: { keyId: 'root-2', publicKey: next.pem } }, 'root-1', root.priv);
    await offerRoster(dir, key, source(), moved);
    const again = await loadTrust(dir, key, source());
    assert.equal(again.root.keyId, 'root-2');
  });
});
