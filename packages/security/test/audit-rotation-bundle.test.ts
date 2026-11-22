import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { describe, it } from 'node:test';
import { AuditChain, auditKeyId, buildExport, checkpointStanding, signCheckpoint, verifyBundle, type AuditEntry, type AuditKeyWindow, type Checkpoint } from '@hn/security';

/** Audit checkpoints across a key rotation and a revocation (Phase 15, task 6). */

const HMAC = randomBytes(32);
const pem = (key: KeyObject): string => createPublicKey(key).export({ type: 'spki', format: 'pem' }).toString();
const old = generateKeyPairSync('ed25519');
const fresh = generateKeyPairSync('ed25519');
const stranger = generateKeyPairSync('ed25519');
const OLD_ID = auditKeyId(createPublicKey(old.privateKey));
const NEW_ID = auditKeyId(createPublicKey(fresh.privateKey));

function chain(count: number): AuditEntry[] {
  let tick = 0;
  const made = new AuditChain({ key: HMAC, now: () => new Date(Date.UTC(2026, 10, 22, 0, 0, (tick += 1))) });
  return Array.from({ length: count }, (_, index) => made.append(index % 2 === 0 ? 'broker/model' : 'broker/session', { user: `u${index % 3}`, n: index }));
}

const at = (rows: readonly AuditEntry[], n: number, key: KeyObject): Checkpoint => signCheckpoint(rows[n - 1] as AuditEntry, '2026-11-22T01:00:00.000Z', key);
const windows = (oldTo: number): AuditKeyWindow[] => [
  { keyId: OLD_ID, publicKey: pem(old.privateKey), from: 0, to: oldTo },
  { keyId: NEW_ID, publicKey: pem(fresh.privateKey), from: oldTo + 1, to: Number.MAX_SAFE_INTEGER },
];
const exportOf = (rows: readonly AuditEntry[], cps: readonly Checkpoint[]) => buildExport(rows, cps, 'auditor@example.com', '2026-11-22T01:00:00.000Z');
const edit = <T>(value: T, change: (copy: any) => void): T => {
  const copy = JSON.parse(JSON.stringify(value));
  change(copy);
  return copy as T;
};

describe('an export that spans a key rotation', () => {
  const rows = chain(10);
  const spanning = exportOf(rows, [at(rows, 5, old.privateKey), at(rows, 10, fresh.privateKey)]);

  it('verifies when each checkpoint is inside its key window', () => {
    const result = verifyBundle(spanning, { hmacKey: HMAC, windows: windows(5) });
    assert.equal(result.ok, true, result.reason ?? '');
    assert.equal(result.checkpointsChecked, 2);
  });

  it('an export that ends in the old era verifies with the old key alone', () => {
    const early = exportOf(rows.slice(0, 5), [at(rows, 5, old.privateKey)]);
    assert.equal(verifyBundle(early, { hmacKey: HMAC, windows: windows(5) }).ok, true);
  });

  it('a rotation cannot hide a missing row, an edited row or a cut tail', () => {
    const keys = { hmacKey: HMAC, windows: windows(5) };
    assert.equal(verifyBundle(edit(spanning, (copy) => copy.rows.splice(5, 1)), keys).ok, false, 'the row at the boundary removed');
    assert.equal(verifyBundle(edit(spanning, (copy) => (copy.rows[5].data.user = 'mallory')), keys).ok, false);
    const cut = exportOf(rows.slice(0, 8), [at(rows, 5, old.privateKey)]);
    const result = verifyBundle(cut, keys);
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /No signed checkpoint covers row 8/);
  });

  it('attack: audit_checkpoint_after_retirement - refuses the old key signing a checkpoint after its retirement', () => {
    const late = exportOf(rows, [at(rows, 10, old.privateKey)]);
    const result = verifyBundle(late, { hmacKey: HMAC, windows: windows(5) });
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /only for rows 0 to 5/);
  });

  it('refuses the new key signing for a row before it began', () => {
    const early = exportOf(rows.slice(0, 4), [at(rows, 4, fresh.privateKey)]);
    const result = verifyBundle(early, { hmacKey: HMAC, windows: windows(5) });
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /only for rows 6 to now/);
  });

  it('refuses a key the roster does not list, and a checkpoint that names a listed key but is signed by another', () => {
    const keys = { hmacKey: HMAC, windows: windows(5) };
    const unlisted = verifyBundle(exportOf(rows, [at(rows, 10, stranger.privateKey)]), keys);
    assert.equal(unlisted.ok, false);
    assert.match(unlisted.reason ?? '', /does not trust/);
    const stolenId = { ...at(rows, 10, stranger.privateKey), keyId: NEW_ID };
    const forged = verifyBundle(exportOf(rows, [stolenId]), keys);
    assert.equal(forged.ok, false);
    assert.match(forged.reason ?? '', /forged or edited/);
  });

  it('asks for a key at all, and still verifies a single pinned key as before', () => {
    assert.equal(verifyBundle(spanning, { hmacKey: HMAC }).ok, false);
    const single = exportOf(rows, [at(rows, 10, fresh.privateKey)]);
    assert.equal(verifyBundle(single, { hmacKey: HMAC, publicKey: createPublicKey(fresh.privateKey) }).ok, true);
  });
});

describe('a leaked audit key that is revoked after a row', () => {
  const rows = chain(12);
  // The old key leaked; the owner says it can be believed up to row 3, though it retired at row 5.
  const revoked = windows(5).map((item) => (item.keyId === OLD_ID ? { ...item, to: 3 } : item));

  it('attack: audit_checkpoint_revoked_key_after_row - refuses a key holder who extends the chain and signs the new head with the leaked key', () => {
    const forger = new AuditChain({ key: HMAC, head: { n: 12, mac: (rows[11] as AuditEntry).mac }, now: () => new Date(Date.UTC(2026, 10, 22, 6)) });
    const forged = [...rows, forger.append('broker/approval-decided', { id: 'x', approver: 'mallory', decision: 'approve' })];
    const result = verifyBundle(exportOf(forged, [at(forged, 13, old.privateKey)]), { hmacKey: HMAC, windows: revoked });
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /only for rows 0 to 3/);
  });

  it('an export that ended at the leaked key\'s last word is no longer accepted, but one covered by the new key is', () => {
    assert.equal(verifyBundle(exportOf(rows.slice(0, 5), [at(rows, 5, old.privateKey)]), { hmacKey: HMAC, windows: revoked }).ok, false);
    assert.equal(verifyBundle(exportOf(rows, [at(rows, 12, fresh.privateKey)]), { hmacKey: HMAC, windows: revoked }).ok, true);
  });

  it('a checkpoint the leaked key signed at or before the cut-off row still counts as history', () => {
    assert.equal(verifyBundle(exportOf(rows.slice(0, 3), [at(rows, 3, old.privateKey)]), { hmacKey: HMAC, windows: revoked }).ok, true);
  });

  it('pins from the revoked key after its cut-off are set aside, and a forged pin is still refused', () => {
    const covering = exportOf(rows, [at(rows, 12, fresh.privateKey)]);
    const setAside = at(rows, 5, old.privateKey);
    assert.equal(verifyBundle(covering, { hmacKey: HMAC, windows: revoked, pins: [setAside] }).ok, true);
    const forgedPin = { ...at(rows, 2, stranger.privateKey), keyId: OLD_ID };
    const result = verifyBundle(covering, { hmacKey: HMAC, windows: revoked, pins: [forgedPin] });
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /Your pinned checkpoint 1/);
  });
});

describe('where a checkpoint stands', () => {
  const rows = chain(6);
  it('tells ok, outside, unknown and forged apart', () => {
    const w = windows(3);
    assert.equal(checkpointStanding(at(rows, 3, old.privateKey), w).state, 'ok');
    assert.equal(checkpointStanding(at(rows, 5, old.privateKey), w).state, 'outside');
    assert.equal(checkpointStanding(at(rows, 5, stranger.privateKey), w).state, 'unknown');
    assert.equal(checkpointStanding({ ...at(rows, 5, stranger.privateKey), keyId: NEW_ID }, w).state, 'forged');
  });
});

describe('extra checkpoints in a bundle', () => {
  const rows = chain(12);
  const revoked = windows(5).map((item) => (item.keyId === OLD_ID ? { ...item, to: 3 } : item));

  it('one a revoked key signed after its cut-off is set aside, but the one covering the last row never is', () => {
    const covering = at(rows, 12, fresh.privateKey);
    const stale = at(rows, 5, old.privateKey);
    assert.equal(verifyBundle(exportOf(rows, [stale, covering]), { hmacKey: HMAC, windows: revoked }).ok, true);
    const onlyStale = verifyBundle(exportOf(rows.slice(0, 5), [stale]), { hmacKey: HMAC, windows: revoked });
    assert.equal(onlyStale.ok, false, 'the covering checkpoint is the one that cannot be set aside');
    assert.match(onlyStale.reason ?? '', /only for rows 0 to 3/);
  });

  it('a forged extra checkpoint is still refused, not set aside', () => {
    const forgedExtra = { ...at(rows, 5, stranger.privateKey), keyId: OLD_ID };
    const result = verifyBundle(exportOf(rows, [forgedExtra, at(rows, 12, fresh.privateKey)]), { hmacKey: HMAC, windows: windows(5) });
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /Checkpoint 1/);
  });
});
