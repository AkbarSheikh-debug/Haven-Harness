import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, createPublicKey, type KeyObject } from 'node:crypto';
import { describe, it } from 'node:test';
import { AuditChain, buildExport, checkpointValid, signCheckpoint, verifyBundle, type AuditEntry, type Checkpoint } from '@hn/security';

const HMAC = randomBytes(32);
const pair = generateKeyPairSync('ed25519');
const PUBLIC: KeyObject = createPublicKey(pair.privateKey);

function chain(count: number): AuditEntry[] {
  let tick = 0;
  const made = new AuditChain({ key: HMAC, now: () => new Date(Date.UTC(2026, 10, 22, 0, 0, (tick += 1))) });
  return Array.from({ length: count }, (_, index) => made.append(index % 2 === 0 ? 'broker/model' : 'broker/session', { user: `u${index % 3}`, n: index }));
}

const checkpointAt = (rows: readonly AuditEntry[], n: number): Checkpoint => signCheckpoint(rows[n - 1] as AuditEntry, '2026-11-22T01:00:00.000Z', pair.privateKey);
const exportOf = (rows: readonly AuditEntry[], covered: readonly number[] = [rows.length]) => buildExport(rows, covered.map((n) => checkpointAt(rows, n)), 'auditor@example.com', '2026-11-22T01:00:00.000Z');
const keys = { hmacKey: HMAC, publicKey: PUBLIC };
const edit = <T>(value: T, change: (copy: any) => void): T => {
  const copy = JSON.parse(JSON.stringify(value));
  change(copy);
  return copy as T;
};

describe('a signed checkpoint', () => {
  it('verifies with its key and not with another, and any edited field breaks it', () => {
    const rows = chain(3);
    const checkpoint = checkpointAt(rows, 3);
    assert.equal(checkpointValid(checkpoint, PUBLIC), true);
    assert.equal(checkpointValid(checkpoint, createPublicKey(generateKeyPairSync('ed25519').privateKey)), false);
    for (const changed of [{ ...checkpoint, n: 2 }, { ...checkpoint, mac: '0'.repeat(64) }, { ...checkpoint, ts: '2026-11-23T00:00:00.000Z' }]) assert.equal(checkpointValid(changed, PUBLIC), false);
  });
});

describe('verifying an audit export', () => {
  it('accepts an untouched export of the whole chain', () => {
    const result = verifyBundle(exportOf(chain(8)), keys);
    assert.equal(result.ok, true, result.reason ?? '');
    assert.equal(result.rows, 8);
  });

  it('accepts a range that starts in the middle, because the signed head fixes every row before it', () => {
    const rows = chain(10);
    const result = verifyBundle(buildExport(rows.slice(4), [checkpointAt(rows, 10)], 'a', '2026-11-22T01:00:00.000Z'), keys);
    assert.equal(result.ok, true, result.reason ?? '');
    assert.equal(result.from, 5);
  });

  it('attack: audit_export_row_edited - refuses an edited row and names it', () => {
    const bundle = edit(exportOf(chain(6)), (copy) => (copy.rows[2].data.user = 'mallory'));
    const result = verifyBundle(bundle, keys);
    assert.equal(result.ok, false);
    assert.equal(result.brokenAt, 3);
  });

  it('attack: audit_export_rows_removed_or_reordered - refuses a removed row, a reordered pair and a repeated row', () => {
    const base = exportOf(chain(6));
    assert.equal(verifyBundle(edit(base, (copy) => copy.rows.splice(2, 1)), keys).ok, false);
    assert.equal(verifyBundle(edit(base, (copy) => ([copy.rows[1], copy.rows[2]] = [copy.rows[2], copy.rows[1]])), keys).ok, false);
    assert.equal(verifyBundle(edit(base, (copy) => copy.rows.splice(3, 0, copy.rows[3])), keys).ok, false);
    // Even when the manifest is changed to match the rows that are left.
    const shorter = edit(base, (copy) => {
      copy.rows.splice(2, 1);
      copy.count = 5;
      copy.to = 5;
    });
    assert.equal(verifyBundle(shorter, keys).ok, false);
  });

  it('attack: audit_export_tail_cut - refuses a cut tail, whether or not the old checkpoint is left in', () => {
    const rows = chain(10);
    const full = exportOf(rows, [5, 10]);
    // The last rows removed and the manifest changed to match, with the checkpoint for row 10 left in: it names a row beyond the end.
    const cut = edit(full, (copy) => {
      copy.rows.length = 7;
      copy.count = 7;
      copy.to = 7;
    });
    const left = verifyBundle(cut, keys);
    assert.equal(left.ok, false);
    assert.match(left.reason ?? '', /cut off/);
    // With the checkpoint for row 10 taken out as well, nothing signed covers row 7.
    const stripped = edit(cut, (copy) => (copy.checkpoints = copy.checkpoints.filter((item: Checkpoint) => item.n <= 5)));
    const noCover = verifyBundle(stripped, keys);
    assert.equal(noCover.ok, false);
    assert.match(noCover.reason ?? '', /No signed checkpoint covers row 7/);
  });

  it('attack: audit_export_tail_extended_by_key_holder - refuses a tail added by someone who holds the audit key, because the new head is not signed', () => {
    const rows = chain(6);
    const chainer = new AuditChain({ key: HMAC, head: { n: 6, mac: (rows[5] as AuditEntry).mac } });
    const forged = [...rows, chainer.append('broker/approval-decided', { id: 'x', approver: 'mallory', decision: 'approve' })];
    const bundle = { ...exportOf(rows), to: 7, count: 7, rows: forged };
    const result = verifyBundle(bundle, keys);
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /No signed checkpoint covers row 7/);
  });

  it('attack: audit_export_row_swapped_by_key_holder - refuses one row swapped for a genuine-looking one by a key holder, because the rows after it no longer follow it', () => {
    const rows = chain(6);
    const forger = new AuditChain({ key: HMAC, head: { n: 3, mac: (rows[2] as AuditEntry).mac }, now: () => new Date(Date.UTC(2026, 10, 22, 5)) });
    const swapped = forger.append('broker/approval-decided', { id: 'x', approver: 'mallory', decision: 'approve' });
    assert.equal(swapped.n, 4);
    const bundle = { ...exportOf(rows), rows: [...rows.slice(0, 3), swapped, ...rows.slice(4)] };
    const result = verifyBundle(bundle, keys);
    assert.equal(result.ok, false);
    assert.equal(result.brokenAt, 5, 'the row after the swapped one does not follow it');
  });

  it('refuses rows rewritten end to end by a key holder, because the checkpoint names the real head', () => {
    const rows = chain(6);
    const other = new AuditChain({ key: HMAC });
    const rewritten = rows.map((row) => other.append(row.type, { ...row.data, user: 'someone-else' }));
    const result = verifyBundle({ ...exportOf(rows), rows: rewritten }, keys);
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /not the ones the broker signed|changed after/);
  });

  it('refuses the wrong audit key', () => {
    const result = verifyBundle(exportOf(chain(4)), { ...keys, hmacKey: randomBytes(32) });
    assert.equal(result.ok, false);
    assert.equal(result.brokenAt, 1);
  });

  it('attack: audit_checkpoint_forged - refuses the wrong public key and a checkpoint forged with another key', () => {
    const rows = chain(4);
    assert.equal(verifyBundle(exportOf(rows), { ...keys, publicKey: createPublicKey(generateKeyPairSync('ed25519').privateKey) }).ok, false);
    const attacker = generateKeyPairSync('ed25519');
    const forged = buildExport(rows, [signCheckpoint(rows[3] as AuditEntry, '2026-11-22T01:00:00.000Z', attacker.privateKey)], 'a', '2026-11-22T01:00:00.000Z');
    const result = verifyBundle(forged, keys);
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /not signed by the pinned/);
  });

  it('refuses a checkpoint whose fields were edited to cover a different row', () => {
    const rows = chain(6);
    const bundle = edit(exportOf(rows, [3, 6]), (copy) => (copy.checkpoints[0].mac = copy.rows[4].mac));
    assert.equal(verifyBundle(bundle, keys).ok, false);
  });

  it('attack: audit_export_view_as_export - never calls a filtered view verified, and a view relabelled as an export is refused because rows are missing', () => {
    const rows = chain(9);
    const picked = rows.filter((row) => row.n % 3 === 0);
    const view = { format: 1, kind: 'view', filter: { type: 'broker/model' }, exportedAt: 'x', exportedBy: 'a', rows: picked };
    const shown = verifyBundle(view, keys);
    assert.equal(shown.ok, false);
    assert.equal(shown.kind, 'view');
    assert.match(shown.reason ?? '', /subset|selection/);
    const relabelled = { format: 1, kind: 'export', from: 3, to: 9, count: 3, exportedAt: 'x', exportedBy: 'a', rows: picked, checkpoints: [checkpointAt(rows, 9)] };
    const result = verifyBundle(relabelled, keys);
    assert.equal(result.ok, false);
  });

  it('uses the auditor\'s pinned checkpoints: a later pin that the export ends before, or disagrees with, is refused', () => {
    const rows = chain(12);
    const early = exportOf(rows.slice(0, 8), [8]);
    assert.equal(verifyBundle(early, keys).ok, true, 'on its own, an earlier export is a valid export');
    const pins = [checkpointAt(rows, 12)];
    const stale = verifyBundle(early, { ...keys, pins });
    assert.equal(stale.ok, false);
    assert.match(stale.reason ?? '', /cut off|out of date/);
    // A pin from a visit when the broker said something else about row 5.
    const alt = new AuditChain({ key: HMAC });
    const altRows = rows.map((row, index) => alt.append(row.type, index === 4 ? { ...row.data, user: 'changed' } : row.data));
    const pinned = signCheckpoint(rows[4] as AuditEntry, '2026-11-22T00:30:00.000Z', pair.privateKey);
    const history = buildExport(altRows, [signCheckpoint(altRows[11] as AuditEntry, '2026-11-22T01:00:00.000Z', pair.privateKey)], 'a', '2026-11-22T01:00:00.000Z');
    const result = verifyBundle(history, { ...keys, pins: [pinned] });
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /does not match|signed/);
  });

  it('refuses things that are not bundles, without throwing', () => {
    for (const junk of [null, 5, 'text', [], {}, { format: 1 }, { format: 1, kind: 'export' }, { format: 1, kind: 'export', from: 1, to: 1, count: 1, rows: [{}], checkpoints: [] }, { format: 1, kind: 'export', from: 0, to: 1, count: 2, rows: [], checkpoints: [] }]) {
      assert.equal(verifyBundle(junk, keys).ok, false);
    }
  });
});
