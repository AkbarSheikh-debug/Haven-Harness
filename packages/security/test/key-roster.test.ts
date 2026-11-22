import assert from 'node:assert/strict';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { describe, it } from 'node:test';
import { RosterError, activeKeys, applyRoster, auditWindows, initialTrust, keyFingerprint, signRoster, type RosterPurpose, type KeyTrust } from '@hn/security';

const pair = (): { priv: KeyObject; pem: string } => {
  const made = generateKeyPairSync('ed25519');
  return { priv: made.privateKey, pem: made.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};

const root = pair();
const k1 = pair();
const k2 = pair();
const k3 = pair();

const base = (purpose: RosterPurpose = 'release'): KeyTrust => initialTrust(purpose, { keyId: 'root-1', publicKey: root.pem }, { k1: k1.pem });
const roster = (extra: Record<string, unknown> = {}, purpose: RosterPurpose = 'release'): Record<string, unknown> => ({
  format: 1,
  purpose,
  serial: 1,
  issued: '2026-11-22T00:00:00Z',
  keys: [{ keyId: 'k1', publicKey: k1.pem }, { keyId: 'k2', publicKey: k2.pem }],
  revoked: [],
  ...extra,
});
const signed = (body: Record<string, unknown>, by = root.priv, id = 'root-1') => signRoster(body, id, by);
const refused = (fn: () => unknown, match: RegExp): void => assert.throws(fn, (error: unknown) => error instanceof RosterError && match.test(error.message));

describe('a root-signed roster', () => {
  it('adds a key and keeps the pinned one', () => {
    const state = applyRoster(base(), signed(roster()));
    assert.deepEqual([...activeKeys(state).keys()].sort(), ['k1', 'k2']);
    assert.equal(state.serial, 1);
  });

  it('drops a key that is not listed, and revokes one by name', () => {
    const one = applyRoster(base(), signed(roster()));
    const dropped = applyRoster(one, signed(roster({ serial: 2, keys: [{ keyId: 'k2', publicKey: k2.pem }] })));
    assert.deepEqual([...activeKeys(dropped).keys()], ['k2']);
    const revoked = applyRoster(one, signed(roster({ serial: 2, keys: [{ keyId: 'k2', publicKey: k2.pem }], revoked: [{ keyId: 'k1', reason: 'leaked' }] })));
    assert.deepEqual([...activeKeys(revoked).keys()], ['k2']);
    assert.equal(revoked.revoked['k1']?.fingerprint, keyFingerprint(k1.pem));
  });

  it('accepts the same roster again, unchanged', () => {
    const once = applyRoster(base(), signed(roster()));
    assert.equal(applyRoster(once, signed(roster())), once);
  });
});

describe('attacks on the roster', () => {
  it('attack: roster_signed_by_signing_key - refuses a roster signed by a signing key, even a trusted one', () => {
    refused(() => applyRoster(base(), signed(roster({ keys: [{ keyId: 'k3', publicKey: k3.pem }] }), k1.priv, 'k1')), /not the root this machine pins/);
  });

  it('attack: roster_forged_or_edited - refuses a roster that claims the root id but is signed by someone else', () => {
    refused(() => applyRoster(base(), signed(roster(), k1.priv, 'root-1')), /signature does not match/);
  });

  it('refuses an edited body', () => {
    const good = signed(roster());
    const edited = { ...good, roster: { ...roster(), keys: [{ keyId: 'k3', publicKey: k3.pem }] } };
    refused(() => applyRoster(base(), edited), /signature does not match/);
  });

  it('attack: roster_replayed_older - refuses an older roster and a different one with the same serial', () => {
    const two = applyRoster(base(), signed(roster({ serial: 2 })));
    refused(() => applyRoster(two, signed(roster({ serial: 1 }))), /older/);
    refused(() => applyRoster(two, signed(roster({ serial: 2, keys: [{ keyId: 'k1', publicKey: k1.pem }] }))), /same serial/);
  });

  it('attack: roster_wrong_purpose - refuses a roster for another purpose', () => {
    refused(() => applyRoster(base('release'), signed(roster({}, 'policy'))), /policy roster/);
  });

  it('refuses a roster that leaves no key that can sign', () => {
    refused(() => applyRoster(base(), signed(roster({ keys: [{ keyId: 'k1', publicKey: k1.pem }], revoked: [{ keyId: 'k1', reason: 'x' }] }))), /revoked|at least one/);
  });

  it('attack: roster_unrevokes_key - never trusts a revoked key again, by id or under another id', () => {
    const revoked = applyRoster(applyRoster(base(), signed(roster())), signed(roster({ serial: 2, keys: [{ keyId: 'k2', publicKey: k2.pem }], revoked: [{ keyId: 'k1', reason: 'leaked' }] })));
    refused(() => applyRoster(revoked, signed(roster({ serial: 3 }))), /revoked and cannot be trusted again/);
    refused(() => applyRoster(revoked, signed(roster({ serial: 3, keys: [{ keyId: 'k2', publicKey: k2.pem }, { keyId: 'fresh', publicKey: k1.pem }] }))), /under another name/);
  });

  it('keeps a revoke when a later roster simply leaves the key out', () => {
    const revoked = applyRoster(applyRoster(base(), signed(roster())), signed(roster({ serial: 2, keys: [{ keyId: 'k2', publicKey: k2.pem }], revoked: [{ keyId: 'k1', reason: 'leaked' }] })));
    const later = applyRoster(revoked, signed(roster({ serial: 3, keys: [{ keyId: 'k2', publicKey: k2.pem }, { keyId: 'k3', publicKey: k3.pem }] })));
    assert.equal(later.revoked['k1']?.reason, 'leaked');
  });

  it('refuses the shapes that hide things', () => {
    refused(() => signed(roster({ extra: 1 })), /unknown field/);
    refused(() => signed(roster({ keys: [] })), /between 1 and/);
    refused(() => signed(roster({ keys: [{ keyId: 'a', publicKey: k1.pem }, { keyId: 'b', publicKey: k1.pem }] })), /already listed/);
    refused(() => signed(roster({ keys: [{ keyId: 'a', publicKey: k1.pem }, { keyId: 'a', publicKey: k2.pem }] })), /twice/);
    refused(() => signed(roster({ keys: [{ keyId: 'a/b', publicKey: k1.pem }] })), /plain label/);
    refused(() => signed(roster({ keys: [{ keyId: 'a', publicKey: 'not a key' }] })), /not a public key/);
    refused(() => signed(roster({ keys: [{ keyId: 'a', publicKey: k1.pem, fromRow: 3 }] })), /audit rosters only/);
    refused(() => signed(roster({ revoked: [{ keyId: 'k1', reason: 'x', afterRow: 4 }] })), /audit rosters only/);
    refused(() => signed(roster({ revoked: [{ keyId: 'k1', reason: '' }] })), /say why/);
    refused(() => applyRoster(base(), { roster: roster(), rootKeyId: 'root-1' }), /Not a signed roster/);
  });
});

describe('the root', () => {
  it('can name a successor, after which only the new root signs', () => {
    const next = pair();
    const moved = applyRoster(base(), signed(roster({ serial: 2, successor: { keyId: 'root-2', publicKey: next.pem } })));
    assert.equal(moved.root.keyId, 'root-2');
    refused(() => applyRoster(moved, signed(roster({ serial: 3 }))), /not the root this machine pins/);
    assert.equal(applyRoster(moved, signed(roster({ serial: 3 }), next.priv, 'root-2')).serial, 3);
  });

  it('cannot go back to an old root or make a signing key the root', () => {
    const next = pair();
    const moved = applyRoster(base(), signed(roster({ serial: 2, successor: { keyId: 'root-2', publicKey: next.pem } })));
    refused(() => applyRoster(moved, signed(roster({ serial: 3, successor: { keyId: 'root-1', publicKey: root.pem } }), next.priv, 'root-2')), /already used/);
    refused(() => applyRoster(base(), signed(roster({ serial: 2, successor: { keyId: 'root-2', publicKey: k2.pem } }))), /cannot also be the root/);
  });
});

describe('audit rosters', () => {
  const auditRoster = (extra: Record<string, unknown>): Record<string, unknown> => roster({ keys: [{ keyId: 'k1', publicKey: k1.pem, fromRow: 0 }], ...extra }, 'audit');

  it('keeps a retired key with the rows it signed, and a revoked key up to its cut-off row', () => {
    const one = applyRoster(base('audit'), signed(auditRoster({})));
    const rotated = applyRoster(one, signed(auditRoster({ serial: 2, keys: [{ keyId: 'k1', publicKey: k1.pem, fromRow: 0, toRow: 99 }, { keyId: 'k2', publicKey: k2.pem, fromRow: 100 }] })));
    const windows = auditWindows(rotated);
    assert.deepEqual(windows.map((item) => [item.keyId, item.from, item.to]), [['k1', 0, 99], ['k2', 100, Number.MAX_SAFE_INTEGER]]);
    const leaked = applyRoster(rotated, signed(auditRoster({ serial: 3, keys: [{ keyId: 'k1', publicKey: k1.pem, fromRow: 0, toRow: 99 }, { keyId: 'k2', publicKey: k2.pem, fromRow: 100 }], revoked: [{ keyId: 'k1', reason: 'leaked', afterRow: 80 }] })));
    assert.equal(auditWindows(leaked).find((item) => item.keyId === 'k1')?.to, 80);
  });

  it('refuses an audit roster in which every key is retired', () => {
    const one = applyRoster(base('audit'), signed(auditRoster({})));
    refused(() => applyRoster(one, signed(auditRoster({ serial: 2, keys: [{ keyId: 'k1', publicKey: k1.pem, fromRow: 0, toRow: 9 }] }))), /at least one key that can sign/);
  });

  it('refuses to forget an audit key, or to change its public key', () => {
    const one = applyRoster(base('audit'), signed(auditRoster({})));
    refused(() => applyRoster(one, signed(auditRoster({ serial: 2, keys: [{ keyId: 'k2', publicKey: k2.pem, fromRow: 100 }] }))), /missing from the roster/);
    refused(() => applyRoster(one, signed(auditRoster({ serial: 2, keys: [{ keyId: 'k1', publicKey: k2.pem, fromRow: 0, toRow: 9 }, { keyId: 'k3', publicKey: k3.pem, fromRow: 10 }] }))), /different public key/);
  });

  it('refuses a revoked-after-row key that is not also retired', () => {
    const one = applyRoster(base('audit'), signed(auditRoster({})));
    refused(() => applyRoster(one, signed(auditRoster({ serial: 2, keys: [{ keyId: 'k1', publicKey: k1.pem, fromRow: 0 }, { keyId: 'k2', publicKey: k2.pem, fromRow: 100 }], revoked: [{ keyId: 'k1', reason: 'x', afterRow: 50 }] }))), /retired with a toRow/);
  });

  it('a later revoke can only tighten the cut-off', () => {
    const one = applyRoster(base('audit'), signed(auditRoster({})));
    const keys = [{ keyId: 'k1', publicKey: k1.pem, fromRow: 0, toRow: 99 }, { keyId: 'k2', publicKey: k2.pem, fromRow: 100 }];
    const first = applyRoster(one, signed(auditRoster({ serial: 2, keys, revoked: [{ keyId: 'k1', reason: 'leaked', afterRow: 50 }] })));
    const wider = applyRoster(first, signed(auditRoster({ serial: 3, keys, revoked: [{ keyId: 'k1', reason: 'leaked', afterRow: 90 }] })));
    assert.equal(auditWindows(wider).find((item) => item.keyId === 'k1')?.to, 50);
  });
});
