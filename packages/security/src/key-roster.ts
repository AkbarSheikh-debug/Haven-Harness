import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import { HnError } from '@hn/core';
import { canonicalJson } from './policy.ts';

/**
 * Key rosters (Phase 15). Three keys in the system sign things other people trust: the release key, the policy key
 * and the audit-signing key. A **roster** says which signing keys are trusted for one purpose, and which are
 * revoked. It is signed by a **root key**, which is not a signing key and stays offline, so a leaked signing key can
 * neither add a key nor revoke the good ones.
 *
 * A machine pins the root once and then follows rosters. Rules that never bend:
 *  - the serial only grows; the same serial with different content is refused;
 *  - a revoked key can never be trusted again, by its id or by its public key under another id;
 *  - a roster leaves at least one usable key;
 *  - a roster is checked against the root the machine already pins, never one the roster brings, except that the
 *    current root may name its own successor.
 * A leaked root cannot be fixed by a roster (the leaker can sign too); the fix is a hand re-pin.
 */

export type RosterPurpose = 'release' | 'policy' | 'audit';

export interface RosterKey {
  readonly keyId: string;
  /** SPKI PEM of an Ed25519 public key. */
  readonly publicKey: string;
  /** Audit only: the first row this key signs checkpoints for. */
  readonly fromRow?: number;
  /** Audit only: the key signs nothing after this row (a routine retirement; its older checkpoints still verify). */
  readonly toRow?: number;
}

export interface RosterRevoked {
  readonly keyId: string;
  /** Lets a machine that never saw the key still refuse it under another id. */
  readonly publicKey?: string;
  readonly reason: string;
  /** Audit only: checkpoints for rows up to and including this one are history and still verify; later ones do not. */
  readonly afterRow?: number;
}

export interface Roster {
  readonly format: 1;
  readonly purpose: RosterPurpose;
  readonly serial: number;
  readonly issued: string;
  readonly keys: readonly RosterKey[];
  readonly revoked: readonly RosterRevoked[];
  readonly successor?: { readonly keyId: string; readonly publicKey: string };
}

export interface SignedRoster {
  readonly roster: unknown;
  readonly rootKeyId: string;
  /** Base64 Ed25519 signature over the canonical text of `roster`. */
  readonly signature: string;
}

export interface RootKey {
  readonly keyId: string;
  readonly publicKey: string;
}

export interface TrustedKey {
  readonly publicKey: string;
  readonly fromRow?: number;
  readonly toRow?: number;
}

export interface RevokedKey {
  readonly fingerprint: string | null;
  readonly afterRow?: number;
  readonly reason: string;
}

/** What a machine knows and keeps: the root, the newest roster's serial and hash, the trusted keys, the revoked ones. */
export interface KeyTrust {
  readonly purpose: RosterPurpose;
  readonly root: RootKey;
  readonly retiredRoots: readonly string[];
  readonly serial: number;
  readonly hash: string | null;
  readonly keys: Readonly<Record<string, TrustedKey>>;
  readonly revoked: Readonly<Record<string, RevokedKey>>;
}

export class RosterError extends HnError {
  constructor(message: string) {
    super('ROSTER_REFUSED', message);
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const PURPOSES: readonly string[] = ['release', 'policy', 'audit'];
const ROSTER_KEYS = new Set(['format', 'purpose', 'serial', 'issued', 'keys', 'revoked', 'successor']);
const MAX_KEYS = 64;
const MAX_ID = 200;

/** A key id is a plain label: no control characters, no slash, not empty. */
function idOk(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID) return false;
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f) || ch === '/' || ch === String.fromCharCode(92)) return false;
  }
  return true;
}

function loadKey(pem: unknown, where: string): KeyObject {
  if (typeof pem !== 'string') throw new RosterError(`${where} needs a public key.`);
  let key: KeyObject;
  try {
    key = createPublicKey(pem);
  } catch {
    throw new RosterError(`${where} is not a public key.`);
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new RosterError(`${where} is not an Ed25519 key.`);
  return key;
}

export const keyFingerprint = (publicKey: KeyObject | string): string => createHash('sha256').update((typeof publicKey === 'string' ? createPublicKey(publicKey) : publicKey).export({ type: 'spki', format: 'der' })).digest('hex');

export const rosterHash = (roster: unknown): string => createHash('sha256').update(canonicalJson(roster)).digest('hex');

function row(value: unknown, where: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new RosterError(`${where} must be a whole number of 0 or more.`);
  return value;
}

/** Checks the shape of a roster. Unknown fields are errors. */
export function parseRoster(value: unknown): Roster {
  if (!isRecord(value)) throw new RosterError('A roster must be an object.');
  for (const key of Object.keys(value)) if (!ROSTER_KEYS.has(key)) throw new RosterError(`A roster has an unknown field "${key}".`);
  if (value['format'] !== 1) throw new RosterError('A roster needs "format": 1.');
  const purpose = value['purpose'];
  if (typeof purpose !== 'string' || !PURPOSES.includes(purpose)) throw new RosterError('A roster needs a purpose: release, policy or audit.');
  const serial = value['serial'];
  if (typeof serial !== 'number' || !Number.isSafeInteger(serial) || serial < 1) throw new RosterError('serial must be a whole number of 1 or more.');
  if (typeof value['issued'] !== 'string' || Number.isNaN(Date.parse(value['issued']))) throw new RosterError('issued must be a date.');
  const audit = purpose === 'audit';
  if (!Array.isArray(value['keys']) || value['keys'].length === 0 || value['keys'].length > MAX_KEYS) throw new RosterError(`keys must list between 1 and ${MAX_KEYS} keys.`);
  const seenIds = new Set<string>();
  const seenPrints = new Set<string>();
  const keys: RosterKey[] = [];
  for (const [index, item] of value['keys'].entries()) {
    const where = `keys[${index}]`;
    if (!isRecord(item)) throw new RosterError(`${where} must be an object.`);
    for (const field of Object.keys(item)) if (!['keyId', 'publicKey', 'fromRow', 'toRow'].includes(field)) throw new RosterError(`${where} has an unknown field "${field}".`);
    if (!idOk(item['keyId'])) throw new RosterError(`${where}.keyId is not a plain label.`);
    const print = keyFingerprint(loadKey(item['publicKey'], where));
    if (seenIds.has(item['keyId'])) throw new RosterError(`${where}.keyId "${item['keyId']}" is listed twice.`);
    if (seenPrints.has(print)) throw new RosterError(`${where} lists a public key that is already listed under another id.`);
    seenIds.add(item['keyId']);
    seenPrints.add(print);
    const fromRow = row(item['fromRow'], `${where}.fromRow`);
    const toRow = row(item['toRow'], `${where}.toRow`);
    if (!audit && (fromRow !== undefined || toRow !== undefined)) throw new RosterError(`${where}: row windows are for audit rosters only.`);
    if (fromRow !== undefined && toRow !== undefined && toRow < fromRow) throw new RosterError(`${where}: toRow is before fromRow.`);
    keys.push({ keyId: item['keyId'], publicKey: item['publicKey'] as string, ...(fromRow === undefined ? {} : { fromRow }), ...(toRow === undefined ? {} : { toRow }) });
  }
  const revokedRaw = value['revoked'] ?? [];
  if (!Array.isArray(revokedRaw) || revokedRaw.length > MAX_KEYS * 4) throw new RosterError('revoked must be a list.');
  const revoked: RosterRevoked[] = [];
  const revokedIds = new Set<string>();
  for (const [index, item] of revokedRaw.entries()) {
    const where = `revoked[${index}]`;
    if (!isRecord(item)) throw new RosterError(`${where} must be an object.`);
    for (const field of Object.keys(item)) if (!['keyId', 'publicKey', 'reason', 'afterRow'].includes(field)) throw new RosterError(`${where} has an unknown field "${field}".`);
    if (!idOk(item['keyId'])) throw new RosterError(`${where}.keyId is not a plain label.`);
    if (typeof item['reason'] !== 'string' || item['reason'].length === 0 || item['reason'].length > 500) throw new RosterError(`${where}.reason must say why, in 500 characters or fewer.`);
    if (item['publicKey'] !== undefined) loadKey(item['publicKey'], `${where}.publicKey`);
    const afterRow = row(item['afterRow'], `${where}.afterRow`);
    if (!audit && afterRow !== undefined) throw new RosterError(`${where}: afterRow is for audit rosters only.`);
    if (revokedIds.has(item['keyId'])) throw new RosterError(`${where}.keyId "${item['keyId']}" is revoked twice.`);
    revokedIds.add(item['keyId']);
    revoked.push({ keyId: item['keyId'], reason: item['reason'], ...(item['publicKey'] === undefined ? {} : { publicKey: item['publicKey'] as string }), ...(afterRow === undefined ? {} : { afterRow }) });
  }
  let successor: Roster['successor'];
  if (value['successor'] !== undefined) {
    const next = value['successor'];
    if (!isRecord(next) || Object.keys(next).length !== 2 || !idOk(next['keyId'])) throw new RosterError('successor needs exactly a keyId and a publicKey.');
    loadKey(next['publicKey'], 'successor');
    successor = { keyId: next['keyId'], publicKey: next['publicKey'] as string };
  }
  return { format: 1, purpose: purpose as RosterPurpose, serial, issued: value['issued'], keys, revoked, ...(successor === undefined ? {} : { successor }) };
}

/** Signs a roster with the root's private key. The shape is checked first, so a bad roster is never signed. */
export function signRoster(roster: unknown, rootKeyId: string, privateKey: KeyObject): SignedRoster {
  parseRoster(roster);
  return { roster, rootKeyId, signature: sign(null, Buffer.from(canonicalJson(roster)), privateKey).toString('base64') };
}

/** The state of a machine that pins a root and some keys but has not seen any roster. */
export function initialTrust(purpose: RosterPurpose, root: RootKey, pins: Readonly<Record<string, string>>): KeyTrust {
  loadKey(root.publicKey, 'The root key');
  const keys: Record<string, TrustedKey> = {};
  for (const [id, pem] of Object.entries(pins)) {
    loadKey(pem, `The pinned key ${id}`);
    keys[id] = { publicKey: pem };
  }
  return { purpose, root, retiredRoots: [], serial: 0, hash: null, keys, revoked: {} };
}

function stricter(a: number | undefined, b: number | undefined): number | undefined {
  if (a === undefined || b === undefined) return undefined;
  return Math.min(a, b);
}

/**
 * Applies a signed roster to a trust state and returns the new state. Throws a `RosterError` that names the reason.
 * Applying the very roster already in force returns the same state, so a roster can be offered again safely.
 */
export function applyRoster(state: KeyTrust, signed: unknown): KeyTrust {
  if (!isRecord(signed) || Object.keys(signed).length !== 3 || typeof signed['rootKeyId'] !== 'string' || typeof signed['signature'] !== 'string' || !isRecord(signed['roster'])) throw new RosterError('Not a signed roster.');
  if (signed['rootKeyId'] !== state.root.keyId) throw new RosterError(`The roster is signed by "${signed['rootKeyId']}", which is not the root this machine pins ("${state.root.keyId}"). A signing key cannot change what is trusted.`);
  let good = false;
  try {
    good = verify(null, Buffer.from(canonicalJson(signed['roster'])), createPublicKey(state.root.publicKey), Buffer.from(signed['signature'], 'base64'));
  } catch {
    good = false;
  }
  if (!good) throw new RosterError('The signature does not match the roster, so it was changed or signed by someone else.');
  const roster = parseRoster(signed['roster']);
  if (roster.purpose !== state.purpose) throw new RosterError(`This is a ${roster.purpose} roster, and this machine is asking for a ${state.purpose} one.`);
  const hash = rosterHash(signed['roster']);
  if (roster.serial < state.serial) throw new RosterError(`This roster is serial ${roster.serial}, older than serial ${state.serial} already in use, so it is refused (an old roster cannot be replayed).`);
  if (roster.serial === state.serial) {
    if (hash !== state.hash) throw new RosterError(`A different roster with the same serial ${roster.serial} was already in use, so this one is refused.`);
    return state;
  }
  // Revocations only ever accumulate, and a repeated one can only get stricter.
  const revoked: Record<string, RevokedKey> = { ...state.revoked };
  for (const item of roster.revoked) {
    const known = state.keys[item.keyId]?.publicKey;
    const fingerprint = item.publicKey !== undefined ? keyFingerprint(item.publicKey) : known !== undefined ? keyFingerprint(known) : (state.revoked[item.keyId]?.fingerprint ?? null);
    const before = state.revoked[item.keyId];
    const afterRow = before === undefined ? item.afterRow : stricter(before.afterRow, item.afterRow);
    revoked[item.keyId] = { fingerprint: fingerprint ?? before?.fingerprint ?? null, reason: before?.reason ?? item.reason, ...(afterRow === undefined ? {} : { afterRow }) };
  }
  const keys: Record<string, TrustedKey> = {};
  for (const item of roster.keys) {
    const entry = revoked[item.keyId];
    const print = keyFingerprint(item.publicKey);
    if (entry !== undefined && entry.afterRow === undefined) throw new RosterError(`The key "${item.keyId}" was revoked and cannot be trusted again. A new key needs a new id.`);
    for (const [id, other] of Object.entries(revoked)) {
      if (other.fingerprint === print && id !== item.keyId) throw new RosterError(`The key listed as "${item.keyId}" is the revoked key "${id}" under another name.`);
    }
    if (state.purpose === 'audit' && entry !== undefined && item.toRow === undefined) throw new RosterError(`The audit key "${item.keyId}" is revoked after a row, so it must also be retired with a toRow.`);
    keys[item.keyId] = { publicKey: item.publicKey, ...(item.fromRow === undefined ? {} : { fromRow: item.fromRow }), ...(item.toRow === undefined ? {} : { toRow: item.toRow }) };
  }
  if (state.purpose === 'audit') {
    // History must not be forgotten: an older key may be retired, never silently dropped.
    for (const [id, item] of Object.entries(state.keys)) {
      if (keys[id] === undefined && !(revoked[id] !== undefined && revoked[id]?.afterRow === undefined)) throw new RosterError(`The audit key "${id}" is missing from the roster. Retire it with a toRow instead of dropping it, or older exports stop verifying.`);
      if (keys[id] !== undefined && keys[id]?.publicKey !== item.publicKey) throw new RosterError(`The audit key "${id}" now has a different public key.`);
    }
  }
  if (!roster.keys.some((item) => item.toRow === undefined && revoked[item.keyId] === undefined)) throw new RosterError('A roster must leave at least one key that can sign.');
  let root = state.root;
  let retiredRoots = state.retiredRoots;
  if (roster.successor !== undefined) {
    const print = keyFingerprint(roster.successor.publicKey);
    if (print === keyFingerprint(state.root.publicKey) || state.retiredRoots.includes(print)) throw new RosterError('The successor root is a root that was already used, so it is refused.');
    if (Object.values(keys).some((item) => keyFingerprint(item.publicKey) === print)) throw new RosterError('A signing key cannot also be the root.');
    retiredRoots = [...state.retiredRoots, keyFingerprint(state.root.publicKey)];
    root = { keyId: roster.successor.keyId, publicKey: roster.successor.publicKey };
  }
  return { purpose: state.purpose, root, retiredRoots, serial: roster.serial, hash, keys, revoked };
}

const bannedPrint = (state: KeyTrust, publicKey: string): boolean => Object.values(state.revoked).some((item) => item.fingerprint !== null && item.fingerprint === keyFingerprint(publicKey));

/** The keys that may sign new work (release and policy): id to public key PEM. Retired and revoked keys are not in it. */
export function activeKeys(state: KeyTrust): Map<string, string> {
  const out = new Map<string, string>();
  for (const [id, item] of Object.entries(state.keys)) {
    if (item.toRow !== undefined || state.revoked[id] !== undefined || bannedPrint(state, item.publicKey)) continue;
    out.set(id, item.publicKey);
  }
  return out;
}

export interface AuditKeyWindow {
  readonly keyId: string;
  readonly publicKey: string;
  /** The first row this key may sign for. */
  readonly from: number;
  /** The last row this key may sign for: its retirement, or the cut-off of a revocation, whichever is first. */
  readonly to: number;
}

/** Audit keys with the row window in which each is believed. A revoked key keeps its window up to `afterRow`. */
export function auditWindows(state: KeyTrust): AuditKeyWindow[] {
  const out: AuditKeyWindow[] = [];
  for (const [id, item] of Object.entries(state.keys)) {
    const cut = state.revoked[id];
    if (cut !== undefined && cut.afterRow === undefined) continue;
    const ends = [item.toRow, cut?.afterRow].filter((value): value is number => value !== undefined);
    out.push({ keyId: id, publicKey: item.publicKey, from: item.fromRow ?? 0, to: ends.length === 0 ? Number.MAX_SAFE_INTEGER : Math.min(...ends) });
  }
  return out;
}

export const isRevoked = (state: KeyTrust, keyId: string): boolean => state.revoked[keyId] !== undefined;
