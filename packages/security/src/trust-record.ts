import { createHmac, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import { applyRoster, initialTrust, keyFingerprint, type RootKey, type RosterPurpose, type KeyTrust } from './key-roster.ts';
import { canonicalJson } from './policy.ts';

/**
 * The trust record (Phase 15, decision 4): what one machine knows about the keys it trusts for one purpose, kept in
 * `<folder>/<purpose>.trust.json` with an HMAC under a key only this machine holds (the log key). Like the record of
 * the highest installed version, an edited or damaged record **refuses**: falling back to the keys the package
 * shipped would quietly forget a revocation. The limit that remains: deleting the file reverts to what the package
 * shipped until the next roster arrives, so `hn trust show` says when there is no record.
 */

export class TrustRecordError extends HnError {
  constructor(message: string) {
    super('TRUST_RECORD_REFUSED', message);
  }
}

/** What a package or a broker config pins before any roster: the root, the starting keys, and a shipped roster. */
export interface TrustSource {
  readonly purpose: RosterPurpose;
  readonly root: RootKey;
  readonly pins: Readonly<Record<string, string>>;
  /** A signed roster that came with the package or archive, applied when it is newer than the record. */
  readonly shipped?: unknown;
}

const recordPath = (folder: string, purpose: RosterPurpose): string => join(folder, `${purpose}.trust.json`);
const macOf = (key: Buffer | string, state: KeyTrust): string => createHmac('sha256', key).update(canonicalJson(state)).digest('hex');
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** The record on disk, or null when there is none. A record that does not check out throws. */
export async function readTrustRecord(folder: string, purpose: RosterPurpose, key: Buffer | string): Promise<KeyTrust | null> {
  const path = recordPath(folder, purpose);
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return null;
  }
  const damaged = (why: string): TrustRecordError => new TrustRecordError(`The ${purpose} trust record ${path} ${why}, so no ${purpose} key is trusted until it is repaired. Take a backup of the file, delete it, and fetch the roster again (this forgets any revocation it held, so check the roster serial afterwards with: hn trust show).`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw damaged('is not valid JSON');
  }
  if (!isRecord(parsed) || !isRecord(parsed['state']) || typeof parsed['mac'] !== 'string') throw damaged('is not a trust record');
  const state = parsed['state'] as unknown as KeyTrust;
  if (state.purpose !== purpose) throw damaged(`is for ${String(state.purpose)}`);
  const want = Buffer.from(macOf(key, state), 'hex');
  const got = Buffer.from(parsed['mac'], 'hex');
  if (want.length !== got.length || !timingSafeEqual(want, got)) throw damaged('was changed by something other than hn');
  return state;
}

export async function writeTrustRecord(folder: string, state: KeyTrust, key: Buffer | string): Promise<void> {
  await mkdir(folder, { recursive: true });
  const path = recordPath(folder, state.purpose);
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, JSON.stringify({ state, mac: macOf(key, state) }), { mode: 0o600 });
  await rename(temp, path);
}

const sameRoot = (state: KeyTrust, root: RootKey): boolean => {
  const print = keyFingerprint(root.publicKey);
  return keyFingerprint(state.root.publicKey) === print || state.retiredRoots.includes(print);
};

/**
 * The trust state for a purpose now: the record if there is one (kept when it descends from the pinned root), else
 * the pinned keys; then the shipped roster if it is newer. A package that pins a root the record never saw is a
 * hand re-pin: the new root and keys are used, and every revocation the record held is kept.
 */
export async function loadTrust(folder: string, key: Buffer | string, source: TrustSource): Promise<KeyTrust> {
  const record = await readTrustRecord(folder, source.purpose, key);
  let state: KeyTrust;
  if (record === null) state = initialTrust(source.purpose, source.root, source.pins);
  else if (sameRoot(record, source.root)) state = record;
  else state = { ...initialTrust(source.purpose, source.root, source.pins), revoked: record.revoked };
  const shipped = source.shipped;
  if (isRecord(shipped) && isRecord(shipped['roster']) && typeof shipped['roster']['serial'] === 'number' && shipped['roster']['serial'] > state.serial) state = applyRoster(state, shipped);
  if (state !== record) await writeTrustRecord(folder, state, key);
  return state;
}

/** Applies a roster someone handed over (a file, a URL, a broker) and keeps the result. Refusals leave the record as it was. */
export async function offerRoster(folder: string, key: Buffer | string, source: TrustSource, signed: unknown): Promise<{ state: KeyTrust; changed: boolean }> {
  const current = await loadTrust(folder, key, source);
  const next = applyRoster(current, signed);
  if (next === current) return { state: current, changed: false };
  await writeTrustRecord(folder, next, key);
  return { state: next, changed: true };
}
