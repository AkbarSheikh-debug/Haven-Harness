import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import { GENESIS, entryFromValue, macOf, type AuditEntry } from './audit.ts';
import { canonicalJson } from './policy.ts';
import type { AuditKeyWindow } from './key-roster.ts';

/**
 * Signed checkpoints and the audit bundle (Phase 14).
 *
 * The audit chain is keyed with a symmetric key, so whoever holds that key can write a chain that verifies. A
 * checkpoint closes that gap: the broker signs `(n, mac, time)` of a row with an Ed25519 key whose public half the
 * auditor pins. A key holder can still forge rows, but cannot forge a signed head, and the head's MAC depends on every
 * row before it, so rows k..n that chain to a signed row n are exactly the rows the broker had.
 *
 * What a checkpoint proves is what the broker said at that time. It does not prove the broker was honest before it
 * signed, and a broker that is compromised can sign anything from then on. An auditor who keeps the checkpoints they
 * have seen (`pins`) can tell that history was rewritten after a visit.
 */

export interface Checkpoint {
  readonly n: number;
  readonly mac: string;
  readonly ts: string;
  readonly keyId: string;
  /** Base64 Ed25519 signature over the canonical text of `[n, mac, ts, keyId]`. */
  readonly sig: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
const CHECKPOINT_KEYS = new Set(['n', 'mac', 'ts', 'keyId', 'sig']);

/** A short name for a public key, so a checkpoint says which key signed it. */
export const auditKeyId = (publicKey: KeyObject): string => createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 16);

const checkpointText = (value: { n: number; mac: string; ts: string; keyId: string }): Buffer => Buffer.from(canonicalJson([value.n, value.mac, value.ts, value.keyId]));

export function signCheckpoint(head: { readonly n: number; readonly mac: string }, ts: string, privateKey: KeyObject): Checkpoint {
  const keyId = auditKeyId(createPublicKey(privateKey));
  const body = { n: head.n, mac: head.mac, ts, keyId };
  return { ...body, sig: sign(null, checkpointText(body), privateKey).toString('base64') };
}

/** A checkpoint from parsed JSON, or null when it is not exactly one. */
export function checkpointFromValue(raw: unknown): Checkpoint | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  if (Object.keys(record).some((key) => !CHECKPOINT_KEYS.has(key))) return null;
  const { n, mac, ts, keyId, sig } = record;
  if (!Number.isSafeInteger(n) || (n as number) < 1 || typeof mac !== 'string' || !HEX64.test(mac)) return null;
  if (typeof ts !== 'string' || Number.isNaN(Date.parse(ts)) || typeof keyId !== 'string' || typeof sig !== 'string' || sig.length > 200) return null;
  return { n: n as number, mac, ts, keyId, sig };
}

/** Whether this checkpoint was signed by this public key. A checkpoint that names another key is not accepted either. */
export function checkpointValid(checkpoint: Checkpoint, publicKey: KeyObject): boolean {
  if (checkpoint.keyId !== auditKeyId(publicKey)) return false;
  try {
    return verify(null, checkpointText(checkpoint), publicKey, Buffer.from(checkpoint.sig, 'base64'));
  } catch {
    return false;
  }
}

/**
 * Where a checkpoint stands against the keys a root-signed audit roster trusts (Phase 15): ok; forged (the key it
 * names did not sign it); unknown (no key in the roster has that id: forged, from another broker, or revoked
 * outright); or outside (a real signature, but for a row after the key's cut-off: it was retired at row 99 and signs
 * nothing for row 100, or revoked after row 80 and is believed up to row 80 and not after).
 */
export function checkpointStanding(checkpoint: Checkpoint, windows: readonly AuditKeyWindow[]): { readonly state: 'ok' | 'forged' | 'unknown' | 'outside'; readonly reason: string } {
  const window = windows.find((item) => auditKeyId(createPublicKey(item.publicKey)) === checkpoint.keyId);
  if (window === undefined) return { state: 'unknown', reason: `was signed by key ${checkpoint.keyId.slice(0, 16)}, which the roster does not trust (it is forged, from another broker, or revoked outright).` };
  if (!checkpointValid(checkpoint, createPublicKey(window.publicKey))) return { state: 'forged', reason: 'does not verify with the key it names (it is forged or edited).' };
  if (checkpoint.n < window.from || checkpoint.n > window.to) {
    const last = window.to === Number.MAX_SAFE_INTEGER ? 'now' : String(window.to);
    return { state: 'outside', reason: `is for row ${checkpoint.n}, but the roster trusts key ${checkpoint.keyId.slice(0, 16)} only for rows ${window.from} to ${last}: a key that was retired or revoked signed it after its cut-off.` };
  }
  return { state: 'ok', reason: '' };
}

/**
 * Why a checkpoint is not accepted, or null when it is. With windows it is checkpointStanding; with only a pinned
 * publicKey it is the single-key check of Phase 14, with legacy as the refusal text.
 */
export function checkpointProblem(checkpoint: Checkpoint, keys: { readonly publicKey?: KeyObject; readonly windows?: readonly AuditKeyWindow[] }, legacy: string): string | null {
  if (keys.windows === undefined) return keys.publicKey !== undefined && checkpointValid(checkpoint, keys.publicKey) ? null : legacy;
  const standing = checkpointStanding(checkpoint, keys.windows);
  return standing.state === 'ok' ? null : standing.reason;
}

/** A contiguous range of rows with the signed checkpoint that covers its last row. The default export, and the only verifiable one. */
export interface AuditExport {
  readonly format: 1;
  readonly kind: 'export';
  readonly from: number;
  readonly to: number;
  readonly count: number;
  readonly exportedAt: string;
  readonly exportedBy: string;
  readonly rows: readonly AuditEntry[];
  readonly checkpoints: readonly Checkpoint[];
  /** The root-signed audit roster in force when this was exported (Phase 15), for a verifier that pins the root. */
  readonly roster?: unknown;
}

/** A filtered selection. It is labelled as a subset, carries the rows' own numbers, and is never reported as verified. */
export interface AuditView {
  readonly format: 1;
  readonly kind: 'view';
  readonly filter: Readonly<Record<string, string>>;
  readonly exportedAt: string;
  readonly exportedBy: string;
  readonly rows: readonly AuditEntry[];
}

export interface BundleVerification {
  readonly ok: boolean;
  readonly kind: 'export' | 'view' | 'unknown';
  /** The first bad row's number, when the fault is in a row. */
  readonly brokenAt: number | null;
  readonly reason: string | null;
  readonly rows: number;
  readonly from: number | null;
  readonly to: number | null;
  /** Checkpoints that were checked against rows: the bundle's own, and the auditor's pins that fall inside the range. */
  readonly checkpointsChecked: number;
}

export interface BundleKeys {
  /** The broker's audit key, handed to the auditor. Needed to check each row. */
  readonly hmacKey: Uint8Array;
  /** The broker's checkpoint public key, pinned by the auditor (one key, for a broker that never rotated). */
  readonly publicKey?: KeyObject;
  /** Or the keys a root-signed audit roster trusts, each with the rows it may sign for (Phase 15). */
  readonly windows?: readonly AuditKeyWindow[];
  /** Checkpoints the auditor saw on an earlier visit. A bundle that disagrees with one, or ends before one, is refused. */
  readonly pins?: readonly Checkpoint[];
}

export const MAX_BUNDLE_ROWS = 100_000;

export function buildExport(rows: readonly AuditEntry[], checkpoints: readonly Checkpoint[], exportedBy: string, exportedAt: string, roster?: unknown): AuditExport {
  const first = rows[0];
  const last = rows[rows.length - 1];
  if (first === undefined || last === undefined) throw new Error('An export needs at least one row.');
  return { format: 1, kind: 'export', from: first.n, to: last.n, count: rows.length, exportedAt, exportedBy, rows, checkpoints, ...(roster === undefined || roster === null ? {} : { roster }) };
}

const failure = (kind: BundleVerification['kind'], reason: string, extra: Partial<BundleVerification> = {}): BundleVerification => ({ ok: false, kind, brokenAt: null, reason, rows: 0, from: null, to: null, checkpointsChecked: 0, ...extra });

/**
 * Checks a bundle with only the bundle, the audit key and the pinned public key. Every refusal names why, and names the
 * row when it is a row's fault.
 */
export function verifyBundle(input: unknown, keys: BundleKeys): BundleVerification {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return failure('unknown', 'This is not an audit bundle.');
  if (keys.publicKey === undefined && keys.windows === undefined) return failure('unknown', 'No audit key was given: pin a public key, or a root whose roster lists the keys.');
  const bundle = input as Record<string, unknown>;
  if (bundle['format'] !== 1) return failure('unknown', 'This is not an audit bundle this version can read.');
  if (bundle['kind'] === 'view') {
    const count = Array.isArray(bundle['rows']) ? bundle['rows'].length : 0;
    return failure('view', 'This is a filtered view: a selection of rows, not the chain. Rows missing from it cannot be told from rows that never existed, so it proves nothing. Ask for an export.', { rows: count });
  }
  if (bundle['kind'] !== 'export') return failure('unknown', 'This is not an audit bundle.');
  const { from, to, count, rows: rawRows, checkpoints: rawCheckpoints } = bundle;
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || !Number.isSafeInteger(count) || (from as number) < 1 || (to as number) < (from as number)) return failure('export', 'The range in this export is not valid.');
  if (!Array.isArray(rawRows) || !Array.isArray(rawCheckpoints)) return failure('export', 'This export has no rows or no checkpoints.');
  if (rawRows.length > MAX_BUNDLE_ROWS || rawCheckpoints.length > MAX_BUNDLE_ROWS) return failure('export', 'This export is larger than hn will check.');
  const start = from as number;
  const end = to as number;
  const header = { from: start, to: end, rows: rawRows.length };
  if (rawRows.length !== (count as number) || rawRows.length !== end - start + 1) return failure('export', `The export says it holds rows ${start} to ${end} but has ${rawRows.length}, so rows were removed or added.`, header);

  // The rows: each one a well-formed row, in order, linked to the one before, with its own MAC.
  const rows: AuditEntry[] = [];
  let previous: AuditEntry | null = null;
  for (const [index, raw] of rawRows.entries()) {
    const row = entryFromValue(raw);
    const expected = start + index;
    if (row === null) return failure('export', `Row ${expected} is not a valid audit row.`, { ...header, brokenAt: expected });
    if (row.n !== expected) return failure('export', `Row ${expected} is numbered ${row.n}, so a row was removed, added or moved.`, { ...header, brokenAt: expected });
    if (previous === null ? start === 1 && row.prev !== GENESIS : row.prev !== previous.mac) return failure('export', `Row ${row.n} does not follow ${previous === null ? 'the start of the chain' : `row ${previous.n}`}.`, { ...header, brokenAt: row.n });
    if (macOf(keys.hmacKey, row) !== row.mac) return failure('export', `Row ${row.n} was changed after it was written, or this is not the broker's audit key.`, { ...header, brokenAt: row.n });
    rows.push(row);
    previous = row;
  }
  const head = rows[rows.length - 1] as AuditEntry;
  const first = rows[0] as AuditEntry;

  // The checkpoints: signed by the pinned key, and agreeing with the rows they name.
  let checked = 0;
  let covered = false;
  const agree = (checkpoint: Checkpoint, label: string): string | null => {
    if (checkpoint.n > end) return `${label} is for row ${checkpoint.n}, but this export ends at row ${end}, so the end was cut off or the export is out of date.`;
    if (checkpoint.n >= start) {
      const row = rows[checkpoint.n - start] as AuditEntry;
      if (row.mac !== checkpoint.mac) return `${label} for row ${checkpoint.n} does not match the row in this export, so the rows are not the ones the broker signed.`;
      checked += 1;
    } else if (checkpoint.n === start - 1) {
      if (first.prev !== checkpoint.mac) return `${label} for row ${checkpoint.n} does not match where this export begins.`;
      checked += 1;
    }
    return null;
  };
  for (const [index, raw] of rawCheckpoints.entries()) {
    const checkpoint = checkpointFromValue(raw);
    const label = `Checkpoint ${index + 1}`;
    if (checkpoint === null) return failure('export', `${label} is not valid.`, header);
    // Under a roster, an extra checkpoint a key signed after its cut-off (a key revoked since the export was first made) is
    // set aside, because the rows are checked by the others. The one that covers the last row is never set aside.
    if (keys.windows !== undefined && checkpoint.n !== end) {
      const standing = checkpointStanding(checkpoint, keys.windows).state;
      if (standing === 'unknown' || standing === 'outside') continue;
    }
    const unsigned = checkpointProblem(checkpoint, keys, 'was not signed by the pinned audit key (it is forged, edited, or from another broker).');
    if (unsigned !== null) return failure('export', `${label} ${unsigned}`, header);
    const problem = agree(checkpoint, label);
    if (problem !== null) return failure('export', problem, { ...header, brokenAt: checkpoint.n >= start && checkpoint.n <= end ? checkpoint.n : null });
    if (checkpoint.n === end && checkpoint.mac === head.mac) covered = true;
  }
  if (!covered) return failure('export', `No signed checkpoint covers row ${end}, the last row. Rows may have been added after the broker's last word, or the end cut off.`, { ...header, brokenAt: end });

  // The auditor's own record of earlier visits.
  for (const [index, pin] of (keys.pins ?? []).entries()) {
    const label = `Your pinned checkpoint ${index + 1}`;
    // Under a roster, a pin the roster no longer lets that key sign (a revoked key after its cut-off) is set aside, not a
    // fault of the export; a forged one still is.
    if (keys.windows !== undefined) {
      const standing = checkpointStanding(pin, keys.windows).state;
      if (standing === 'unknown' || standing === 'outside') continue;
    }
    const pinProblem = checkpointProblem(pin, keys, 'does not verify with this key.');
    if (pinProblem !== null) return failure('export', `${label} ${pinProblem}`, header);
    const problem = agree(pin, label);
    if (problem !== null) return failure('export', problem, header);
  }
  return { ok: true, kind: 'export', brokenAt: null, reason: null, rows: rows.length, from: start, to: end, checkpointsChecked: checked };
}
