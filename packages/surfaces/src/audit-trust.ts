import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import { RosterError, applyRoster, auditWindows, initialTrust, type AuditKeyWindow, type KeyTrust } from '@hn/security';

/**
 * What an auditor keeps about which audit-signing keys to believe (Phase 15): in the folder `hn audit pin` writes,
 * `audit-root.pem` (the root key the operator gave them, pinned once) and `audit-trust.json` (the newest roster's
 * result, so a revocation they have seen is never forgotten and an older roster cannot undo it).
 */

const ROOT_FILE = 'audit-root.pem';
const STATE_FILE = 'audit-trust.json';

const norm = (pem: string): string => pem.trim().replace(/\r/g, '');
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

export async function readAuditRoot(folder: string): Promise<string | null> {
  return readFile(join(folder, ROOT_FILE), 'utf8').then(norm, () => null);
}

/** The state the auditor has kept, or null when they pinned no root. */
export async function readAuditTrust(folder: string): Promise<KeyTrust | null> {
  const root = await readAuditRoot(folder);
  if (root === null) return null;
  const text = await readFile(join(folder, STATE_FILE), 'utf8').catch(() => null);
  if (text === null) return initialTrust('audit', { keyId: 'audit-root', publicKey: root }, {});
  try {
    const parsed = JSON.parse(text) as KeyTrust;
    if (parsed.purpose !== 'audit') throw new Error('wrong purpose');
    return parsed;
  } catch {
    throw new HnError('TRUST_RECORD_REFUSED', `${join(folder, STATE_FILE)} is damaged, so no audit key is trusted from this folder. Delete it and run hn audit pin again (this forgets any revocation it held).`);
  }
}

/** Pins a root for the first time. A different root later is refused: it is another operator, or someone swapping it. */
export async function pinAuditRoot(folder: string, rootPem: string): Promise<'pinned' | 'same'> {
  await mkdir(folder, { recursive: true });
  const kept = await readAuditRoot(folder);
  if (kept !== null && kept !== norm(rootPem)) throw new HnError('AUDIT_KEY_MISMATCH', `The root key you gave is not the one already pinned in ${join(folder, ROOT_FILE)}. Nothing was changed.`);
  if (kept === null) await writeFile(join(folder, ROOT_FILE), `${norm(rootPem)}\n`);
  return kept === null ? 'pinned' : 'same';
}

/** The state with the root's label taken from the roster that is being offered (the label is only a name; the key decides). */
function relabelled(state: KeyTrust, signed: unknown): KeyTrust {
  const label = isRecord(signed) && typeof signed['rootKeyId'] === 'string' ? signed['rootKeyId'] : null;
  return label !== null && state.serial === 0 && state.retiredRoots.length === 0 ? { ...state, root: { keyId: label, publicKey: state.root.publicKey } } : state;
}

/** Applies a roster to what the auditor has kept, and keeps the result. A roster that does not check out throws. */
export async function offerAuditRoster(folder: string, signed: unknown): Promise<KeyTrust> {
  const state = await readAuditTrust(folder);
  if (state === null) throw new HnError('BAD_COMMAND', 'No root is pinned in this folder. Run: hn audit pin <folder> --root <the root public key you were given>');
  const next = applyRoster(relabelled(state, signed), signed);
  if (next !== state) await writeFile(join(folder, STATE_FILE), JSON.stringify(next));
  return next;
}

/**
 * The audit keys to believe for a bundle: what the auditor has kept, plus the roster inside the bundle when it is newer.
 * A bundle's roster that is older than the kept one is ignored, so a stale roster (from before a revocation) cannot be
 * used to pass off a leaked key's checkpoints. One that does not check out against the root is an error.
 */
export async function auditWindowsFor(folder: string, bundleRoster: unknown): Promise<{ windows: AuditKeyWindow[]; serial: number }> {
  const state = await readAuditTrust(folder);
  if (state === null) throw new HnError('BAD_COMMAND', `No root is pinned in ${folder}. Run: hn audit pin ${folder} --root <the root public key you were given>`);
  let now = state;
  if (bundleRoster !== undefined && bundleRoster !== null) {
    try {
      now = applyRoster(relabelled(state, bundleRoster), bundleRoster);
    } catch (error) {
      const older = error instanceof RosterError && /older than serial/.test(error.message);
      if (!older) throw new HnError('AUDIT_ROSTER_REFUSED', `The roster in the bundle was refused: ${error instanceof Error ? error.message : String(error)}`);
      // An older roster than the one kept: the kept one stands.
    }
  }
  if (now.serial === 0) throw new HnError('AUDIT_ROSTER_REFUSED', 'There is no roster: neither in the bundle nor kept from an earlier visit, so no audit key is trusted. Ask the operator for the signed audit roster.');
  return { windows: auditWindows(now), serial: now.serial };
}
