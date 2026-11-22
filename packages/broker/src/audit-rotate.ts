import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import { auditKeyId, checkpointFromValue, signCheckpoint } from '@hn/security';
import { RETIRED_FILE, ROSTER_FILE, readRetired, type RetiredKey } from './audit-checkpoints.ts';

/**
 * `hn broker rotate-audit-key <state folder> <folder for the draft>` (Phase 15, decision 8). Retires the audit-signing
 * key and starts a new one, with the broker stopped:
 *
 *  1. the old key signs one last checkpoint at the newest row, so its era ends on a row it vouched for;
 *  2. its public half and that row are recorded in `audit-retired.json` (the broker keeps accepting its older
 *     checkpoints and never lets it sign again);
 *  3. a new key replaces it, and the old private key is overwritten and gone;
 *  4. a draft roster lists every key with the rows it signed for. The operator signs it with the ROOT key
 *     (`hn trust sign`) and puts the result at `audit-roster.json` in the state folder.
 *
 * A leaked key is retired the same way, then listed as revoked in the roster with the row the leak began at
 * (`afterRow`), so its checkpoints after that row are refused.
 */

async function lastRow(state: string): Promise<{ n: number; mac: string }> {
  let text: string;
  try {
    text = await readFile(join(state, 'audit.jsonl'), 'utf8');
  } catch {
    return { n: 0, mac: '' };
  }
  const lines = text.split('\n');
  // A last line with no newline after it is a write that never finished; it is not a row.
  if (lines[lines.length - 1] !== '') lines.pop();
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index];
    if (line === undefined || line === '') continue;
    const row = JSON.parse(line) as { n?: unknown; mac?: unknown };
    if (!Number.isSafeInteger(row.n) || typeof row.mac !== 'string') throw new HnError('BAD_COMMAND', 'The last row of audit.jsonl is not a row, so the audit key is not rotated. Start the broker once to check the chain, then try again.');
    return { n: row.n as number, mac: row.mac };
  }
  return { n: 0, mac: '' };
}

export async function rotateAuditKey(state: string, folder: string, out: (text: string) => void, now: Date = new Date()): Promise<void> {
  let oldPrivate;
  try {
    oldPrivate = createPrivateKey(await readFile(join(state, 'audit-sign.key')));
  } catch {
    throw new HnError('BAD_COMMAND', `${state} has no audit-signing key yet. Start the broker once, then run this again.`);
  }
  const retired = await readRetired(state);
  const boundary = Math.max(-1, ...retired.map((item) => item.toRow));
  const head = await lastRow(state);
  if (retired.length > 0 && head.n <= boundary) throw new HnError('BAD_COMMAND', `The current audit-signing key has signed nothing since the last rotation (the newest row is ${head.n}). Rotate after more rows have been written.`);
  const oldPublic = createPublicKey(oldPrivate);
  const oldId = auditKeyId(oldPublic);
  // 1. The old key's last word, so its era ends on a row it vouched for. The same row is never signed twice.
  if (head.n >= 1) {
    const path = join(state, 'checkpoints.jsonl');
    const have = await readFile(path, 'utf8').catch(() => '');
    const signed = have.split('\n').some((line) => {
      try {
        const found = line === '' ? null : checkpointFromValue(JSON.parse(line));
        return found !== null && found.n === head.n && found.mac === head.mac;
      } catch {
        return false;
      }
    });
    if (!signed) await appendFile(path, `${JSON.stringify(signCheckpoint(head, now.toISOString(), oldPrivate))}\n`, { mode: 0o600 });
  }
  // 2. The old key's public half and its last row.
  const nowRetired: RetiredKey[] = [...retired, { keyId: oldId, publicKey: oldPublic.export({ type: 'spki', format: 'pem' }).toString(), toRow: head.n }];
  await writeFile(join(state, RETIRED_FILE), `${JSON.stringify(nowRetired, null, 2)}\n`, { mode: 0o600 });
  // 3. The new key replaces the old one in one step.
  const fresh = generateKeyPairSync('ed25519');
  const temp = join(state, `audit-sign.key.${process.pid}.new`);
  await writeFile(temp, fresh.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  await rename(temp, join(state, 'audit-sign.key'));
  const freshPem = fresh.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const freshId = auditKeyId(fresh.publicKey);
  // 4. The draft roster.
  let serial = 1;
  try {
    const earlier = JSON.parse(await readFile(join(state, ROSTER_FILE), 'utf8')) as { roster?: { serial?: unknown } };
    if (typeof earlier.roster?.serial === 'number') serial = earlier.roster.serial + 1;
  } catch {
    // No roster yet.
  }
  const keys: { keyId: string; publicKey: string; fromRow: number; toRow?: number }[] = nowRetired.map((item, index) => ({ keyId: item.keyId, publicKey: item.publicKey, fromRow: index === 0 ? 0 : (nowRetired[index - 1] as RetiredKey).toRow + 1, toRow: item.toRow }));
  keys.push({ keyId: freshId, publicKey: freshPem, fromRow: head.n + 1 });
  const draft = { purpose: 'audit', serial, keys, revoked: [] };
  await mkdir(folder, { recursive: true });
  const draftPath = join(folder, 'audit-roster-draft.json');
  await writeFile(draftPath, `${JSON.stringify(draft, null, 2)}\n`);
  out(`Retired audit-signing key ${oldId} at row ${head.n}; the new key is ${freshId} (rows ${head.n + 1} onward). The old private key is gone from ${state}.
Wrote ${draftPath}. Now, with the ROOT key (never on the broker):
  hn trust sign ${draftPath} <root-key.pem> <root key id> ${join(state, ROSTER_FILE)}
Until that roster is in place, an auditor who pinned only the old key cannot verify checkpoints from the new one.
If the old key LEAKED, add to "revoked" in the draft before signing: { "keyId": "${oldId}", "reason": "...", "afterRow": <the last row you trust it for> }.
`);
}
