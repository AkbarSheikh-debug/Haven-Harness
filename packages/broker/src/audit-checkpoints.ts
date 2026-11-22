import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { AuditError, auditKeyId, checkpointFromValue, checkpointValid, signCheckpoint, type Checkpoint } from '@hn/security';

/**
 * The broker's signed checkpoints (Phase 14, decision 4). The signing key is made on first start and lives in the
 * broker's state folder next to the audit key; the public half is what an auditor pins. A checkpoint file that does not
 * agree with the chain, or with the key, is refused at start, never repaired: someone changed one of the two.
 */

/** A signing key the broker stopped using (Phase 15): its checkpoints are history, valid up to the row it was retired at. */
export interface RetiredKey {
  readonly keyId: string;
  readonly publicKey: string;
  readonly toRow: number;
}

export const RETIRED_FILE = 'audit-retired.json';
export const ROSTER_FILE = 'audit-roster.json';

/** The keys retired so far; a missing file is none, a damaged one is refused. */
export async function readRetired(state: string): Promise<RetiredKey[]> {
  let text: string;
  try {
    text = await readFile(join(state, RETIRED_FILE), 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new AuditError(`${RETIRED_FILE} is not valid JSON, so the broker does not know which older audit-signing keys to accept.`);
  }
  if (!Array.isArray(parsed)) throw new AuditError(`${RETIRED_FILE} must be a list.`);
  return parsed.map((item, index) => {
    const entry = item as Partial<RetiredKey> | null;
    if (typeof entry?.keyId !== 'string' || typeof entry.publicKey !== 'string' || !Number.isSafeInteger(entry.toRow) || (entry.toRow as number) < 0) throw new AuditError(`${RETIRED_FILE} entry ${index + 1} is not a retired key.`);
    if (auditKeyId(createPublicKey(entry.publicKey)) !== entry.keyId) throw new AuditError(`${RETIRED_FILE} entry ${index + 1} names a key id that is not its public key's.`);
    return { keyId: entry.keyId, publicKey: entry.publicKey, toRow: entry.toRow as number };
  });
}

export interface CheckpointBook {
  /** Older signing keys, each with the last row it signed for. */
  readonly retired: readonly RetiredKey[];
  readonly publicKey: KeyObject;
  readonly publicPem: string;
  readonly keyId: string;
  list(): readonly Checkpoint[];
  /** Signs the row at this position. The same position and MAC is signed once; asking again returns the first. */
  sign(head: { readonly n: number; readonly mac: string }, now: Date): Promise<Checkpoint>;
}

export const PUBLIC_KEY_FILE = 'audit-sign.pub.pem';
const PRIVATE_KEY_FILE = 'audit-sign.key';
const FILE = 'checkpoints.jsonl';

/** Opens the book, checking every checkpoint against the key and against the verified chain (`macOf` gives a row's MAC). */
export async function openCheckpoints(state: string, macOf: (n: number) => string | null): Promise<CheckpointBook> {
  await mkdir(state, { recursive: true, mode: 0o700 });
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(await readFile(join(state, PRIVATE_KEY_FILE)));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    const pair = generateKeyPairSync('ed25519');
    await writeFile(join(state, PRIVATE_KEY_FILE), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    privateKey = pair.privateKey;
  }
  const publicKey = createPublicKey(privateKey);
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  // The public half is a convenience copy for the operator to hand over; the private key is the truth.
  await writeFile(join(state, PUBLIC_KEY_FILE), publicPem);
  const retired = await readRetired(state);
  const path = join(state, FILE);
  const known: Checkpoint[] = [];
  let text = '';
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const lines = text.split('\n');
  // A last line with no newline after it is a write the process died in the middle of, so it is dropped, not trusted.
  if (lines[lines.length - 1] !== '') {
    lines.pop();
    // Take the torn text out of the file too, or the next checkpoint would be written onto the end of it.
    await writeFile(path, lines.length === 0 ? '' : lines.map((line) => `${line}\n`).join(''), { mode: 0o600 });
  }
  for (const [index, line] of lines.entries()) {
    if (line === '') continue;
    let parsed: Checkpoint | null = null;
    try {
      parsed = checkpointFromValue(JSON.parse(line));
    } catch {
      parsed = null;
    }
    const where = `${path} line ${index + 1}`;
    if (parsed === null) throw new AuditError(`${where} is not a checkpoint.`);
    if (!checkpointValid(parsed, publicKey)) {
      const older = retired.find((item) => item.keyId === parsed.keyId);
      if (older === undefined || !checkpointValid(parsed, createPublicKey(older.publicKey))) throw new AuditError(`${where} was not signed by this broker's audit-signing key.`);
      if (parsed.n > older.toRow) throw new AuditError(`${where} is for row ${parsed.n}, but the key that signed it was retired at row ${older.toRow}, so it was signed after its retirement.`);
    }
    if (macOf(parsed.n) !== parsed.mac) throw new AuditError(`${where} names row ${parsed.n}, which is not in the audit chain as signed, so the chain or the checkpoints were changed.`);
    known.push(parsed);
  }
  let writes: Promise<unknown> = Promise.resolve();
  return {
    retired,
    publicKey,
    publicPem,
    keyId: auditKeyId(publicKey),
    list: () => known,
    sign(head, now) {
      const existing = known.find((item) => item.n === head.n && item.mac === head.mac);
      // Rows up to the newest retirement belong to the older keys, which can no longer sign: a new key signing one would
      // make a checkpoint no roster accepts.
      const boundary = Math.max(-1, ...retired.map((item) => item.toRow));
      if (existing === undefined && head.n <= boundary) return Promise.reject(new AuditError(`Row ${head.n} was covered by a retired audit-signing key (retired at row ${boundary}), which can no longer sign.`));
      if (existing !== undefined) return Promise.resolve(existing);
      const checkpoint = signCheckpoint(head, now.toISOString(), privateKey);
      known.push(checkpoint);
      const write = writes.then(() => appendFile(path, `${JSON.stringify(checkpoint)}\n`, { mode: 0o600 }));
      writes = write.catch(() => undefined);
      return write.then(() => checkpoint);
    },
  };
}
