import { createHmac } from 'node:crypto';
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { HnError } from '@hn/core';

/**
 * A tamper-evident record of what was asked and decided, meant to be shipped off the machine.
 * Each entry's MAC covers the one before it, so editing, removing, reordering or inserting a row
 * breaks everything after it. Removing the tail is caught by comparing against an anchored head.
 * With a key that stays on the machine this only proves tampering to someone who holds the key;
 * team mode anchors the head elsewhere.
 */

export const GENESIS = '0'.repeat(64);

export interface AuditEntry {
  readonly n: number;
  readonly ts: string;
  readonly type: string;
  readonly data: Readonly<Record<string, unknown>>;
  readonly prev: string;
  readonly mac: string;
}

export class AuditError extends HnError {
  constructor(message: string) {
    super('AUDIT_INVALID', message);
  }
}

/** Key order must not change the MAC, so objects are written with sorted keys. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function macOf(key: Uint8Array, entry: Omit<AuditEntry, 'mac'>): string {
  return createHmac('sha256', key).update(canonical([entry.n, entry.ts, entry.type, entry.data, entry.prev])).digest('hex');
}

export interface ChainHead {
  readonly n: number;
  readonly mac: string;
}

export interface ChainOptions {
  readonly key: Uint8Array;
  /** Resume after this entry. Omit for a new chain. */
  readonly head?: ChainHead;
  readonly now?: () => Date;
}

/** Pairs are enforced as rows are written: a decision needs an earlier ask, and each id is asked and decided once. */
class Pairing {
  readonly #asked = new Set<string>();
  readonly #decided = new Set<string>();

  check(type: string, data: Readonly<Record<string, unknown>>): string | null {
    if (type !== 'approval/asked' && type !== 'approval/decided') return null;
    const id = data['approvalId'];
    if (typeof id !== 'string' || id === '') return `${type} needs an approvalId.`;
    if (type === 'approval/asked') {
      if (this.#asked.has(id)) return `approval ${id} was asked twice.`;
      this.#asked.add(id);
      return null;
    }
    if (!this.#asked.has(id)) return `approval ${id} was decided but never asked.`;
    if (this.#decided.has(id)) return `approval ${id} was decided twice.`;
    this.#decided.add(id);
    return null;
  }

  get open(): string[] {
    return [...this.#asked].filter((id) => !this.#decided.has(id));
  }
}

export class AuditChain {
  readonly #key: Uint8Array;
  readonly #now: () => Date;
  readonly #pairing = new Pairing();
  #head: ChainHead;

  constructor(options: ChainOptions) {
    this.#key = options.key;
    this.#now = options.now ?? (() => new Date());
    this.#head = options.head ?? { n: 0, mac: GENESIS };
  }

  get head(): ChainHead {
    return this.#head;
  }

  /** Asks that were never decided, for example because the process died. */
  get openApprovals(): string[] {
    return this.#pairing.open;
  }

  /** Rebuilds pairing state from entries already verified, so a resumed chain keeps enforcing it. */
  adopt(entries: readonly AuditEntry[]): void {
    for (const entry of entries) this.#pairing.check(entry.type, entry.data);
  }

  append(type: string, data: Readonly<Record<string, unknown>>): AuditEntry {
    const problem = this.#pairing.check(type, data);
    if (problem !== null) throw new AuditError(problem);
    const body = { n: this.#head.n + 1, ts: this.#now().toISOString(), type, data, prev: this.#head.mac };
    const entry: AuditEntry = { ...body, mac: macOf(this.#key, body) };
    this.#head = { n: entry.n, mac: entry.mac };
    return entry;
  }
}

export interface Verification {
  readonly ok: boolean;
  readonly entries: readonly AuditEntry[];
  readonly head: ChainHead;
  /** 1-based number of the first bad row, when `ok` is false. */
  readonly brokenAt: number | null;
  readonly reason: string | null;
  readonly openApprovals: readonly string[];
}

const ENTRY_KEYS = new Set(['n', 'ts', 'type', 'data', 'prev', 'mac']);

/** A row from already-parsed JSON, or null when it is not exactly a row: unknown fields, wrong types and arrays are all refused. */
export function entryFromValue(raw: unknown): AuditEntry | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  if (Object.keys(record).some((key) => !ENTRY_KEYS.has(key))) return null;
  const { n, ts, type, data, prev, mac } = record;
  if (!Number.isSafeInteger(n) || typeof ts !== 'string' || typeof type !== 'string') return null;
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return null;
  if (typeof prev !== 'string' || typeof mac !== 'string') return null;
  return { n: n as number, ts, type, data: data as Record<string, unknown>, prev, mac };
}

function parseEntry(line: string): AuditEntry | null {
  try {
    return entryFromValue(JSON.parse(line));
  } catch {
    return null;
  }
}

/**
 * Checks every row. `expectedHead` is the last head known from somewhere an attacker could not edit;
 * without it a deleted tail cannot be told from a log that simply ended.
 */
export function verifyAudit(text: string, key: Uint8Array, expectedHead?: ChainHead): Verification {
  const entries: AuditEntry[] = [];
  const pairing = new Pairing();
  let head: ChainHead = { n: 0, mac: GENESIS };
  const fail = (brokenAt: number, reason: string): Verification => ({
    ok: false,
    entries,
    head,
    brokenAt,
    reason,
    openApprovals: pairing.open,
  });

  const lines = text.split('\n').filter((line) => line !== '');
  for (const [index, line] of lines.entries()) {
    const entry = parseEntry(line);
    const at = index + 1;
    if (entry === null) return fail(at, `Row ${at} is not a valid audit entry.`);
    if (entry.n !== head.n + 1) return fail(at, `Row ${at} is numbered ${entry.n}, so a row was removed, added or moved.`);
    if (entry.prev !== head.mac) return fail(at, `Row ${at} does not follow row ${head.n}.`);
    if (macOf(key, entry) !== entry.mac) return fail(at, `Row ${at} was changed after it was written.`);
    const problem = pairing.check(entry.type, entry.data);
    if (problem !== null) return fail(at, `Row ${at}: ${problem}`);
    entries.push(entry);
    head = { n: entry.n, mac: entry.mac };
  }
  if (expectedHead !== undefined && (expectedHead.n !== head.n || expectedHead.mac !== head.mac)) {
    return fail(head.n + 1, `The log ends at row ${head.n}, but row ${expectedHead.n} was expected, so the end was cut off.`);
  }
  return { ok: true, entries, head, brokenAt: null, reason: null, openApprovals: pairing.open };
}

export interface AuditFile {
  readonly chain: AuditChain;
  /** Writes one row and resolves when it is on disk. Rows are written in order. */
  record(type: string, data: Readonly<Record<string, unknown>>): Promise<AuditEntry>;
}

/** Opens (or creates) an audit file. A file that fails verification is refused, never repaired. */
export async function openAuditFile(path: string, key: Uint8Array, expectedHead?: ChainHead): Promise<AuditFile> {
  await mkdir(dirname(path), { recursive: true });
  let text = '';
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const verified = verifyAudit(text, key, expectedHead);
  if (!verified.ok) throw new AuditError(`${path} failed verification: ${verified.reason}`);
  const chain = new AuditChain({ key, head: verified.head });
  chain.adopt(verified.entries);
  let queue: Promise<unknown> = Promise.resolve();
  let failure: Error | null = null;
  return {
    chain,
    record(type, data) {
      // After a failed write the chain head is ahead of the disk, so nothing more may be written.
      if (failure !== null) return Promise.reject(new AuditError(`The audit file stopped accepting rows: ${failure.message}`));
      const entry = chain.append(type, data);
      const write = queue.then(() => appendFile(path, `${JSON.stringify(entry)}\n`, { mode: 0o600 }));
      queue = write.catch((error: unknown) => {
        failure = error instanceof Error ? error : new Error(String(error));
      });
      return write.then(() => entry);
    },
  };
}
