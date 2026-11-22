import { open, stat } from 'node:fs/promises';
import { entryFromValue, type AuditEntry } from '@hn/security';

/**
 * What the broker can answer about its own audit chain without loading it into a response: a compact index of every row
 * (number, time, type, who and which session it names, where it sits in the file) built once when the chain has been
 * verified at start, and kept up to date as rows are written. Rows are read back from the file by position, so a query
 * touches only the rows it returns.
 *
 * The index holds nothing a client sent except through the broker's own rows, and a filter value is only ever compared
 * (equal, or a prefix): no filter text is ever turned into a pattern.
 */

export interface IndexedRow {
  readonly n: number;
  readonly time: number;
  readonly type: string;
  readonly mac: string;
  /** Everyone the row names: `user`, `requester` and `approver`. */
  readonly people: readonly string[];
  readonly session: string | null;
  readonly offset: number;
  readonly length: number;
}

export interface RowFilter {
  readonly user?: string;
  readonly session?: string;
  /** A row's type must start with this. */
  readonly type?: string;
  readonly since?: number;
  readonly until?: number;
}

export interface ApprovalRecord {
  readonly id: string;
  readonly requester: string | null;
  readonly action: string | null;
  readonly requestedAt: string | null;
  readonly state: 'pending' | 'approved' | 'denied' | 'used';
  readonly decidedBy: string | null;
  readonly decidedAt: string | null;
  readonly usedAt: string | null;
  /** Attempts by people who may not decide it. */
  readonly refused: readonly { readonly approver: string; readonly reason: string; readonly at: string }[];
  /** The rows that make up this record, so each line can be checked against the chain. */
  readonly rows: readonly number[];
}

export interface SessionRecord {
  readonly user: string;
  readonly session: string;
  readonly firstAt: string;
  readonly lastAt: string;
  readonly modelCalls: number;
  readonly usd: number;
  readonly tokens: number;
  readonly firstRow: number;
  readonly lastRow: number;
}

const text = (value: unknown): string | null => (typeof value === 'string' ? value : null);

function indexRow(entry: AuditEntry, offset: number, length: number): IndexedRow {
  const people = [...new Set(['user', 'requester', 'approver'].flatMap((key) => (typeof entry.data[key] === 'string' ? [entry.data[key] as string] : [])))];
  return { n: entry.n, time: Date.parse(entry.ts), type: entry.type, mac: entry.mac, people, session: text(entry.data['session']), offset, length };
}

export class AuditStore {
  readonly #path: string;
  readonly #rows: IndexedRow[] = [];
  #size = 0;

  constructor(path: string) {
    this.#path = path;
  }

  /** Indexes a file whose chain has already been verified. */
  async load(): Promise<void> {
    let bytes: Buffer;
    try {
      const handle = await open(this.#path, 'r');
      try {
        bytes = await handle.readFile();
      } finally {
        await handle.close();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw error;
    }
    let offset = 0;
    while (offset < bytes.length) {
      const end = bytes.indexOf(0x0a, offset);
      if (end === -1) break;
      const entry = entryFromValue(JSON.parse(bytes.subarray(offset, end).toString('utf8')));
      if (entry === null) throw new Error(`${this.#path} has a row the chain accepted but the index cannot read.`);
      this.#rows.push(indexRow(entry, offset, end + 1 - offset));
      offset = end + 1;
    }
    this.#size = offset;
  }

  /** Adds the row just written. Rows are written one after another, so its place is the end of the file so far. */
  add(entry: AuditEntry): void {
    const length = Buffer.byteLength(`${JSON.stringify(entry)}\n`);
    this.#rows.push(indexRow(entry, this.#size, length));
    this.#size += length;
  }

  get head(): { readonly n: number; readonly mac: string } {
    const last = this.#rows[this.#rows.length - 1];
    return last === undefined ? { n: 0, mac: '0'.repeat(64) } : { n: last.n, mac: last.mac };
  }

  get count(): number {
    return this.#rows.length;
  }

  macOf(n: number): string | null {
    return this.#rows[n - 1]?.mac ?? null;
  }

  /** The index rows that match, after row `after`, oldest first. */
  match(filter: RowFilter, after = 0): IndexedRow[] {
    const out: IndexedRow[] = [];
    for (let at = after; at < this.#rows.length; at += 1) {
      const row = this.#rows[at] as IndexedRow;
      if (filter.user !== undefined && !row.people.includes(filter.user)) continue;
      if (filter.session !== undefined && row.session !== filter.session) continue;
      if (filter.type !== undefined && !row.type.startsWith(filter.type)) continue;
      if (filter.since !== undefined && row.time < filter.since) continue;
      if (filter.until !== undefined && row.time > filter.until) continue;
      out.push(row);
    }
    return out;
  }

  /** Reads rows by number, `from` to `to` inclusive, in one read. */
  async read(from: number, to: number): Promise<AuditEntry[]> {
    const first = this.#rows[from - 1];
    const last = this.#rows[to - 1];
    if (first === undefined || last === undefined || to < from) return [];
    const length = last.offset + last.length - first.offset;
    const handle = await open(this.#path, 'r');
    try {
      const buffer = Buffer.alloc(length);
      let done = 0;
      while (done < length) {
        const { bytesRead } = await handle.read(buffer, done, length - done, first.offset + done);
        if (bytesRead === 0) break;
        done += bytesRead;
      }
      return buffer.subarray(0, done).toString('utf8').split('\n').filter((line) => line !== '').map((line) => {
        const entry = entryFromValue(JSON.parse(line));
        if (entry === null) throw new Error('The audit file changed under the broker.');
        return entry;
      });
    } finally {
      await handle.close();
    }
  }

  /** Rows by their index entries, reading each contiguous run once. */
  async readMatched(matched: readonly IndexedRow[]): Promise<AuditEntry[]> {
    const out: AuditEntry[] = [];
    let at = 0;
    while (at < matched.length) {
      let end = at;
      while (end + 1 < matched.length && (matched[end + 1] as IndexedRow).n === (matched[end] as IndexedRow).n + 1) end += 1;
      out.push(...(await this.read((matched[at] as IndexedRow).n, (matched[end] as IndexedRow).n)));
      at = end + 1;
    }
    return out;
  }

  /** Whether the file still has the size the index expects, so a change made behind the broker's back is noticed. */
  async intact(): Promise<boolean> {
    try {
      return (await stat(this.#path)).size === this.#size;
    } catch {
      return this.#size === 0;
    }
  }

  /** Each approval as one record, joined by its id from the broker's approval rows. Oldest request first. */
  async approvals(filter: { user?: string; state?: ApprovalRecord['state'] | 'refused' } = {}): Promise<ApprovalRecord[]> {
    const rows = await this.readMatched(this.match({ type: 'broker/approval-' }));
    const byId = new Map<string, { -readonly [K in keyof ApprovalRecord]: ApprovalRecord[K] } & { refused: { approver: string; reason: string; at: string }[]; rows: number[] }>();
    const get = (id: string): NonNullable<ReturnType<typeof byId.get>> => {
      let found = byId.get(id);
      if (found === undefined) byId.set(id, (found = { id, requester: null, action: null, requestedAt: null, state: 'pending', decidedBy: null, decidedAt: null, usedAt: null, refused: [], rows: [] }));
      return found;
    };
    for (const row of rows) {
      const id = text(row.data['id']);
      if (id === null) continue;
      const record = get(id);
      record.rows.push(row.n);
      if (row.type === 'broker/approval-requested') {
        record.requester = text(row.data['user']);
        record.action = text(row.data['action']);
        record.requestedAt = row.ts;
      } else if (row.type === 'broker/approval-decided') {
        record.requester ??= text(row.data['requester']);
        record.action ??= text(row.data['action']);
        record.state = row.data['decision'] === 'approve' ? 'approved' : 'denied';
        record.decidedBy = text(row.data['approver']);
        record.decidedAt = row.ts;
      } else if (row.type === 'broker/approval-used') {
        record.state = 'used';
        record.usedAt = row.ts;
        record.decidedBy ??= text(row.data['decidedBy']);
      } else if (row.type === 'broker/approval-refused') {
        record.refused.push({ approver: text(row.data['approver']) ?? '', reason: text(row.data['reason']) ?? '', at: row.ts });
      }
    }
    return [...byId.values()].filter((record) => (filter.user === undefined || record.requester === filter.user || record.decidedBy === filter.user || record.refused.some((item) => item.approver === filter.user)) && (filter.state === undefined || (filter.state === 'refused' ? record.refused.length > 0 : record.state === filter.state)));
  }

  /** One record per person and session, from the rows that name a session. */
  async sessions(user?: string): Promise<SessionRecord[]> {
    const rows = await this.readMatched(this.match({ ...(user === undefined ? {} : { user }) }).filter((row) => row.session !== null && (row.type === 'broker/session' || row.type === 'broker/model')));
    const byKey = new Map<string, { -readonly [K in keyof SessionRecord]: SessionRecord[K] }>();
    for (const row of rows) {
      const who = text(row.data['user']);
      const session = text(row.data['session']);
      if (who === null || session === null) continue;
      const key = `${who}\u0000${session}`;
      let found = byKey.get(key);
      if (found === undefined) byKey.set(key, (found = { user: who, session, firstAt: row.ts, lastAt: row.ts, modelCalls: 0, usd: 0, tokens: 0, firstRow: row.n, lastRow: row.n }));
      found.lastAt = row.ts;
      found.lastRow = row.n;
      if (row.type === 'broker/model') {
        found.modelCalls += 1;
        if (typeof row.data['usd'] === 'number') found.usd += row.data['usd'];
        if (typeof row.data['tokens'] === 'number') found.tokens += row.data['tokens'];
      }
    }
    return [...byKey.values()];
  }
}
