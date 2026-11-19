import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { ORIGINS, toolCallsOf, type Origin, type SessionEvent } from '@hn/core';
import { join as joinOrigins } from '@hn/security';
import { parseLog } from '@hn/session';
import { ftsQuery, openDatabase, type DatabaseSync } from './sqlite.ts';

const MAX_TEXT = 4_000;
const MAX_LIMIT = 50;
const ORIGIN_SET: ReadonlySet<string> = new Set(ORIGINS);

export interface SessionHit {
  readonly session: string;
  readonly seq: number;
  readonly ts: string;
  readonly type: string;
  /** The row's origin, or `web` when its log did not verify: a forged log is the least trusted text there is. */
  readonly origin: Origin;
  readonly tool: string | null;
  readonly snippet: string;
}

export interface SessionFilters {
  readonly origins?: readonly Origin[];
  readonly session?: string;
  readonly since?: string;
  readonly until?: string;
  readonly tool?: string;
  readonly limit?: number;
}

export interface SessionIndexOptions {
  /** The SQLite file. It is an index only; deleting it loses nothing. */
  readonly db: string;
  /** This project's folder of session logs: `sessions/<projectKey>`. */
  readonly logs: string;
  readonly key: Buffer;
}

type Row = Record<string, unknown>;

/** Text a row adds to the index, or null for rows that are not conversation (pinned frames, replacements). */
function textOf(event: SessionEvent, toolNames: Map<string, string>): { text: string; tool: string | null } | null {
  const data = event.data;
  if (data['surfaceOp'] !== undefined || data['pinned'] === true || data['recall'] === true) return null;
  if (event.type === 'user/message') return typeof data['text'] === 'string' ? { text: data['text'], tool: null } : null;
  if (event.type === 'assistant/message') {
    const calls = toolCallsOf(event);
    for (const call of calls) toolNames.set(call.id, call.name);
    const said = typeof data['text'] === 'string' ? data['text'] : '';
    const called = calls.map((call) => `${call.name} ${JSON.stringify(call.args).slice(0, 300)}`).join('\n');
    return { text: [said, called].filter((part) => part !== '').join('\n'), tool: calls[0]?.name ?? null };
  }
  if (event.type === 'tool/result') {
    const callId = typeof data['callId'] === 'string' ? data['callId'] : '';
    return { text: typeof data['content'] === 'string' ? data['content'] : '', tool: toolNames.get(callId) ?? null };
  }
  return null;
}

/** The origin a hit shows. Words the person typed or picked count as the harness's own record, never as a new `user` row. */
function shownOrigin(row: Row): Origin {
  if (row['verified'] !== 1) return 'web';
  const origin = String(row['origin']);
  if (!ORIGIN_SET.has(origin)) return 'web';
  return origin === 'user' || origin === 'human-selected' ? 'harness' : (origin as Origin);
}

/**
 * Search over past sessions of this project (10.1): SQLite FTS5 rebuilt from the logs, never a
 * second truth. Every hit is a real row with its session, seq and origin. No model is involved.
 */
export class SessionIndex {
  readonly #db: DatabaseSync;
  readonly #logs: string;
  readonly #key: Buffer;

  private constructor(options: SessionIndexOptions) {
    this.#db = openDatabase(options.db);
    this.#logs = options.logs;
    this.#key = options.key;
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS logs(path TEXT PRIMARY KEY, size INTEGER, mtime REAL, verified INTEGER);
      CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, path TEXT, session TEXT, seq INTEGER, ts TEXT, type TEXT, origin TEXT, tool TEXT, text TEXT, verified INTEGER);
      CREATE INDEX IF NOT EXISTS events_session ON events(session, seq);
      CREATE INDEX IF NOT EXISTS events_path ON events(path);
      CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(text, tokenize='unicode61');
    `);
  }

  static open(options: SessionIndexOptions): SessionIndex {
    return new SessionIndex(options);
  }

  /** Brings the index up to date with the logs on disk: new or grown logs are read again, vanished ones removed. */
  async refresh(): Promise<number> {
    const files = await logFiles(this.#logs);
    const known = new Map((this.#db.prepare('SELECT path, size, mtime FROM logs').all() as Row[]).map((row) => [String(row['path']), row]));
    let indexed = 0;
    for (const file of files) {
      const info = await stat(file).catch(() => null);
      if (info === null) continue;
      const seen = known.get(file);
      known.delete(file);
      if (seen !== undefined && seen['size'] === info.size && seen['mtime'] === info.mtimeMs) continue;
      this.#index(file, await readFile(file), info.size, info.mtimeMs);
      indexed += 1;
    }
    for (const gone of known.keys()) this.#forget(gone);
    return indexed;
  }

  /** Throws the index away and builds it again from the logs. */
  async rebuild(): Promise<number> {
    this.#db.exec('DELETE FROM events_fts; DELETE FROM events; DELETE FROM logs;');
    return this.refresh();
  }

  #forget(path: string): void {
    this.#db.prepare('DELETE FROM events_fts WHERE rowid IN (SELECT id FROM events WHERE path = ?)').run(path);
    this.#db.prepare('DELETE FROM events WHERE path = ?').run(path);
    this.#db.prepare('DELETE FROM logs WHERE path = ?').run(path);
  }

  #index(path: string, bytes: Buffer, size: number, mtime: number): void {
    const log = parseLog(bytes, this.#key);
    const verified = log.trust === 'verified' ? 1 : 0;
    const session = path.split(/[\\/]/).at(-1) ?? path;
    const insert = this.#db.prepare('INSERT INTO events(path, session, seq, ts, type, origin, tool, text, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    const insertText = this.#db.prepare('INSERT INTO events_fts(rowid, text) VALUES (?, ?)');
    this.#db.exec('BEGIN');
    try {
      this.#forget(path);
      const toolNames = new Map<string, string>();
      for (const event of log.events) {
        const found = textOf(event, toolNames);
        if (found === null || found.text.trim() === '') continue;
        const text = found.text.slice(0, MAX_TEXT);
        const result = insert.run(path, session, event.seq, event.ts, event.type, event.origin, found.tool, text, verified);
        insertText.run(result.lastInsertRowid, text);
      }
      this.#db.prepare('INSERT INTO logs(path, size, mtime, verified) VALUES (?, ?, ?, ?)').run(path, size, mtime, verified);
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
  }

  /** Hits for every word first; if none, for any word. Ranked by BM25. */
  search(query: string, filters: SessionFilters = {}): { hits: SessionHit[]; origin: Origin } {
    const limit = Math.max(1, Math.min(MAX_LIMIT, filters.limit ?? 10));
    for (const mode of ['AND', 'OR'] as const) {
      const match = ftsQuery(query, mode);
      if (match === null) break;
      const where: string[] = ['events_fts MATCH ?'];
      const params: (string | number)[] = [match];
      if (filters.session !== undefined) (where.push('e.session = ?'), params.push(filters.session));
      if (filters.since !== undefined) (where.push('e.ts >= ?'), params.push(filters.since));
      if (filters.until !== undefined) (where.push('e.ts <= ?'), params.push(filters.until));
      if (filters.tool !== undefined) (where.push('e.tool = ?'), params.push(filters.tool));
      if (filters.origins !== undefined && filters.origins.length > 0) {
        where.push(`e.origin IN (${filters.origins.map(() => '?').join(', ')})`);
        params.push(...filters.origins);
      }
      const rows = this.#db
        .prepare(`SELECT e.session, e.seq, e.ts, e.type, e.origin, e.tool, e.verified, snippet(events_fts, 0, '[', ']', '…', 24) AS snip
          FROM events_fts JOIN events e ON e.id = events_fts.rowid WHERE ${where.join(' AND ')} ORDER BY bm25(events_fts) LIMIT ?`)
        .all(...params, limit) as Row[];
      if (rows.length === 0) continue;
      const hits = rows.map((row): SessionHit => ({
        session: String(row['session']),
        seq: Number(row['seq']),
        ts: String(row['ts']),
        type: String(row['type']),
        origin: shownOrigin(row),
        tool: row['tool'] === null ? null : String(row['tool']),
        snippet: String(row['snip']),
      }));
      return { hits, origin: joinOrigins(...hits.map((hit) => hit.origin)) };
    }
    return { hits: [], origin: 'harness' };
  }

  /** The indexed rows around one hit, in order. */
  trace(session: string, seq: number, around = 5): { rows: (SessionHit & { text: string })[]; origin: Origin } {
    const span = Math.max(0, Math.min(20, around));
    const rows = this.#db
      .prepare('SELECT session, seq, ts, type, origin, tool, verified, text FROM events WHERE session = ? AND seq BETWEEN ? AND ? ORDER BY seq')
      .all(session, seq - span * 4, seq + span * 4) as Row[];
    const index = rows.findIndex((row) => Number(row['seq']) >= seq);
    const start = Math.max(0, (index === -1 ? rows.length : index) - span);
    const picked = rows.slice(start, start + span * 2 + 1).map((row) => ({
      session: String(row['session']),
      seq: Number(row['seq']),
      ts: String(row['ts']),
      type: String(row['type']),
      origin: shownOrigin(row),
      tool: row['tool'] === null ? null : String(row['tool']),
      snippet: '',
      text: String(row['text']).slice(0, 600),
    }));
    return { rows: picked, origin: joinOrigins(...picked.map((row) => row.origin)) };
  }

  close(): void {
    this.#db.close();
  }
}

/** Session logs in a project folder, with each child's log under `<parent>.children/`. Files with a dot are not logs. */
async function logFiles(folder: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(folder, { withFileTypes: true }).catch(() => [])) {
    if (entry.isFile() && !entry.name.includes('.')) out.push(join(folder, entry.name));
    if (entry.isDirectory() && entry.name.endsWith('.children')) {
      for (const child of await readdir(join(folder, entry.name), { withFileTypes: true }).catch(() => [])) {
        if (child.isFile() && !child.name.includes('.')) out.push(join(folder, entry.name, child.name));
      }
    }
  }
  return out.sort();
}
