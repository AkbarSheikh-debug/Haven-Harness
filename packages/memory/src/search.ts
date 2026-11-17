import { createHash } from 'node:crypto';
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { ORIGINS, type Origin } from '@hn/core';
import { join as joinOrigins } from '@hn/security';
import { MemoryFile } from './memory-file.ts';
import type { MemoryPaths } from './paths.ts';
import type { MemoryEntry } from './record.ts';
import { ftsQuery, openDatabase, type DatabaseSync } from './sqlite.ts';

/** Constants from 10.4. A token is taken as four characters; the chunker only needs the size roughly. */
export const SEARCH = {
  chunkChars: 1_600,
  overlapChars: 320,
  vectorWeight: 0.7,
  keywordWeight: 0.3,
  candidateFactor: 4,
  minScore: 0.35,
  maxResults: 6,
  mmrLambda: 0.7,
  halfLifeDays: 30,
} as const;

export interface Chunk {
  readonly id: string;
  /** `USER.md`, `MEMORY.md` or `notes:YYYY-MM-DD`. */
  readonly source: string;
  readonly text: string;
  /** The worst origin of the entries inside. */
  readonly origin: Origin;
  readonly taint: 'clean' | 'untrusted';
  /** The newest entry's time, for decay. */
  readonly newest: string;
  /** USER.md and MEMORY.md never decay. */
  readonly evergreen: boolean;
}

export interface MemoryHit extends Chunk {
  readonly score: number;
}

/** Turns texts into vectors. Ollama by default; anything that keeps text on the machine fits. */
export interface Embedder {
  readonly model: string;
  embed(texts: readonly string[], signal?: AbortSignal): Promise<Float32Array[]>;
}

/** An embedder served by a local Ollama, so memory text never leaves the machine. */
export class OllamaEmbedder implements Embedder {
  readonly model: string;
  readonly #url: string;

  constructor(model: string, baseUrl = 'http://127.0.0.1:11434') {
    this.model = model;
    this.#url = `${baseUrl.replace(/\/+$/, '')}/api/embed`;
  }

  async embed(texts: readonly string[], signal?: AbortSignal): Promise<Float32Array[]> {
    const response = await fetch(this.#url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: this.model, input: texts }),
      signal: signal ?? AbortSignal.timeout(60_000),
    });
    if (!response.ok) throw new Error(`The embedding model answered ${response.status}.`);
    const body = (await response.json()) as { embeddings?: number[][] };
    if (!Array.isArray(body.embeddings) || body.embeddings.length !== texts.length) throw new Error('The embedding model returned no vectors.');
    return body.embeddings.map((vector) => Float32Array.from(vector));
  }
}

const hash = (text: string): string => createHash('sha256').update(text).digest('hex').slice(0, 32);

/**
 * Groups entries into chunks of about 400 tokens, each starting with about 80 tokens of the one before. A chunk
 * never mixes origins or taint: entries are first split into runs that share both, so one web line on a day cannot
 * mark the user's own lines of that day as web and keep them out of recall (found live).
 */
export function chunkEntries(source: string, entries: readonly MemoryEntry[], evergreen: boolean): Chunk[] {
  const runs: MemoryEntry[][] = [];
  for (const entry of entries) {
    const last = runs.at(-1)?.at(-1);
    if (last !== undefined && last.origin === entry.origin && last.taint === entry.taint) runs.at(-1)?.push(entry);
    else runs.push([entry]);
  }
  return runs.flatMap((run) => chunkRun(source, run, evergreen));
}

function chunkRun(source: string, entries: readonly MemoryEntry[], evergreen: boolean): Chunk[] {
  const chunks: Chunk[] = [];
  let start = 0;
  while (start < entries.length) {
    let end = start;
    let size = 0;
    while (end < entries.length && (end === start || size + (entries[end] as MemoryEntry).text.length <= SEARCH.chunkChars)) {
      size += (entries[end] as MemoryEntry).text.length + 1;
      end += 1;
    }
    const part = entries.slice(start, end);
    const text = part.map((entry) => entry.text).join('\n').slice(0, SEARCH.chunkChars * 2);
    chunks.push({
      id: hash(`${source}\n${text}`),
      source,
      text,
      origin: joinOrigins(...part.map((entry) => entry.origin)),
      taint: part.some((entry) => entry.taint === 'untrusted') ? 'untrusted' : 'clean',
      newest: part.map((entry) => entry.when).sort().at(-1) ?? new Date(0).toISOString(),
      evergreen,
    });
    if (end >= entries.length) break;
    // Step back over the newest entries until the overlap is covered, but always move forward.
    let back = end;
    let overlap = 0;
    while (back - 1 > start && overlap < SEARCH.overlapChars) {
      back -= 1;
      overlap += (entries[back] as MemoryEntry).text.length;
    }
    start = Math.max(start + 1, back);
  }
  return chunks;
}

const words = (text: string): Set<string> => new Set(text.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? []);

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let shared = 0;
  for (const word of a) if (b.has(word)) shared += 1;
  return shared / (a.size + b.size - shared);
}

function cosine(a: Float32Array, b: Float32Array): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    dot += (a[i] as number) * (b[i] as number);
    na += (a[i] as number) ** 2;
    nb += (b[i] as number) ** 2;
  }
  return na === 0 || nb === 0 ? 0 : dot / Math.sqrt(na * nb);
}

/** Maximal marginal relevance: each pick trades its score against its likeness to what is already picked. */
export function mmr(hits: readonly MemoryHit[], lambda: number, max: number): MemoryHit[] {
  const sets = new Map(hits.map((hit) => [hit.id, words(hit.text)]));
  const left = [...hits];
  const picked: MemoryHit[] = [];
  while (left.length > 0 && picked.length < max) {
    let best = 0;
    let bestValue = Number.NEGATIVE_INFINITY;
    left.forEach((hit, index) => {
      const likeness = Math.max(0, ...picked.map((chosen) => jaccard(sets.get(hit.id) as Set<string>, sets.get(chosen.id) as Set<string>)));
      const value = lambda * hit.score - (1 - lambda) * likeness;
      if (value > bestValue) [best, bestValue] = [index, value];
    });
    picked.push(...left.splice(best, 1));
  }
  return picked;
}

export interface MemoryIndexOptions {
  readonly db: string;
  readonly paths: MemoryPaths;
  readonly embedder?: Embedder | null;
  readonly now?: () => Date;
}

type Row = Record<string, unknown>;
const ORIGIN_SET: ReadonlySet<string> = new Set(ORIGINS);

/**
 * Search over this project's memory: USER.md, MEMORY.md and every daily note, chunked. Keyword
 * search (FTS5, BM25) always; with an embedder, `0.7 vector + 0.3 keyword`. Candidates x4, minimum
 * score 0.35, 30-day decay except for USER.md and MEMORY.md, MMR, at most 6.
 */
export class MemoryIndex {
  readonly #db: DatabaseSync;
  readonly #paths: MemoryPaths;
  readonly #embedder: Embedder | null;
  readonly #now: () => Date;
  #signature = '';

  private constructor(options: MemoryIndexOptions) {
    this.#db = openDatabase(options.db);
    this.#paths = options.paths;
    this.#embedder = options.embedder ?? null;
    this.#now = options.now ?? (() => new Date());
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS chunks(rid INTEGER PRIMARY KEY, id TEXT, source TEXT, text TEXT, origin TEXT, taint TEXT, newest TEXT, evergreen INTEGER);
      CREATE TABLE IF NOT EXISTS vectors(id TEXT, model TEXT, vec BLOB, PRIMARY KEY (id, model));
      CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(text, tokenize='unicode61');
    `);
  }

  static open(options: MemoryIndexOptions): MemoryIndex {
    return new MemoryIndex(options);
  }

  get keywordOnly(): boolean {
    return this.#embedder === null;
  }

  /** Every source, read through the store, so a hand-edited or damaged file is never searched. */
  async #sources(): Promise<{ source: string; entries: readonly MemoryEntry[]; evergreen: boolean }[]> {
    const out: { source: string; entries: readonly MemoryEntry[]; evergreen: boolean }[] = [];
    const now = this.#now;
    const user = await MemoryFile.open({ path: this.#paths.user, scope: 'user', project: null, now });
    const memory = await MemoryFile.open({ path: this.#paths.memory, scope: 'project', project: this.#paths.projectKey, now });
    if (user.status === 'ok') out.push({ source: 'USER.md', entries: user.entries, evergreen: true });
    if (memory.status === 'ok') out.push({ source: 'MEMORY.md', entries: memory.entries, evergreen: true });
    const days = (await readdir(this.#paths.daily).catch(() => [] as string[])).filter((name) => /^\d{4}-\d{2}-\d{2}\.md$/.test(name)).sort();
    for (const name of days) {
      const file = await MemoryFile.open({ path: join(this.#paths.daily, name), scope: 'daily', project: this.#paths.projectKey, now });
      if (file.status === 'ok') out.push({ source: `notes:${name.slice(0, 10)}`, entries: file.entries, evergreen: false });
    }
    return out;
  }

  async #signatureNow(): Promise<string> {
    const files = [this.#paths.user, this.#paths.memory];
    for (const name of await readdir(this.#paths.daily).catch(() => [] as string[])) files.push(join(this.#paths.daily, name));
    // Both files: a hand edit changes only the Markdown, and must take that file out of the search at once.
    const parts = await Promise.all(files.filter((file) => file.endsWith('.md')).sort().flatMap((file) => [file, `${file}.meta.json`]).map(async (file) => {
      const info = await stat(file).catch(() => null);
      return info === null ? `${file}:-` : `${file}:${info.size}:${info.mtimeMs}`;
    }));
    return hash(parts.join('\n'));
  }

  /** Rebuilds the chunks when any memory file changed. Vectors are cached by chunk, so only new text is embedded. */
  async refresh(signal?: AbortSignal): Promise<void> {
    const signature = await this.#signatureNow();
    if (signature === this.#signature) return;
    const chunks = (await this.#sources()).flatMap((source) => chunkEntries(source.source, source.entries, source.evergreen));
    this.#db.exec('BEGIN');
    try {
      this.#db.exec('DELETE FROM chunks_fts; DELETE FROM chunks;');
      const insert = this.#db.prepare('INSERT INTO chunks(id, source, text, origin, taint, newest, evergreen) VALUES (?, ?, ?, ?, ?, ?, ?)');
      const insertText = this.#db.prepare('INSERT INTO chunks_fts(rowid, text) VALUES (?, ?)');
      for (const chunk of chunks) {
        const result = insert.run(chunk.id, chunk.source, chunk.text, chunk.origin, chunk.taint, chunk.newest, chunk.evergreen ? 1 : 0);
        insertText.run(result.lastInsertRowid, chunk.text);
      }
      this.#db.exec('COMMIT');
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
    if (this.#embedder !== null) {
      const model = this.#embedder.model;
      const have = new Set((this.#db.prepare('SELECT id FROM vectors WHERE model = ?').all(model) as Row[]).map((row) => String(row['id'])));
      const missing = chunks.filter((chunk) => !have.has(chunk.id));
      for (let i = 0; i < missing.length; i += 32) {
        const batch = missing.slice(i, i + 32);
        const vectors = await this.#embedder.embed(batch.map((chunk) => chunk.text), signal);
        const put = this.#db.prepare('INSERT OR REPLACE INTO vectors(id, model, vec) VALUES (?, ?, ?)');
        batch.forEach((chunk, index) => put.run(chunk.id, model, Buffer.from((vectors[index] as Float32Array).buffer)));
      }
    }
    this.#signature = signature;
  }

  #chunk(row: Row): Chunk {
    const origin = String(row['origin']);
    return {
      id: String(row['id']),
      source: String(row['source']),
      text: String(row['text']),
      origin: ORIGIN_SET.has(origin) ? (origin as Origin) : 'web',
      taint: row['taint'] === 'clean' ? 'clean' : 'untrusted',
      newest: String(row['newest']),
      evergreen: row['evergreen'] === 1,
    };
  }

  #decay(chunk: Chunk): number {
    if (chunk.evergreen) return 1;
    const days = Math.max(0, (this.#now().getTime() - Date.parse(chunk.newest)) / 86_400_000);
    return 0.5 ** (days / SEARCH.halfLifeDays);
  }

  /** Ranked hits, best first. `allow` drops chunks before ranking, so a caller's rule applies to what is even considered. */
  async search(query: string, options: { readonly allow?: (chunk: Chunk) => boolean; readonly max?: number; readonly signal?: AbortSignal } = {}): Promise<MemoryHit[]> {
    await this.refresh(options.signal);
    const max = Math.max(1, Math.min(SEARCH.maxResults, options.max ?? SEARCH.maxResults));
    const candidates = max * SEARCH.candidateFactor;
    const allow = options.allow ?? (() => true);
    const keyword = new Map<string, { chunk: Chunk; score: number }>();
    const match = ftsQuery(query, 'OR');
    if (match !== null) {
      const rows = this.#db
        .prepare('SELECT c.*, bm25(chunks_fts) AS rank FROM chunks_fts JOIN chunks c ON c.rid = chunks_fts.rowid WHERE chunks_fts MATCH ? ORDER BY rank LIMIT ?')
        .all(match, candidates * 4) as Row[];
      const kept = rows.map((row) => ({ chunk: this.#chunk(row), raw: -Number(row['rank']) })).filter((item) => allow(item.chunk)).slice(0, candidates);
      const top = Math.max(...kept.map((item) => item.raw), Number.MIN_VALUE);
      for (const item of kept) keyword.set(item.chunk.id, { chunk: item.chunk, score: Math.max(0, item.raw / top) });
    }
    const vector = new Map<string, { chunk: Chunk; score: number }>();
    if (this.#embedder !== null) {
      const [queryVector] = await this.#embedder.embed([query], options.signal);
      const rows = this.#db.prepare('SELECT c.*, v.vec FROM chunks c JOIN vectors v ON v.id = c.id AND v.model = ?').all(this.#embedder.model) as Row[];
      const scored = rows
        .map((row) => {
          const bytes = row['vec'] as Uint8Array;
          const vec = new Float32Array(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
          return { chunk: this.#chunk(row), score: Math.max(0, cosine(queryVector as Float32Array, vec)) };
        })
        .filter((item) => allow(item.chunk))
        .sort((a, b) => b.score - a.score)
        .slice(0, candidates);
      for (const item of scored) vector.set(item.chunk.id, item);
    }
    const ids = new Set([...keyword.keys(), ...vector.keys()]);
    const hits: MemoryHit[] = [];
    for (const id of ids) {
      const chunk = (keyword.get(id) ?? vector.get(id))?.chunk as Chunk;
      const kw = keyword.get(id)?.score ?? 0;
      const base = this.#embedder === null ? kw : SEARCH.vectorWeight * (vector.get(id)?.score ?? 0) + SEARCH.keywordWeight * kw;
      const score = base * this.#decay(chunk);
      if (score >= SEARCH.minScore) hits.push({ ...chunk, score });
    }
    hits.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
    return mmr(hits, SEARCH.mmrLambda, max);
  }

  close(): void {
    this.#db.close();
  }
}
