import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';

export type { DatabaseSync } from 'node:sqlite';

let ctor: (new (path: string) => DatabaseSync) | null = null;

/**
 * `node:sqlite` behind one function (its stability is a risk, so it is wrapped). Node
 * prints an experimental warning when the module loads, which would land in the middle of the
 * REPL, so that one warning is held back while it loads.
 */
export function openDatabase(path: string): DatabaseSync {
  if (ctor === null) {
    const original = process.emitWarning;
    process.emitWarning = ((warning: string | Error, ...rest: unknown[]) => {
      if (String(warning).includes('SQLite')) return;
      (original as (...args: unknown[]) => void).call(process, warning, ...rest);
    }) as typeof process.emitWarning;
    try {
      ctor = (createRequire(import.meta.url)('node:sqlite') as { DatabaseSync: new (path: string) => DatabaseSync }).DatabaseSync;
    } finally {
      process.emitWarning = original;
    }
  }
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new ctor(path);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  return db;
}

/** An FTS5 query from free text: each word quoted, so no word is ever read as query syntax. */
export function ftsQuery(text: string, join: 'AND' | 'OR'): string | null {
  const words = text.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? [];
  const unique = [...new Set(words.filter((word) => word.length > 1))].slice(0, 24);
  return unique.length === 0 ? null : unique.map((word) => `"${word}"`).join(` ${join} `);
}
