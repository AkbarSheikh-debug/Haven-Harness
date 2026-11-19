import { createHash } from 'node:crypto';
import { ORIGINS, type Origin } from '@hn/core';

/** `user` is USER.md, `project` is MEMORY.md, `daily` is a day's working notes. */
export const SCOPES = ['user', 'project', 'daily'] as const;
export type MemoryScope = (typeof SCOPES)[number];

/** Who wrote an entry: the person by hand, the agent, background review, or the dreamer through a card. */
export const WRITERS = ['user', 'agent', 'review', 'dream'] as const;
export type Writer = (typeof WRITERS)[number];

/**
 * One entry, with every field slide 37 will need from day one, so enterprise gates need no
 * migration. `origin` is the origin of the text's source, kept across disk, so a fact learned
 * from a web page stays `web`. `taint` is whether the writing session held untrusted text.
 */
export interface MemoryEntry {
  readonly id: string;
  readonly text: string;
  readonly who: Writer;
  readonly when: string;
  readonly sourceSession: string | null;
  readonly project: string | null;
  readonly scope: MemoryScope;
  readonly origin: Origin;
  readonly taint: 'clean' | 'untrusted';
  readonly expires: string | null;
  readonly why: string;
  /** Who allowed a long-term write: `user-request` (decision 3) or the name of the person who said yes. */
  readonly approvedBy: string | null;
}

export interface Sidecar {
  readonly v: 1;
  readonly entries: readonly MemoryEntry[];
  /** Hash of the Markdown this sidecar rendered. A different file on disk was edited by hand. */
  readonly renderedHash: string;
  /** The Markdown before the last write. Seeing it on disk means the write stopped between the two renames. */
  readonly previousRenderedHash: string | null;
}

/** Long-term entries are separated by a line holding only this mark, as in Hermes. */
export const DELIMITER = '§';

const ENTRY_KEYS = ['id', 'text', 'who', 'when', 'sourceSession', 'project', 'scope', 'origin', 'taint', 'expires', 'why', 'approvedBy'] as const;
const ORIGIN_SET: ReadonlySet<string> = new Set(ORIGINS);
const SCOPE_SET: ReadonlySet<string> = new Set(SCOPES);
const WRITER_SET: ReadonlySet<string> = new Set(WRITERS);
const HASH = /^[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{8,32}$/;

export const hashText = (text: string): string => createHash('sha256').update(text).digest('hex');

const isDate = (value: unknown): value is string => typeof value === 'string' && !Number.isNaN(Date.parse(value));
const isNullableString = (value: unknown): value is string | null => value === null || typeof value === 'string';

/** Returns the entry when `raw` is exactly a well-formed entry. Unknown keys, including `__proto__`, fail. */
export function parseEntry(raw: unknown): MemoryEntry | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const keys = Object.keys(raw);
  if (keys.length !== ENTRY_KEYS.length || !ENTRY_KEYS.every((key) => Object.hasOwn(raw, key))) return null;
  const record = raw as Record<string, unknown>;
  const { id, text, who, when, sourceSession, project, scope, origin, taint, expires, why, approvedBy } = record;
  if (typeof id !== 'string' || !ID.test(id)) return null;
  if (typeof text !== 'string' || typeof why !== 'string') return null;
  if (typeof who !== 'string' || !WRITER_SET.has(who)) return null;
  if (typeof scope !== 'string' || !SCOPE_SET.has(scope)) return null;
  if (typeof origin !== 'string' || !ORIGIN_SET.has(origin)) return null;
  if (taint !== 'clean' && taint !== 'untrusted') return null;
  if (!isDate(when) || !(expires === null || isDate(expires))) return null;
  if (!isNullableString(sourceSession) || !isNullableString(project) || !isNullableString(approvedBy)) return null;
  return {
    id, text, who: who as Writer, when, sourceSession, project, scope: scope as MemoryScope,
    origin: origin as Origin, taint, expires, why, approvedBy,
  };
}

/** The sidecar from its JSON text, or `null` if any part of it is malformed. Never a partial load. */
export function parseSidecar(json: string): Sidecar | null {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(',');
  if (keys !== 'entries,previousRenderedHash,renderedHash,v' || record['v'] !== 1) return null;
  const { entries, renderedHash, previousRenderedHash } = record;
  if (typeof renderedHash !== 'string' || !HASH.test(renderedHash)) return null;
  if (!(previousRenderedHash === null || (typeof previousRenderedHash === 'string' && HASH.test(previousRenderedHash)))) return null;
  if (!Array.isArray(entries)) return null;
  const parsed = entries.map(parseEntry);
  if (parsed.some((entry) => entry === null)) return null;
  return { v: 1, entries: parsed as MemoryEntry[], renderedHash, previousRenderedHash };
}

const HEADER: Readonly<Record<MemoryScope, string>> = {
  user: '<!-- hn memory: USER.md. Change it with /memory; a hand edit is noticed and asked about. -->',
  project: '<!-- hn memory: MEMORY.md. Change it with /memory; a hand edit is noticed and asked about. -->',
  daily: '<!-- hn memory: working notes. Each line shows where it came from. -->',
};

/** The text an entry costs against the cap: long-term entries joined by the delimiter line. */
export function body(entries: readonly MemoryEntry[]): string {
  return entries.map((entry) => entry.text).join(`\n${DELIMITER}\n`);
}

/** The Markdown on disk. Daily notes are one line per entry, each tagged with its origin. */
export function render(scope: MemoryScope, entries: readonly MemoryEntry[]): string {
  if (scope === 'daily') return `${HEADER.daily}\n${entries.map((entry) => `- [${entry.origin}] ${entry.text}`).join('\n')}\n`;
  return `${HEADER[scope]}\n${body(entries)}\n`;
}

/** The entries a Markdown file holds after a person edited it by hand. They become the user's own words. */
export function entriesFromMarkdown(scope: MemoryScope, markdown: string): string[] {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n').filter((line) => !/^<!--.*-->$/.test(line.trim()));
  if (scope === 'daily') {
    return lines.map((line) => line.replace(/^-\s*(\[[a-z-]+\]\s*)?/, '').trim()).filter((line) => line !== '');
  }
  return lines.join('\n').split(new RegExp(`^${DELIMITER}$`, 'm')).map((part) => part.trim()).filter((part) => part !== '');
}
