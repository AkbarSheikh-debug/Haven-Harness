import { randomBytes } from 'node:crypto';
import type { Origin } from '@hn/core';
import { Redactor, join as joinOrigins, scanThreat, sentinelWriteProblem, type ThreatVerdict } from '@hn/security';
import { atomicWrite, dropHistory, listHistory, pushHistory, readHistory, readOrNull, removeIfPresent, withLock } from './disk.ts';
import { DELIMITER, body, entriesFromMarkdown, hashText, parseSidecar, render, type MemoryEntry, type MemoryScope, type Sidecar, type Writer } from './record.ts';

/** Characters each file may hold. Daily notes are written freely and tail-capped at load; their cap only bounds the file. */
export const CAPS: Readonly<Record<MemoryScope, number>> = { user: 1_375, project: 2_200, daily: 65_536 };
const HISTORY_LIMIT = 100;

/** `hand-edited`: the Markdown is not what hn last wrote. `corrupt`: the sidecar cannot be read. Either way writes wait for a person. */
export type FileStatus = 'ok' | 'hand-edited' | 'corrupt';

export type MemoryOp =
  | { readonly op: 'add'; readonly text: string }
  | { readonly op: 'replace'; readonly match: string; readonly text: string }
  | { readonly op: 'remove'; readonly match: string };

export interface WriteMeta {
  readonly who: Writer;
  readonly sourceSession: string | null;
  /** The origin of the text being written, which the entry keeps. */
  readonly origin: Origin;
  readonly taint: 'clean' | 'untrusted';
  readonly why: string;
  readonly approvedBy: string | null;
  readonly expires?: string | null;
}

export type ApplyResult =
  | { readonly ok: true; readonly entries: readonly MemoryEntry[]; readonly used: number; readonly cap: number }
  | { readonly ok: false; readonly reason: string; readonly entries: readonly MemoryEntry[] };

export interface MemoryFileOptions {
  readonly path: string;
  readonly scope: MemoryScope;
  readonly project: string | null;
  readonly cap?: number;
  /** The strict scan by default. Any trouble in the scan means the write is refused. */
  readonly scan?: (texts: readonly string[]) => Promise<ThreatVerdict>;
  readonly redactor?: Redactor;
  readonly now?: () => Date;
}

const sidecarPath = (path: string): string => `${path}.meta.json`;
const newId = (): string => randomBytes(4).toString('hex');

/**
 * One memory file and its sidecar. The sidecar is the truth and holds every entry's record; the
 * Markdown is rendered from it for people to read. A Markdown file that no longer matches what
 * hn rendered was edited by hand, and is reported rather than overwritten or parsed silently.
 */
export class MemoryFile {
  readonly path: string;
  readonly scope: MemoryScope;
  readonly cap: number;
  readonly #project: string | null;
  readonly #scan: (texts: readonly string[]) => Promise<ThreatVerdict>;
  readonly #redactor: Redactor;
  readonly #now: () => Date;
  #status: FileStatus = 'ok';
  #entries: readonly MemoryEntry[] = [];
  #markdown: string | null = null;

  private constructor(options: MemoryFileOptions) {
    this.path = options.path;
    this.scope = options.scope;
    this.cap = options.cap ?? CAPS[options.scope];
    this.#project = options.project;
    this.#scan = options.scan ?? ((texts) => scanThreat(texts, 'strict'));
    this.#redactor = options.redactor ?? new Redactor();
    this.#now = options.now ?? (() => new Date());
  }

  static async open(options: MemoryFileOptions): Promise<MemoryFile> {
    const file = new MemoryFile(options);
    await file.reload();
    return file;
  }

  get status(): FileStatus {
    return this.#status;
  }

  /** Entries that have not expired. */
  get entries(): readonly MemoryEntry[] {
    const now = this.#now().getTime();
    return this.#entries.filter((entry) => entry.expires === null || Date.parse(entry.expires) > now);
  }

  /** The Markdown on disk as it is now, for showing a hand edit to a person. */
  get markdown(): string | null {
    return this.#markdown;
  }

  /** Characters used against the cap, counted as the entries render. */
  get used(): number {
    return this.scope === 'daily' ? render('daily', this.entries).length : body(this.entries).length;
  }

  async reload(): Promise<void> {
    const markdown = await readOrNull(this.path);
    const sidecarText = await readOrNull(sidecarPath(this.path));
    this.#markdown = markdown;
    if (sidecarText === null) {
      this.#entries = [];
      this.#status = markdown === null ? 'ok' : 'hand-edited';
      return;
    }
    const sidecar = parseSidecar(sidecarText);
    if (sidecar === null) {
      this.#entries = [];
      this.#status = 'corrupt';
      return;
    }
    this.#entries = sidecar.entries;
    const onDisk = markdown === null ? null : hashText(markdown);
    if (onDisk === sidecar.renderedHash) {
      this.#status = 'ok';
    } else if (onDisk !== null && onDisk === sidecar.previousRenderedHash) {
      // The last write stopped after the sidecar and before the Markdown. Finish it.
      const fresh = render(this.scope, sidecar.entries);
      await atomicWrite(this.path, fresh);
      this.#markdown = fresh;
      this.#status = 'ok';
    } else {
      this.#status = 'hand-edited';
    }
  }

  /**
   * Applies every operation or none. The cap is checked on the final state, so a batch may remove
   * before it adds. Long-term files need `approvedBy`; the caller decides who may give it.
   */
  async apply(ops: readonly MemoryOp[], meta: WriteMeta): Promise<ApplyResult> {
    return withLock(this.path, async () => {
      await this.reload();
      const refuse = (reason: string): ApplyResult => ({ ok: false, reason, entries: this.entries });
      if (this.#status !== 'ok') return refuse(this.#statusReason());
      if (ops.length === 0) return refuse('There is nothing to write.');
      if (this.scope !== 'daily' && (meta.approvedBy === null || meta.approvedBy.trim() === '')) {
        return refuse(`${this.#name()} holds long-term memory, so a write needs the user's own request or a person's approval.`);
      }
      let working = [...this.entries];
      const written: string[] = [];
      for (const op of ops) {
        if (op.op === 'add') {
          const checked = this.#checkText(op.text, null);
          if (typeof checked !== 'string') return refuse(checked.reason);
          // The same fact twice is one fact: a model that repeats a call (seen live) does not fill the file.
          if (working.some((entry) => entry.text === checked)) continue;
          working.push(this.#entry(newId(), checked, meta, meta.origin));
          written.push(checked);
          continue;
        }
        const found = findUnique(working, op.match);
        if (typeof found === 'string') return refuse(found);
        if (op.op === 'remove') {
          working = working.filter((entry) => entry !== found);
          continue;
        }
        const checked = this.#checkText(op.text, found.text);
        if (typeof checked !== 'string') return refuse(checked.reason);
        // The new text may carry words of the old one, so it keeps the worse of the two origins.
        working = working.map((entry) => (entry === found ? this.#entry(found.id, checked, meta, joinOrigins(found.origin, meta.origin)) : entry));
        written.push(checked);
      }
      const used = this.scope === 'daily' ? render('daily', working).length : body(working).length;
      if (used > this.cap) {
        return refuse(`${this.#name()} would hold ${used} of ${this.cap} characters. Nothing was written. Remove or shorten an entry first; the current entries are listed.`);
      }
      if (written.length > 0) {
        const verdict = await this.#scan(written);
        if (!verdict.clean) {
          const why = verdict.findings.map((finding) => finding.label).join('; ') || verdict.reason || 'the scan did not finish';
          return refuse(`The text was not saved: it ${why}. Memory is read at the start of every session, so it is held to the strictest scan.`);
        }
      }
      await this.#write(working);
      return { ok: true, entries: this.entries, used, cap: this.cap };
    });
  }

  /** Puts back the exact bytes from before the last write. */
  async undo(): Promise<{ readonly ok: boolean; readonly reason: string }> {
    return withLock(this.path, async () => {
      const seq = (await listHistory(this.path)).at(-1);
      const item = seq === undefined ? null : await readHistory(this.path, seq);
      if (seq === undefined || item === null) return { ok: false, reason: `${this.#name()} has nothing to undo.` };
      await restore(sidecarPath(this.path), item.sidecar);
      await restore(this.path, item.markdown);
      await dropHistory(this.path, seq);
      await this.reload();
      return { ok: true, reason: `${this.#name()} is back to how it was at ${item.when}.` };
    });
  }

  /** The saved states, newest last. */
  async history(): Promise<{ readonly seq: number; readonly when: string; readonly entries: number }[]> {
    const out: { seq: number; when: string; entries: number }[] = [];
    for (const seq of await listHistory(this.path)) {
      const item = await readHistory(this.path, seq);
      if (item === null) continue;
      const sidecar = item.sidecar === null ? null : parseSidecar(item.sidecar);
      out.push({ seq, when: item.when, entries: sidecar?.entries.length ?? 0 });
    }
    return out;
  }

  /**
   * A person looked at a hand-edited file and kept it. Entries whose text is unchanged keep their
   * record, so a `web` fact does not become the user's by surviving an edit; new text is the user's.
   */
  async acceptHandEdit(by: string): Promise<ApplyResult> {
    return withLock(this.path, async () => {
      await this.reload();
      if (this.#status === 'ok') return { ok: false, reason: `${this.#name()} has no hand edit to accept.`, entries: this.entries };
      const previous = new Map(this.#entries.map((entry) => [entry.text, entry]));
      const meta: WriteMeta = { who: 'user', sourceSession: null, origin: 'user', taint: 'clean', why: 'edited by hand', approvedBy: by };
      const texts = entriesFromMarkdown(this.scope, this.#markdown ?? '');
      const entries = texts.map((text) => previous.get(text) ?? this.#entry(newId(), text, meta, 'user'));
      await this.#write(entries);
      return { ok: true, entries: this.entries, used: this.used, cap: this.cap };
    });
  }

  #name(): string {
    return this.scope === 'user' ? 'USER.md' : this.scope === 'project' ? 'MEMORY.md' : "Today's notes";
  }

  #statusReason(): string {
    if (this.#status === 'corrupt') return `${this.#name()}'s record file cannot be read, so nothing was written. A person needs to look at it with /memory.`;
    return `${this.#name()} was changed by hand since hn last wrote it, so nothing was written. A person needs to review it with /memory first.`;
  }

  /** The text to store, or why it cannot be stored. Redaction runs after the write-back check, which needs the model's own words. */
  #checkText(text: string, existing: string | null): string | { reason: string } {
    const trimmed = text.trim();
    if (trimmed === '') return { reason: 'An entry cannot be empty.' };
    if (this.scope === 'daily' && /[\r\n]/.test(trimmed)) return { reason: 'A daily note entry is one line.' };
    if (new RegExp(`^\\s*${DELIMITER}\\s*$`, 'm').test(trimmed)) return { reason: `A line holding only ${DELIMITER} separates entries, so an entry cannot contain one.` };
    const sentinel = sentinelWriteProblem(existing, trimmed);
    if (sentinel !== null) return { reason: sentinel };
    return this.#redactor.redact(trimmed);
  }

  #entry(id: string, text: string, meta: WriteMeta, origin: Origin): MemoryEntry {
    return {
      id, text, who: meta.who, when: this.#now().toISOString(), sourceSession: meta.sourceSession, project: this.scope === 'user' ? null : this.#project,
      scope: this.scope, origin, taint: meta.taint, expires: meta.expires ?? null, why: meta.why, approvedBy: meta.approvedBy,
    };
  }

  /** History first, then the sidecar, then the Markdown. A stop between the last two is finished by the next `reload`. */
  async #write(entries: readonly MemoryEntry[]): Promise<void> {
    const oldSidecar = await readOrNull(sidecarPath(this.path));
    await pushHistory(this.path, { when: this.#now().toISOString(), sidecar: oldSidecar, markdown: this.#markdown }, HISTORY_LIMIT);
    const markdown = render(this.scope, entries);
    const sidecar: Sidecar = {
      v: 1, entries, renderedHash: hashText(markdown), previousRenderedHash: this.#markdown === null ? null : hashText(this.#markdown),
    };
    await atomicWrite(sidecarPath(this.path), JSON.stringify(sidecar, null, 1));
    await atomicWrite(this.path, markdown);
    this.#entries = entries;
    this.#markdown = markdown;
    this.#status = 'ok';
  }
}

async function restore(path: string, text: string | null): Promise<void> {
  if (text === null) await removeIfPresent(path);
  else await atomicWrite(path, text);
}

/** The one entry `match` names, or why it names none or several. Identical duplicates count as one. */
export function findUnique(entries: readonly MemoryEntry[], match: string): MemoryEntry | string {
  const needle = match.trim();
  if (needle === '') return 'Name the entry with a short piece of its text.';
  // A blocked entry is shown only as `[BLOCKED #id]`, so it can be named by its id.
  const byId = /^#([0-9a-f]{8,32})$/.exec(needle);
  if (byId !== null) return entries.find((entry) => entry.id === byId[1]) ?? `No entry has the id ${needle}.`;
  const hits = entries.filter((entry) => entry.text.includes(needle));
  if (hits.length === 0) return `No entry contains "${needle}".`;
  if (new Set(hits.map((entry) => entry.text)).size > 1) {
    const listed = hits.map((entry) => `"${entry.text.slice(0, 60)}${entry.text.length > 60 ? '…' : ''}"`).join(', ');
    return `"${needle}" matches ${hits.length} entries: ${listed}. Use a longer piece of the one you mean.`;
  }
  return hits[0] as MemoryEntry;
}
