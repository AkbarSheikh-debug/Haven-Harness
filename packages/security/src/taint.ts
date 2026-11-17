import { createHash } from 'node:crypto';
import type { Origin } from '@hn/core';

/**
 * How far an origin is from a human at a keyboard. A row derived from several others takes the
 * highest rank among them, so a summary of a web page is as untrusted as the web page.
 */
const RANK: Readonly<Record<Origin, number>> = {
  harness: 0,
  user: 0,
  'human-selected': 1,
  workspace: 2,
  hook: 3,
  memory: 3,
  'tool-output': 4,
  'model-derived': 4,
  event: 5,
  ipc: 5,
  child: 5,
  mcp: 6,
  web: 7,
};

/** The worst origin among `origins`. With no inputs the result is `harness`, the most trusted. */
export function join(...origins: readonly Origin[]): Origin {
  let worst: Origin = origins[0] ?? 'harness';
  for (const origin of origins) if (RANK[origin] > RANK[worst]) worst = origin;
  return worst;
}

/** Only `user` and `human-selected` are trusted, plus `workspace` once the repo's tracked files are trusted. */
export function isUntrusted(origin: Origin, workspaceTrusted = false): boolean {
  if (origin === 'harness' || origin === 'user' || origin === 'human-selected') return false;
  if (origin === 'workspace') return !workspaceTrusted;
  return true;
}

export interface TaintFlags {
  /** An untrusted-origin row has entered the session. */
  readonly untrusted: boolean;
  /** Private data is reachable. True for every workspace unless the repo is confirmed public. */
  readonly private: boolean;
  /** An external-class tool is reachable. */
  readonly external: boolean;
}

export interface TaintOptions {
  readonly workspaceTrusted?: boolean;
  readonly onChange?: (flags: TaintFlags, why: string) => void;
}

/** The three legs of the Rule of Two. A session may hold any two. With all three, every external effect needs a human. */
export class TaintTracker {
  readonly #workspaceTrusted: boolean;
  readonly #onChange: ((flags: TaintFlags, why: string) => void) | undefined;
  readonly #files = new Map<string, Origin>();
  #untrusted = false;
  #private = true;
  #external = false;
  #worst: Origin = 'harness';

  /** The worst origin that has entered the session. Anything the session writes carries at least this much taint. */
  get worst(): Origin {
    return this.#worst;
  }

  constructor(options: TaintOptions = {}) {
    this.#workspaceTrusted = options.workspaceTrusted ?? false;
    this.#onChange = options.onChange;
  }

  get flags(): TaintFlags {
    return { untrusted: this.#untrusted, private: this.#private, external: this.#external };
  }

  /** Call for every row that enters the session. Returns the same origin, for chaining. */
  observe(origin: Origin): Origin {
    this.#worst = join(this.#worst, origin);
    if (!this.#untrusted && isUntrusted(origin, this.#workspaceTrusted)) {
      this.#untrusted = true;
      this.#onChange?.(this.flags, `an untrusted ${origin} row entered`);
    }
    return origin;
  }

  /** An unmarked repo is private. Only a public mark that the remote confirmed clears the flag. */
  setRepoVisibility(markedPublic: boolean, remoteConfirmsPublic: boolean): void {
    const next = !(markedPublic && remoteConfirmsPublic);
    if (next === this.#private) return;
    this.#private = next;
    this.#onChange?.(this.flags, next ? 'the repo is private' : 'the repo is confirmed public');
  }

  setExternalReachable(reachable: boolean): void {
    if (reachable === this.#external) return;
    this.#external = reachable;
    this.#onChange?.(this.flags, reachable ? 'an external tool is reachable' : 'no external tool is reachable');
  }

  /** All three legs at once: the injected text can read private data and send it out. */
  get trifecta(): boolean {
    return this.#untrusted && this.#private && this.#external;
  }

  /** Whether a call of this effect class must be shown to a human, in any mode, and denied when none is present. */
  requiresHuman(effect: string): boolean {
    return effect === 'external' && this.trifecta;
  }

  /**
   * A file written while the session was tainted stays tainted. The sidecar is keyed by content hash,
   * so web -> file -> read cannot launder the text, and renaming or copying the file does not either.
   */
  recordWrite(content: Uint8Array | string, sessionOrigin: Origin): void {
    const key = contentKey(content);
    this.#files.set(key, join(this.#files.get(key) ?? 'harness', sessionOrigin));
  }

  /** The origin a row should get when this content is read back. */
  originOfRead(content: Uint8Array | string, fileOrigin: Origin = 'workspace'): Origin {
    return join(fileOrigin, this.#files.get(contentKey(content)) ?? 'harness');
  }

  /** What to persist and restore, so taint survives resume. */
  snapshot(): { flags: TaintFlags; files: [string, Origin][] } {
    return { flags: this.flags, files: [...this.#files] };
  }
}

export function contentKey(content: Uint8Array | string): string {
  return createHash('sha256').update(content).digest('hex');
}
