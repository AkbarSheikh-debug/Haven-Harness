import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

/**
 * Trust binds to content, not to a path. Every file that can steer the agent or run code
 * (instruction files, skills, hooks, MCP config, saved workflows, image recipes, anything under
 * `.hn/`) is hashed, and any change asks a human again, including after a `git pull`.
 * Trust decides what loads. It never decides what the agent may do.
 */

const CONTROL_NAMES = new Set([
  'agents.md',
  'claude.md',
  'skill.md',
  'agents.local.md',
  'claude.local.md',
  '.mcp.json',
  'sandbox.yaml',
  'dockerfile',
  'devcontainer.json',
  '.devcontainer.json',
]);
// Bare names like `hooks/` or `skills/` are not here on purpose: a React `hooks/` folder is ordinary source.
// Those names matter only under a control parent, and every path under these folders is already a control path.
// Only this agent's own folders. `.husky`, `.vscode`, `.devcontainer`, `.claude` and `.cursor` steer the editor, git and other agents,
// so they are on the host-exec manifest instead, which the hand-back checks and the gate checks below tier 3.
const CONTROL_FOLDERS = new Set(['.hn', '.agents']);

/** Whether a project-relative path is a control file. Case-insensitive, because the model may be on NTFS or APFS. */
export function isControlPath(relativePath: string): boolean {
  const segments = relativePath
    .replaceAll('\\', '/')
    .toLowerCase()
    .split('/')
    .filter((segment) => segment !== '' && segment !== '.');
  const name = segments.at(-1) ?? '';
  if (CONTROL_NAMES.has(name)) return true;
  return segments.slice(0, -1).some((segment) => CONTROL_FOLDERS.has(segment));
}

export const hashContent = (content: Uint8Array | string): string => createHash('sha256').update(content).digest('hex');

export type TrustState = 'trusted' | 'new' | 'changed';

export interface TrustCheck {
  readonly state: TrustState;
  readonly hash: string;
  /** Present when `state` is `changed`: what the human is being asked to accept. */
  readonly diff?: string;
}

interface TrustFile {
  readonly version: 1;
  readonly entries: Readonly<Record<string, string>>;
  readonly mac: string;
  /**
   * The last approved text, kept only to show a diff next session. It is not covered by the MAC and decides nothing:
   * trust comes from the hash alone, so a tampered text can make a diff look wrong but cannot make anything trusted.
   */
  readonly texts?: Readonly<Record<string, string>>;
}

export interface TrustOptions {
  /** Keep each approved text, up to 64 KB, so a change can be shown as a diff in a later session. Off by default. */
  readonly keepText?: boolean;
}

const MAX_KEPT_TEXT = 64 * 1024;

const macOf = (key: Uint8Array, entries: Readonly<Record<string, string>>): string =>
  createHmac('sha256', key)
    .update(JSON.stringify(Object.entries(entries).sort(([a], [b]) => (a < b ? -1 : 1))))
    .digest('hex');

/** A small line diff, enough for a human to see what changed. The full file is always available to open. */
export function summarizeDiff(before: string, after: string, maxLines = 40): string {
  const a = before.split('\n');
  const b = after.split('\n');
  const inB = new Set(b);
  const inA = new Set(a);
  const out = [...a.filter((line) => !inB.has(line)).map((line) => `- ${line}`), ...b.filter((line) => !inA.has(line)).map((line) => `+ ${line}`)];
  if (out.length === 0) return '(only the order or spacing of lines changed)';
  return out.length > maxLines ? `${out.slice(0, maxLines).join('\n')}\n... and ${out.length - maxLines} more changed lines` : out.join('\n');
}

export class TrustStore {
  readonly #path: string;
  readonly #key: Uint8Array;
  #entries = new Map<string, string>();
  /** Last trusted text per path, kept in memory only, to show a diff. Not persisted: the hash is the record. */
  readonly #texts = new Map<string, string>();

  readonly #keepText: boolean;

  constructor(path: string, key: Uint8Array, options: TrustOptions = {}) {
    this.#path = path;
    this.#key = key;
    this.#keepText = options.keepText === true;
  }

  /** Loads the store. A missing file is an empty store. A file whose MAC fails trusts nothing. */
  async load(): Promise<{ tampered: boolean }> {
    let raw: string;
    try {
      raw = await readFile(this.#path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { tampered: false };
      throw error;
    }
    try {
      const file = JSON.parse(raw) as Partial<TrustFile>;
      const entries = file.entries;
      if (file.version !== 1 || typeof file.mac !== 'string' || typeof entries !== 'object' || entries === null) return this.#reject();
      const expected = Buffer.from(macOf(this.#key, entries), 'hex');
      const given = Buffer.from(file.mac, 'hex');
      if (expected.length !== given.length || !timingSafeEqual(expected, given)) return this.#reject();
      this.#entries = new Map(Object.entries(entries).filter(([, hash]) => typeof hash === 'string'));
      if (this.#keepText && typeof file.texts === 'object' && file.texts !== null) {
        for (const [path, text] of Object.entries(file.texts)) if (typeof text === 'string' && this.#entries.has(path)) this.#texts.set(path, text);
      }
      return { tampered: false };
    } catch {
      return this.#reject();
    }
  }

  #reject(): { tampered: boolean } {
    this.#entries = new Map();
    return { tampered: true };
  }

  /** `path` should be absolute and canonical. A nested `.hn` folder is a different path, so it is asked about separately. */
  check(path: string, content: Uint8Array | string): TrustCheck {
    const hash = hashContent(content);
    const known = this.#entries.get(path);
    if (known === undefined) return { state: 'new', hash };
    if (known === hash) return { state: 'trusted', hash };
    const before = this.#texts.get(path);
    const after = typeof content === 'string' ? content : Buffer.from(content).toString('utf8');
    return { state: 'changed', hash, diff: before === undefined ? 'The file changed since you last trusted it.' : summarizeDiff(before, after) };
  }

  /** Records a human's yes. Call only from an approval the human answered. */
  async approve(path: string, content: Uint8Array | string): Promise<void> {
    this.#entries.set(path, hashContent(content));
    this.#texts.set(path, typeof content === 'string' ? content : Buffer.from(content).toString('utf8'));
    await this.#save();
  }

  async revoke(path: string): Promise<void> {
    this.#entries.delete(path);
    this.#texts.delete(path);
    await this.#save();
  }

  async #save(): Promise<void> {
    const entries = Object.fromEntries(this.#entries);
    const texts = this.#keepText ? Object.fromEntries([...this.#texts].filter(([path, text]) => this.#entries.has(path) && text.length <= MAX_KEPT_TEXT)) : undefined;
    const file: TrustFile = { version: 1, entries, mac: macOf(this.#key, entries), ...(texts === undefined ? {} : { texts }) };
    await mkdir(dirname(this.#path), { recursive: true });
    const temp = `${this.#path}.${process.pid}.tmp`;
    await writeFile(temp, JSON.stringify(file), { mode: 0o600 });
    await rename(temp, this.#path);
  }
}
