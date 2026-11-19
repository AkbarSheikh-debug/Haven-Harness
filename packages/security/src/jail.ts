import path from 'node:path';

const RESERVED_NAMES = /^(con|prn|aux|nul|conin\$|conout\$|clock\$|com[\d¹²³]|lpt[\d¹²³])(\..*)?$/i;
/** `PROGRA~1`, `ENV~1.TXT`: the short alias NTFS gives a long name. It can spell a secret file without its name. */
const SHORT_NAME = /^[^.]{1,6}~\d+(\.[^.]{0,3})?$/;

export class JailError extends Error {}

export interface JailOptions {
  readonly root: string;
  /** Resolves links on the backend the tool really touches. Rejects with ENOENT when absent. */
  readonly realpath: (path: string) => Promise<string>;
  readonly platform?: NodeJS.Platform;
}

function rejectWindowsTricks(input: string): void {
  if (/^[\\/]{2}/.test(input)) throw new JailError(`${input}: network and device paths are not allowed.`);
  if (/^[a-z]:(?![\\/])/i.test(input)) throw new JailError(`${input}: drive-relative paths are not allowed. Use a full path.`);
  for (const segment of input.split(/[\\/]/)) {
    if (segment === '' || segment === '.' || segment === '..') continue;
    if (/^[a-z]:$/i.test(segment)) continue;
    if (SHORT_NAME.test(segment)) throw new JailError(`${input}: 8.3 short names are not allowed. Use the full name.`);
    if (segment.includes(':')) throw new JailError(`${input}: alternate data streams are not allowed.`);
    if (/[. ]$/.test(segment)) throw new JailError(`${input}: names ending in a dot or space are not allowed.`);
    if (RESERVED_NAMES.test(segment)) throw new JailError(`${input}: reserved device names are not allowed.`);
  }
}

/**
 * Keeps a path inside the project: attach it, clean it, resolve links, then check it
 * is still inside. This checks then opens, so a racing local process could swap a link
 * in between. Phase 2's helper closes that gap.
 */
export class Jail {
  readonly #root: string;
  readonly #realpath: (path: string) => Promise<string>;
  readonly #platform: NodeJS.Platform;
  readonly #path: typeof path.posix;

  constructor(options: JailOptions) {
    this.#root = options.root;
    this.#realpath = options.realpath;
    this.#platform = options.platform ?? process.platform;
    this.#path = this.#platform === 'win32' ? path.win32 : path.posix;
  }

  #inside(root: string, candidate: string): boolean {
    const fold = (value: string): string =>
      this.#platform === 'win32' || this.#platform === 'darwin' ? value.toLowerCase() : value;
    const relative = this.#path.relative(fold(root), fold(candidate));
    return relative === '' || (!relative.startsWith('..') && !this.#path.isAbsolute(relative));
  }

  /** The nearest existing ancestor is resolved, so a new file under a linked folder is still caught. */
  async #resolveLinks(target: string): Promise<string> {
    const missing: string[] = [];
    let current = target;
    for (;;) {
      try {
        return this.#path.join(await this.#realpath(current), ...missing.reverse());
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        const parent = this.#path.dirname(current);
        if (parent === current) throw error;
        missing.push(this.#path.basename(current));
        current = parent;
      }
    }
  }

  async resolve(input: string): Promise<string> {
    if (input.includes('\0')) throw new JailError('Paths cannot contain a NUL character.');
    if (this.#platform === 'win32') rejectWindowsTricks(input);
    const attached = this.#path.resolve(this.#root, input);
    if (!this.#inside(this.#root, attached)) throw new JailError(`${input} is outside the project.`);
    const root = await this.#realpath(this.#root);
    const resolved = await this.#resolveLinks(attached);
    if (!this.#inside(root, resolved)) throw new JailError(`${input} leads outside the project through a link.`);
    // One spelling of the drive letter, so a later string comparison cannot be fooled by case.
    return this.#platform === 'win32' ? resolved.replace(/^[a-z]:/, (drive) => drive.toUpperCase()) : resolved;
  }
}
