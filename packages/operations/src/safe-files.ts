import { spawn } from 'node:child_process';
import { access, realpath } from 'node:fs/promises';
import path from 'node:path';

/**
 * `safeRead` and `safeWrite`. Node has no `openat2` and no `O_NOFOLLOW` on Windows, so a check
 * followed by an open can be raced by a local process that swaps a link in between. These go
 * through the native `hn-sandbox` helper, which walks the path one folder at a time and refuses
 * any link, junction, hardlinked or non-regular file. If the helper is missing, file access
 * refuses; it never falls back to the unsafe path.
 */

const MESSAGES: Readonly<Record<string, string>> = {
  link: 'A link or junction is in the way, and links are never followed. Use a normal file inside the project.',
  hardlink: 'The file has more than one name, so it could be a way into another file. Use a normal file.',
  not_regular: 'That is not a regular file.',
  outside_root: 'That path leaves the project.',
  too_large: 'That file is too large.',
  not_directory: 'A part of that path is not a folder.',
  exists: 'That file already exists.',
  not_found: 'No such file.',
  unsupported: 'That is not supported on this platform.',
};

/** A refusal or failure from the helper. `code` is an errno-style name where one exists, so existing handling of ENOENT still works. */
export class SafeFileError extends Error {
  readonly code: string;
  readonly reason: string;

  constructor(reason: string, detail: string) {
    super(`${MESSAGES[reason] ?? 'The file operation failed.'}${detail === '' ? '' : ` (${detail})`}`);
    this.reason = reason;
    this.code = reason === 'not_found' ? 'ENOENT' : reason === 'exists' ? 'EEXIST' : `HN_${reason.toUpperCase()}`;
  }
}

export interface WriteFlags {
  /** Create missing parent folders, one at a time, refusing links. */
  readonly mkdir?: boolean;
  /** Fail if the file already exists, instead of replacing it. */
  readonly createOnly?: boolean;
}

export interface SafeFiles {
  /** `absolute` must be inside `root`. Reads at most `maxBytes`. */
  read(root: string, absolute: string, maxBytes: number): Promise<Buffer>;
  write(root: string, absolute: string, bytes: Uint8Array, flags?: WriteFlags): Promise<void>;
  /** Removes one regular file. A directory, a link, or a path through a link is refused. */
  delete(root: string, absolute: string): Promise<void>;
}

interface Outcome {
  readonly code: number | null;
  readonly stdout: Buffer;
  readonly stderr: string;
}

const HELPER_TIMEOUT_MS = 30_000;

function call(helper: string, args: readonly string[], stdin: Uint8Array | null): Promise<Outcome> {
  return new Promise((resolve, reject) => {
    const child = spawn(helper, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const timer = setTimeout(() => child.kill(), HELPER_TIMEOUT_MS);
    child.stdout.on('data', (chunk: Buffer) => out.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => err.push(chunk));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString('utf8') });
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(stdin === null ? undefined : Buffer.from(stdin));
  });
}

function refusal(outcome: Outcome): SafeFileError {
  try {
    const parsed = JSON.parse(outcome.stderr.trim().split('\n').at(-1) ?? '') as { code?: string; message?: string };
    return new SafeFileError(parsed.code ?? 'io', parsed.message ?? '');
  } catch {
    return new SafeFileError('io', outcome.stderr.slice(0, 200));
  }
}

/** The path under `root`, or a refusal. The helper checks again; this keeps an obvious escape from spawning anything. */
export function relativeInside(root: string, absolute: string): string {
  const flavour = root.includes('\\') || /^[a-z]:/i.test(root) ? path.win32 : path.posix;
  const relative = flavour.relative(root, absolute);
  if (relative === '' || relative.startsWith('..') || flavour.isAbsolute(relative)) throw new SafeFileError('outside_root', absolute);
  return relative;
}

export function createSafeFiles(helper: string): SafeFiles {
  // The helper refuses a root that is itself a link, so it is given the real folder. The path stays relative to the name the caller used.
  const real = new Map<string, string>();
  const realRoot = async (root: string): Promise<string> => {
    const known = real.get(root);
    if (known !== undefined) return known;
    const resolved = await realpath(root);
    real.set(root, resolved);
    return resolved;
  };
  return {
    async read(root, absolute, maxBytes) {
      const outcome = await call(helper, ['read', '--root', await realRoot(root), '--path', relativeInside(root, absolute), '--max', String(maxBytes)], null);
      if (outcome.code !== 0) throw refusal(outcome);
      return outcome.stdout;
    },
    async write(root, absolute, bytes, flags = {}) {
      const args = ['write', '--root', await realRoot(root), '--path', relativeInside(root, absolute), '--max', String(Math.max(bytes.length, 1))];
      if (flags.mkdir === true) args.push('--mkdir');
      if (flags.createOnly === true) args.push('--create-only');
      const outcome = await call(helper, args, bytes);
      if (outcome.code !== 0) throw refusal(outcome);
    },
    async delete(root, absolute) {
      const outcome = await call(helper, ['delete', '--root', await realRoot(root), '--path', relativeInside(root, absolute)], null);
      if (outcome.code !== 0) throw refusal(outcome);
    },
  };
}

const binary = process.platform === 'win32' ? 'hn-sandbox.exe' : 'hn-sandbox';

/** Looks for the helper: an explicit path, a release build in the repo, then the user's own bin folder. Returns null if none runs. */
export async function findHelper(options: { env?: NodeJS.ProcessEnv; repoRoot?: string; home?: string } = {}): Promise<string | null> {
  const env = options.env ?? process.env;
  const candidates = [
    env['HN_SANDBOX_BIN'],
    options.repoRoot === undefined ? undefined : path.join(options.repoRoot, 'native', 'hn-sandbox', 'target', 'release', binary),
    options.home === undefined ? undefined : path.join(options.home, 'bin', binary),
  ];
  for (const candidate of candidates) {
    if (candidate === undefined || candidate === '') continue;
    try {
      await access(candidate);
      const outcome = await call(candidate, ['version'], null);
      if (outcome.code === 0 && outcome.stdout.toString('utf8').startsWith('hn-sandbox ')) return candidate;
    } catch {
      // Not there, or not runnable: try the next place.
    }
  }
  return null;
}

/** Whether the helper can reach an OS keychain on this machine. `unsupported` means the key file stays the fallback. */
export async function probeKeychain(helper: string): Promise<'supported' | 'unsupported' | 'error'> {
  try {
    const outcome = await call(helper, ['keychain', 'get', '--service', 'hn-doctor-probe', '--account', `missing-${process.pid}`], null);
    if (outcome.code === 0) return 'supported';
    const reason = refusal(outcome).reason;
    return reason === 'not_found' ? 'supported' : reason === 'unsupported' ? 'unsupported' : 'error';
  } catch {
    return 'error';
  }
}
