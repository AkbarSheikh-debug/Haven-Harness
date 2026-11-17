import { createHash } from 'node:crypto';
import { copyFile, lstat, mkdir, readFile, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { bareRepoRoots, hostExecReasons, isSecretPath, summarizeDiff } from '@hn/security';
import type { SafeFiles } from './safe-files.ts';

/**
 * Hand-back. The box works on a COPY of the project, never the host tree. When it is
 * done, what it wrote is hostile output: a file in it can make the host run code the next time
 * anything touches it. So the copy is turned into a plan of whole files. Files on the host-exec
 * manifest need a human to see the diff and approve the exact content. Links, devices and files
 * with more than one name are never imported. Nothing here runs git or any other program.
 */

export interface FileState {
  readonly hash: string;
  readonly mode: number;
  readonly size: number;
}

export type Baseline = ReadonlyMap<string, FileState>;

export interface Skipped {
  readonly path: string;
  readonly why: string;
}

const MAX_FILES = 50_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_DIFF_BYTES = 256 * 1024;

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const posix = (path: string): string => path.replaceAll('\\', '/');

/** A name Windows would treat specially is skipped on every platform, so a copy made on Linux is safe to import on Windows. */
function unsafeName(name: string): string | null {
  if (/[:<>"|?*\u0000-\u001f]/.test(name)) return 'its name has characters Windows treats specially';
  if (/[. ]$/.test(name)) return 'its name ends in a dot or space';
  if (/^(con|prn|aux|nul|conin\$|conout\$|com[1-9]|lpt[1-9])(\..*)?$/i.test(name)) return 'its name is a reserved device name';
  return null;
}

export interface CopyReport {
  readonly baseline: Baseline;
  readonly skipped: readonly Skipped[];
}

export interface CopyOptions {
  /** Extra paths to leave out, such as `node_modules`. Receives a forward-slash relative path. */
  readonly skip?: (relativePath: string) => boolean;
}

/**
 * Copies the project for the box. `.git` is left out entirely, so the box has no repository to attack
 * and `git show HEAD~50:.env` finds nothing. Secret files are left out by name. Links and special
 * files are not copied.
 */
export async function createCopy(hostRoot: string, copyRoot: string, options: CopyOptions = {}): Promise<CopyReport> {
  const baseline = new Map<string, FileState>();
  const skipped: Skipped[] = [];
  await mkdir(copyRoot, { recursive: true });

  const walk = async (relativeDir: string): Promise<void> => {
    const entries = await readdir(join(hostRoot, relativeDir), { withFileTypes: true });
    for (const entry of entries) {
      const relative = posix(join(relativeDir, entry.name));
      if (entry.name.toLowerCase() === '.git') {
        skipped.push({ path: relative, why: 'git internals are never given to the box' });
        continue;
      }
      if (isSecretPath(relative)) {
        skipped.push({ path: relative, why: 'it may hold secrets' });
        continue;
      }
      if (options.skip?.(relative) === true) {
        skipped.push({ path: relative, why: 'left out by request' });
        continue;
      }
      const info = await lstat(join(hostRoot, relative));
      if (info.isSymbolicLink()) skipped.push({ path: relative, why: 'a symbolic link is not copied' });
      else if (info.isDirectory()) {
        await mkdir(join(copyRoot, relative), { recursive: true });
        await walk(relative);
      } else if (!info.isFile()) skipped.push({ path: relative, why: 'a special file is not copied' });
      else if (info.size > MAX_FILE_BYTES) skipped.push({ path: relative, why: 'the file is too large to copy' });
      else {
        if (baseline.size >= MAX_FILES) throw new Error(`The project has more than ${MAX_FILES} files. Narrow it with skip.`);
        await copyFile(join(hostRoot, relative), join(copyRoot, relative));
        baseline.set(relative, { hash: sha256(await readFile(join(copyRoot, relative))), mode: info.mode & 0o7777, size: info.size });
      }
    }
  };
  await walk('');
  return { baseline, skipped };
}

export const baselineToJson = (baseline: Baseline): string => JSON.stringify([...baseline]);

/** Rebuilds a saved baseline. Anything malformed means no baseline, and nothing can be imported without one. */
export function baselineFromJson(text: string): Baseline {
  const entries = JSON.parse(text) as unknown;
  if (!Array.isArray(entries)) throw new Error('The baseline is not a list.');
  const map = new Map<string, FileState>();
  for (const entry of entries) {
    const [path, state] = entry as [unknown, Record<string, unknown>];
    if (typeof path !== 'string' || typeof state?.['hash'] !== 'string' || typeof state['mode'] !== 'number' || typeof state['size'] !== 'number') {
      throw new Error('The baseline has a malformed entry.');
    }
    map.set(path, { hash: state['hash'], mode: state['mode'], size: state['size'] });
  }
  return map;
}

export type ChangeKind = 'add' | 'modify' | 'delete';

export interface PlannedChange {
  readonly kind: ChangeKind;
  readonly path: string;
  /** Content hash to import. Absent for a delete. The approval binds to this. */
  readonly hash?: string;
  readonly size?: number;
  readonly mode?: number;
  /** Why a human must see this. Empty for an ordinary file. */
  readonly reasons: readonly string[];
  /** What changed, as text a person can read. */
  readonly diff: string;
}

export interface ImportPlan {
  readonly auto: readonly PlannedChange[];
  readonly gated: readonly PlannedChange[];
  readonly skipped: readonly Skipped[];
}

async function readText(path: string): Promise<string | null> {
  try {
    const bytes = await readFile(path);
    if (bytes.length > MAX_DIFF_BYTES || bytes.includes(0)) return null;
    return bytes.toString('utf8');
  } catch {
    return null;
  }
}

/** Compares the copy with the baseline and sorts the changes into the ones that may go back and the ones that need a human. */
export async function planImport(hostRoot: string, copyRoot: string, baseline: Baseline): Promise<ImportPlan> {
  const skipped: Skipped[] = [];
  const found = new Map<string, FileState>();

  const walk = async (relativeDir: string): Promise<void> => {
    for (const entry of await readdir(join(copyRoot, relativeDir), { withFileTypes: true })) {
      const relative = posix(join(relativeDir, entry.name));
      try {
        const info = await lstat(join(copyRoot, relative));
        const bad = unsafeName(entry.name);
        if (info.isSymbolicLink()) skipped.push({ path: relative, why: 'a symbolic link is never imported' });
        else if (info.isDirectory()) await walk(relative);
        else if (!info.isFile()) skipped.push({ path: relative, why: 'a special file is never imported' });
        else if (bad !== null) skipped.push({ path: relative, why: bad });
        else if (info.nlink > 1) skipped.push({ path: relative, why: 'the file has more than one name, so it may be a way into another file' });
        else if (info.size > MAX_FILE_BYTES) skipped.push({ path: relative, why: 'the file is too large to import' });
        else found.set(relative, { hash: sha256(await readFile(join(copyRoot, relative))), mode: info.mode & 0o7777, size: info.size });
      } catch (error) {
        // Whatever the box wrote is hostile. An entry that cannot be inspected is left out, never trusted and never a crash.
        skipped.push({ path: relative, why: `it cannot be inspected (${(error as NodeJS.ErrnoException).code ?? 'error'}), so it is not imported` });
      }
    }
  };
  await walk('');

  const raw: { kind: ChangeKind; path: string; state?: FileState }[] = [];
  for (const [path, state] of found) {
    const was = baseline.get(path);
    if (was === undefined) raw.push({ kind: 'add', path, state });
    else if (was.hash !== state.hash) raw.push({ kind: 'modify', path, state });
    else if ((was.mode & 0o6000) !== (state.mode & 0o6000) && (state.mode & 0o6000) !== 0) raw.push({ kind: 'modify', path, state });
    else if (was.mode !== state.mode) skipped.push({ path, why: 'a mode change is not applied' });
  }
  for (const path of baseline.keys()) if (!found.has(path) && !skipped.some((entry) => entry.path === path)) raw.push({ kind: 'delete', path });

  const roots = bareRepoRoots(raw.map((change) => change.path));
  const auto: PlannedChange[] = [];
  const gated: PlannedChange[] = [];
  for (const change of raw) {
    const before = change.kind === 'add' ? null : await readText(join(hostRoot, change.path));
    const after = change.kind === 'delete' ? null : await readText(join(copyRoot, change.path));
    const reasons = hostExecReasons(change.path, { before, after, ...(change.state === undefined ? {} : { mode: change.state.mode }) }, roots);
    const diff =
      before === null && after === null
        ? change.kind === 'delete'
          ? 'The file would be deleted.'
          : `A binary or large file (${change.state?.size ?? 0} bytes).`
        : summarizeDiff(before ?? '', after ?? '');
    const planned: PlannedChange = {
      kind: change.kind,
      path: change.path,
      ...(change.state === undefined ? {} : { hash: change.state.hash, size: change.state.size, mode: change.state.mode }),
      reasons,
      diff,
    };
    (reasons.length > 0 ? gated : auto).push(planned);
  }
  const order = (a: PlannedChange, b: PlannedChange): number => (a.path < b.path ? -1 : 1);
  return { auto: auto.sort(order), gated: gated.sort(order), skipped };
}

export interface ApplyOptions {
  readonly files: SafeFiles;
  readonly hostRoot: string;
  readonly copyRoot: string;
  readonly baseline: Baseline;
  /** Human approvals: path to the exact content hash that was shown (`delete` for a deletion). Anything else is not applied. */
  readonly approved?: ReadonlyMap<string, string>;
}

export interface ImportResult {
  readonly applied: readonly string[];
  readonly blocked: readonly Skipped[];
}

/**
 * Applies a plan to the host through the safe-file helper, so a link on the host side cannot redirect
 * a write. The box must be stopped first. Each change re-checks that the content is what the human was
 * shown and that the host file is still what the copy started from.
 */
export async function applyImport(plan: ImportPlan, options: ApplyOptions): Promise<ImportResult> {
  const applied: string[] = [];
  const blocked: Skipped[] = [];
  const approved = options.approved ?? new Map<string, string>();

  const one = async (change: PlannedChange, needsApproval: boolean): Promise<void> => {
    const key = change.hash ?? 'delete';
    if (needsApproval && approved.get(change.path) !== key) {
      blocked.push({ path: change.path, why: `needs a human: ${change.reasons.join('; ')}` });
      return;
    }
    const target = join(options.hostRoot, change.path);
    const was = options.baseline.get(change.path);
    try {
      if (change.kind === 'add') {
        const bytes = await readFile(join(options.copyRoot, change.path));
        if (sha256(bytes) !== change.hash) return void blocked.push({ path: change.path, why: 'the file changed after it was reviewed' });
        await options.files.write(options.hostRoot, target, bytes, { mkdir: true, createOnly: true });
      } else if (change.kind === 'modify') {
        const bytes = await readFile(join(options.copyRoot, change.path));
        if (sha256(bytes) !== change.hash) return void blocked.push({ path: change.path, why: 'the file changed after it was reviewed' });
        const host = await options.files.read(options.hostRoot, target, MAX_FILE_BYTES).catch(() => null);
        if (host === null || was === undefined || sha256(host) !== was.hash) return void blocked.push({ path: change.path, why: 'the file on the host changed since the copy was made' });
        await options.files.write(options.hostRoot, target, bytes, { mkdir: false });
      } else {
        const host = await options.files.read(options.hostRoot, target, MAX_FILE_BYTES).catch(() => null);
        if (host === null || was === undefined || sha256(host) !== was.hash) return void blocked.push({ path: change.path, why: 'the file on the host changed since the copy was made' });
        await options.files.delete(options.hostRoot, target);
      }
      applied.push(change.path);
    } catch (error) {
      blocked.push({ path: change.path, why: error instanceof Error ? error.message : String(error) });
    }
  };

  for (const change of plan.auto) await one(change, false);
  for (const change of plan.gated) await one(change, true);
  return { applied, blocked };
}

/** Where the baseline for a copy is kept: next to the copy, never inside the folder the box can write. */
export const baselinePath = (copyRoot: string): string => join(dirname(copyRoot), `${copyRoot.split(/[\\/]/).at(-1) ?? 'copy'}.baseline.json`);
