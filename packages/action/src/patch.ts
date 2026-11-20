import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { git } from './proc.ts';

/**
 * The patch is what a model, in a box, decided to change. The publish job does not believe it. It reads the patch the
 * way `git apply` will, and refuses the whole thing, with a reason a person can act on, if it would touch what must
 * stay a human's decision or is too big for anyone to review. A refused patch is not silently trimmed to something
 * that passes: half a change is not what anyone asked for, and the files left out would go unmentioned.
 */

export const MAX_PATCH_BYTES = 2 * 1024 * 1024;
export const MAX_FILES = 100;
export const MAX_CHANGED_LINES = 10_000;

/**
 * A path (lower-cased, forward slashes) is protected if it equals one of these, or lies under one that ends in `/`. A
 * repository that uses its own copy of the Action (a local `./action` path) adds that folder with `protected-paths`.
 */
export const PROTECTED: readonly string[] = ['.github/', '.githooks/', '.husky/', '.gitmodules', '.gitattributes', '.npmrc', '.yarnrc', '.yarnrc.yml', '.pnpmfile.cjs', 'codeowners'];

export interface PatchProblem {
  readonly path: string;
  readonly rule: string;
}

export interface PatchReport {
  readonly ok: boolean;
  readonly files: readonly string[];
  readonly additions: number;
  readonly deletions: number;
  readonly problems: readonly PatchProblem[];
}

function pathProblem(path: string, extraProtected: readonly string[]): string | null {
  if (path === '' || path.length > 260) return 'a path that is empty or too long';
  if (/[\u0000-\u001f\u007f\\"]/.test(path) || path.includes(':')) return 'a path with a control character, a backslash, a quote or a colon';
  if (path.startsWith('/') || /(^|\/)\.\.(\/|$)/.test(path)) return 'a path that leaves the repository';
  const lower = path.toLowerCase();
  const parts = lower.split('/');
  if (parts.some((part) => part === '.git' || part.startsWith('.git ') || part === '.git.' || part === 'git~1')) return 'a path inside .git';
  const rules = [...PROTECTED, ...extraProtected.map((rule) => rule.toLowerCase())];
  for (const rule of rules) {
    if (rule.endsWith('/') ? lower.startsWith(rule) || lower === rule.slice(0, -1) : lower === rule || lower.endsWith(`/${rule}`)) return `a protected path (${rule})`;
  }
  return null;
}

/** What the patch would change, and every reason it must not be applied without a person. */
export async function inspectPatch(patch: Buffer, options: { protectedPaths?: readonly string[] } = {}): Promise<PatchReport> {
  const problems: PatchProblem[] = [];
  if (patch.length > MAX_PATCH_BYTES) return { ok: false, files: [], additions: 0, deletions: 0, problems: [{ path: '(the patch)', rule: `bigger than ${MAX_PATCH_BYTES} bytes` }] };
  // `git apply` reads the patch the way the publish step will, so what it reports is what would happen. It needs no repository for this.
  const dir = await mkdtemp(join(tmpdir(), 'hn-patch-'));
  try {
    const numstat = await git(['apply', '--numstat', '-z'], { cwd: dir, input: patch });
    if (numstat.status !== 0) return { ok: false, files: [], additions: 0, deletions: 0, problems: [{ path: '(the patch)', rule: 'not a patch git can read' }] };
    const summary = await git(['apply', '--summary'], { cwd: dir, input: patch });
    if (summary.status !== 0) return { ok: false, files: [], additions: 0, deletions: 0, problems: [{ path: '(the patch)', rule: 'not a patch git can read' }] };

    const files: string[] = [];
    let additions = 0;
    let deletions = 0;
    // `-z` numstat: "<added>\t<deleted>\t<path>\0" per file. A rename would use an extra empty field, and none is expected.
    for (const entry of numstat.stdout.toString('utf8').split('\0').filter((part) => part !== '')) {
      const match = /^(\d+|-)\t(\d+|-)\t([\s\S]*)$/.exec(entry);
      if (match === null) {
        problems.push({ path: '(the patch)', rule: 'a change git described in a form this check does not understand' });
        continue;
      }
      const [, added, removed, path = ''] = match;
      files.push(path);
      if (added === '-' || removed === '-') problems.push({ path, rule: 'a binary change' });
      else {
        additions += Number(added);
        deletions += Number(removed);
      }
      const bad = pathProblem(path, options.protectedPaths ?? []);
      if (bad !== null) problems.push({ path, rule: bad });
    }
    for (const line of summary.stdout.toString('utf8').split('\n')) {
      const mode = /^ (?:create|delete) mode (\d+) (.*)$/.exec(line) ?? /^ mode change (\d+) => (\d+) (.*)$/.exec(line);
      if (mode === null) {
        if (/^ (rename|copy) /.test(line)) problems.push({ path: line.trim().slice(0, 100), rule: 'a rename or copy (patches are made without them)' });
        continue;
      }
      const modes = mode.length === 4 ? [mode[1], mode[2]] : [mode[1]];
      const path = mode[mode.length - 1] ?? '';
      for (const value of modes) {
        if (value === '120000') problems.push({ path, rule: 'a symbolic link' });
        else if (value === '160000') problems.push({ path, rule: 'a submodule' });
        else if (value !== '100644' && value !== '100755') problems.push({ path, rule: `an unusual file mode (${value})` });
      }
    }
    if (files.length > MAX_FILES) problems.push({ path: '(the patch)', rule: `more than ${MAX_FILES} files` });
    if (additions + deletions > MAX_CHANGED_LINES) problems.push({ path: '(the patch)', rule: `more than ${MAX_CHANGED_LINES} changed lines` });
    if (files.length === 0 && patch.length > 0) problems.push({ path: '(the patch)', rule: 'a patch with no files in it' });
    return { ok: problems.length === 0, files, additions, deletions, problems };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
