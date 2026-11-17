import { spawn } from 'node:child_process';
import { access, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, isAbsolute, join, resolve } from 'node:path';

/**
 * Git, hardened. The binary is found by absolute path, never in the working directory. It runs with no
 * system or global config, no hooks, no fsmonitor, no credential prompts and no network protocols, so nothing a
 * repository says can make the harness run a program. Clones the harness owns get their config rewritten before
 * every command, so a filter or merge driver planted in one is never invoked.
 */

export interface GitResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

let cachedGit: string | null | undefined;

/** An absolute path to git: an override, the usual install places, then absolute PATH entries other than the working directory. */
export async function findGit(env: NodeJS.ProcessEnv = process.env): Promise<string | null> {
  if (cachedGit !== undefined && env === process.env) return cachedGit;
  const exe = process.platform === 'win32' ? 'git.exe' : 'git';
  const programFiles = env['ProgramFiles'] ?? 'C:/Program Files';
  const fixed = process.platform === 'win32' ? [`${programFiles}/Git/cmd/git.exe`, `${programFiles}/Git/bin/git.exe`] : ['/usr/bin/git', '/usr/local/bin/git', '/opt/homebrew/bin/git'];
  const cwd = resolve(process.cwd()).toLowerCase();
  const fromPath = (env['PATH'] ?? env['Path'] ?? '')
    .split(delimiter)
    .filter((entry) => entry !== '' && isAbsolute(entry) && resolve(entry).toLowerCase() !== cwd)
    .map((entry) => join(entry, exe));
  for (const candidate of [env['HN_GIT_BIN'], ...fixed, ...fromPath]) {
    if (candidate === undefined || candidate === '' || !isAbsolute(candidate)) continue;
    try {
      await access(candidate);
      if (env === process.env) cachedGit = candidate;
      return candidate;
    } catch {
      // Try the next place.
    }
  }
  if (env === process.env) cachedGit = null;
  return null;
}

let emptyHooks: string | null = null;

/** An empty folder for hooks, holding an empty file for the global config (Git for Windows cannot open NUL as one). */
async function noHooksDir(): Promise<string> {
  if (emptyHooks !== null) return emptyHooks;
  const dir = join(tmpdir(), 'hn-no-hooks');
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'empty.gitconfig'), '');
  emptyHooks = dir;
  return dir;
}

export class GitError extends Error {
  readonly result: GitResult;
  constructor(args: readonly string[], result: GitResult) {
    super(`git ${args[0] ?? ''} failed (${result.code ?? 'no code'}): ${result.stderr.trim().slice(0, 500)}`);
    this.result = result;
  }
}

export interface GitOptions {
  readonly cwd: string;
  readonly input?: string | Buffer;
  readonly timeoutMs?: number;
  /** Throw on a non-zero exit. Default true. */
  readonly check?: boolean;
}

/** Runs git with the hardened settings. Output is capped at 64 MiB. */
export async function git(args: readonly string[], options: GitOptions): Promise<GitResult> {
  const binary = await findGit();
  if (binary === null) throw new Error('git was not found in its usual places, so this needs git and cannot run.');
  const hooks = await noHooksDir();
  const hardened = [
    '-c', `core.hooksPath=${hooks}`,
    '-c', 'core.fsmonitor=false',
    '-c', 'core.untrackedCache=false',
    '-c', 'credential.helper=',
    '-c', 'protocol.allow=never',
    '-c', 'protocol.file.allow=always',
    '-c', 'core.askPass=',
    '-c', 'diff.external=',
    '-c', 'commit.gpgSign=false',
    '-c', 'tag.gpgSign=false',
    '-c', 'core.autocrlf=false',
    '-c', 'safe.directory=*',
  ];
  const env: NodeJS.ProcessEnv = {
    PATH: process.env['PATH'] ?? '',
    ...(process.platform === 'win32' ? { SystemRoot: process.env['SystemRoot'] ?? 'C:\\Windows' } : {}),
    HOME: hooks,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: join(hooks, 'empty.gitconfig'),
    GIT_ATTR_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_AUTHOR_NAME: 'hn',
    GIT_AUTHOR_EMAIL: 'hn@localhost',
    GIT_COMMITTER_NAME: 'hn',
    GIT_COMMITTER_EMAIL: 'hn@localhost',
    LC_ALL: 'C',
  };
  return new Promise((resolvePromise, reject) => {
    const child = spawn(binary, [...hardened, ...args], { cwd: options.cwd, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let size = 0;
    child.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size < 64 * 1024 * 1024) out.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => err.push(chunk));
    child.stdin.on('error', () => undefined);
    child.stdin.end(options.input ?? '');
    const timer = setTimeout(() => child.kill('SIGKILL'), options.timeoutMs ?? 120_000);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      const result = { code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') };
      if (options.check !== false && code !== 0) reject(new GitError(args, result));
      else resolvePromise(result);
    });
  });
}

/** The repository's top folder, or null when `dir` is not inside a git work tree. */
export async function gitTopLevel(dir: string): Promise<string | null> {
  const result = await git(['rev-parse', '--show-toplevel'], { cwd: dir, check: false }).catch(() => null);
  return result === null || result.code !== 0 ? null : resolve(result.stdout.trim());
}

/** The config a harness-owned clone always has. Anything a session wrote into it is replaced before git reads it. */
const CLONE_CONFIG = '[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = true\n\tautocrlf = false\n\tsymlinks = false\n';

/** Puts back the clone's own config and drops info/attributes, so a planted filter, driver or hook path does nothing. */
export async function sanitizeClone(clone: string): Promise<void> {
  await writeFile(join(clone, '.git', 'config'), CLONE_CONFIG);
  await rm(join(clone, '.git', 'info', 'attributes'), { force: true });
}

export interface Harvest {
  readonly name: string;
  /** Where the work now lives in the project's repository. */
  readonly ref: string;
  readonly commit: string;
  readonly base: string;
  readonly files: readonly string[];
}

export type Landing = { readonly ok: true; readonly files: readonly string[] } | { readonly ok: false; readonly why: string; readonly ref: string };

const NAME = /^[A-Za-z0-9-]{1,64}$/;

/**
 * Private clones for writers that must not share a checkout. A clone has no remote and its
 * own refs, so nothing in it can move the project's branches; work comes back only by the project fetching it into a
 * namespace the harness chose.
 */
export class Workspaces {
  readonly repo: string;
  readonly folder: string;
  readonly namespace: string;

  constructor(options: { readonly repo: string; readonly folder: string; readonly namespace: string }) {
    if (!/^refs\/hn\/[A-Za-z0-9/_-]+$/.test(options.namespace)) throw new Error('A workspace namespace must be under refs/hn/.');
    this.repo = options.repo;
    this.folder = options.folder;
    this.namespace = options.namespace;
  }

  /** Refuses unless the project is a git work tree whose tracked files have no uncommitted changes, which a clone could not see. */
  async check(): Promise<string | null> {
    const top = await gitTopLevel(this.repo);
    if (top === null) return 'the project is not a git repository';
    if (top.toLowerCase() !== resolve(this.repo).toLowerCase()) return 'the session does not run at the top of its git repository';
    const status = await git(['status', '--porcelain', '--untracked-files=no'], { cwd: this.repo });
    if (status.stdout.trim() !== '') return 'the project has uncommitted changes to tracked files, which a clone would not see; commit or stash them first';
    return null;
  }

  path(name: string): string {
    if (!NAME.test(name)) throw new Error(`Not a workspace name: ${name}`);
    return join(this.folder, name);
  }

  /** A fresh clone of HEAD on its own branch, with no remote. */
  async create(name: string): Promise<{ readonly path: string; readonly base: string }> {
    const path = this.path(name);
    await mkdir(this.folder, { recursive: true });
    const base = (await git(['rev-parse', 'HEAD'], { cwd: this.repo })).stdout.trim();
    await git(['clone', '--no-local', '--quiet', '--no-checkout', this.repo, path], { cwd: this.folder, timeoutMs: 600_000 });
    await sanitizeClone(path);
    await git(['checkout', '--quiet', '-B', 'hn/work', base], { cwd: path });
    return { path, base };
  }

  /** Commits whatever the writer left and fetches it into the project under the namespace. Null when nothing changed. */
  async harvest(name: string, base: string, message: string, refSuffix: string = name): Promise<Harvest | null> {
    const path = this.path(name);
    await sanitizeClone(path);
    await git(['add', '-A'], { cwd: path });
    const staged = await git(['diff', '--cached', '--quiet'], { cwd: path, check: false });
    if (staged.code !== 0) await git(['commit', '--quiet', '--no-verify', '-m', message.slice(0, 2_000)], { cwd: path });
    const commit = (await git(['rev-parse', 'HEAD'], { cwd: path })).stdout.trim();
    if (commit === base) return null;
    if (!/^[A-Za-z0-9/_-]{1,128}$/.test(refSuffix) || refSuffix.includes('..')) throw new Error(`Not a ref name: ${refSuffix}`);
    const ref = `${this.namespace}/${refSuffix}`;
    await git(['fetch', '--quiet', '--no-tags', path, `+refs/heads/hn/work:${ref}`], { cwd: this.repo });
    const files = (await git(['diff', '--name-only', '--no-renames', base, commit], { cwd: this.repo })).stdout.split('\n').filter(Boolean);
    return { name, ref, commit, base, files };
  }

  /**
   * Applies a harvest to the project's working tree as a patch, never as a merge commit: the person's branch only
   * gains changed files, as if one writer had made them. A patch that no longer applies is a conflict; nothing is
   * forced, and the work stays at its ref.
   */
  async land(harvest: Harvest): Promise<Landing> {
    const patch = await git(['diff', '--binary', '--no-ext-diff', '--no-textconv', '--no-renames', harvest.base, harvest.commit], { cwd: this.repo });
    if (patch.stdout.trim() === '') return { ok: true, files: [] };
    const check = await git(['apply', '--check', '--whitespace=nowarn', '-'], { cwd: this.repo, input: patch.stdout, check: false });
    if (check.code !== 0) return { ok: false, why: check.stderr.trim().split('\n').slice(0, 5).join('; '), ref: harvest.ref };
    await git(['apply', '--whitespace=nowarn', '-'], { cwd: this.repo, input: patch.stdout });
    return { ok: true, files: harvest.files };
  }

  /** The project's current branch head, and its name. */
  async head(): Promise<{ readonly commit: string; readonly branch: string }> {
    const commit = (await git(['rev-parse', 'HEAD'], { cwd: this.repo })).stdout.trim();
    const branch = (await git(['symbolic-ref', '--short', 'HEAD'], { cwd: this.repo, check: false })).stdout.trim();
    return { commit, branch };
  }

  /**
   * One step of the Lead's merge queue: merges `ref` into the project's current branch. The branch must still be
   * at `expected` (compare-and-set), so nothing that moved it outside the queue goes unnoticed. The merge itself runs in
   * a scratch clone whose config the harness wrote, so no hook, filter or merge driver runs; the result comes back by a
   * fast-forward. A conflict is aborted and reported; nothing is forced.
   */
  async mergeIntoHead(ref: string, expected: string, message: string): Promise<{ readonly ok: true; readonly head: string } | { readonly ok: false; readonly kind: 'conflict' | 'moved' | 'dirty'; readonly why: string }> {
    const before = await this.head();
    if (before.commit !== expected) return { ok: false, kind: 'moved', why: `the branch is at ${before.commit.slice(0, 12)}, not ${expected.slice(0, 12)} where the queue left it` };
    const status = await git(['status', '--porcelain', '--untracked-files=no'], { cwd: this.repo });
    if (status.stdout.trim() !== '') return { ok: false, kind: 'dirty', why: 'the project has uncommitted changes to tracked files' };
    const scratch = `merge-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const { path } = await this.create(scratch);
    try {
      await git(['fetch', '--quiet', '--no-tags', this.repo, `+${ref}:refs/hn/incoming`], { cwd: path });
      await sanitizeClone(path);
      const merged = await git(['merge', '--no-ff', '--no-edit', '-m', message.slice(0, 2_000), 'refs/hn/incoming'], { cwd: path, check: false });
      if (merged.code !== 0) {
        await git(['merge', '--abort'], { cwd: path, check: false });
        const why = `${merged.stdout}\n${merged.stderr}`.split('\n').filter((line) => /CONFLICT|error|fatal/i.test(line)).slice(0, 5).join('; ');
        return { ok: false, kind: 'conflict', why: why === '' ? 'the merge did not apply' : why };
      }
      await git(['fetch', '--quiet', '--no-tags', path, `+HEAD:${this.namespace}/merged`], { cwd: this.repo });
      if ((await this.head()).commit !== expected) return { ok: false, kind: 'moved', why: 'the branch moved while the merge ran' };
      const forward = await git(['merge', '--ff-only', '--quiet', `${this.namespace}/merged`], { cwd: this.repo, check: false });
      if (forward.code !== 0) return { ok: false, kind: 'moved', why: forward.stderr.trim().slice(0, 300) };
      return { ok: true, head: (await this.head()).commit };
    } finally {
      await this.remove(scratch).catch(() => undefined);
    }
  }

  async remove(name: string): Promise<void> {
    await rm(this.path(name), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}
