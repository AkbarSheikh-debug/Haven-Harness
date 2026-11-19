import { execFile } from 'node:child_process';
import { copyFile, lstat, mkdir, readdir } from 'node:fs/promises';
import { dirname, join, normalize, relative, sep } from 'node:path';
import { isSecretPath } from '@hn/security';

/**
 * Building a project's image (decision 9) without trusting the project. The Dockerfile is project-written, so it is
 * read, not obeyed: every base image must be pinned by digest, a `# syntax=` frontend only from Docker's own image and
 * pinned, no remote ADD, no secret or ssh mounts, no network flag on RUN. The build context is never the project
 * folder: the harness copies only the files the Dockerfile's COPY and ADD name, and never a secret, `.git` or a link.
 * The build runs with `--network none`.
 */

export interface DockerfileReport {
  readonly bases: readonly string[];
  /** Project paths the Dockerfile copies in (COPY and ADD without --from). */
  readonly sources: readonly string[];
  /** Why this Dockerfile is refused, in plain words. Empty when it is acceptable. */
  readonly problems: readonly string[];
}

const PINNED = /@sha256:[0-9a-f]{64}$/;
const OFFICIAL_FRONTEND = /^(docker\.io\/)?docker\/dockerfile(-upstream)?:[\w.-]+@sha256:[0-9a-f]{64}$/;

/** Joins continuation lines and drops comments, keeping the parser directives at the top. */
function instructions(text: string): { directives: Map<string, string>; lines: string[] } {
  const directives = new Map<string, string>();
  const raw = text.split(/\r?\n/);
  let i = 0;
  for (; i < raw.length; i += 1) {
    const match = /^\s*#\s*([a-zA-Z]+)\s*=\s*(.*?)\s*$/.exec(raw[i] as string);
    if (match === null) break;
    directives.set((match[1] as string).toLowerCase(), match[2] as string);
  }
  const lines: string[] = [];
  let current = '';
  for (; i < raw.length; i += 1) {
    const line = raw[i] as string;
    if (/^\s*#/.test(line)) continue;
    if (/\\\s*$/.test(line)) {
      current += `${line.replace(/\\\s*$/, '')} `;
      continue;
    }
    current += line;
    if (current.trim() !== '') lines.push(current.trim());
    current = '';
  }
  if (current.trim() !== '') lines.push(current.trim());
  return { directives, lines };
}

/** Splits an instruction's arguments, as JSON form or shell words. */
function words(rest: string): string[] {
  if (rest.trim().startsWith('[')) {
    try {
      const parsed = JSON.parse(rest) as unknown;
      if (Array.isArray(parsed)) return parsed.map(String);
    } catch {
      // Falls through to words.
    }
  }
  return rest.split(/\s+/).filter((word) => word !== '');
}

export function analyzeDockerfile(text: string): DockerfileReport {
  const { directives, lines } = instructions(text);
  const problems: string[] = [];
  const bases: string[] = [];
  const stages = new Set<string>();
  const sources: string[] = [];
  const syntax = directives.get('syntax');
  if (syntax !== undefined && !OFFICIAL_FRONTEND.test(syntax)) {
    problems.push(`# syntax=${syntax} is refused: a build frontend runs with the builder's privileges, so only Docker's own docker/dockerfile image, pinned by digest, is accepted.`);
  }
  for (const line of lines) {
    const [keyword = '', ...restParts] = line.split(/\s+/);
    const rest = restParts.join(' ');
    const op = keyword.toUpperCase();
    if (op === 'FROM') {
      const parts = words(rest).filter((word) => !word.startsWith('--'));
      const image = parts[0] ?? '';
      const alias = parts[1]?.toUpperCase() === 'AS' ? parts[2] : undefined;
      if (image !== 'scratch' && !stages.has(image) && !PINNED.test(image)) problems.push(`FROM ${image} is not pinned by digest (name@sha256:...), so it can change under you.`);
      if (/--platform=\$|\$\{?BUILDPLATFORM/.test(rest) === false && /\$/.test(image)) problems.push(`FROM ${image} uses a variable, so the base cannot be checked.`);
      bases.push(image);
      if (alias !== undefined) stages.add(alias);
    } else if (op === 'COPY' || op === 'ADD') {
      const parts = words(rest);
      const flags = parts.filter((word) => word.startsWith('--'));
      const operands = parts.filter((word) => !word.startsWith('--'));
      if (flags.some((flag) => flag.startsWith('--from'))) continue;
      const fileSources = operands.slice(0, -1);
      for (const source of fileSources) {
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(source) || /^git@/.test(source)) {
          problems.push(`${op} ${source} fetches from the network during the build, which is refused.`);
          continue;
        }
        sources.push(source);
      }
    } else if (op === 'RUN') {
      if (/--mount=[^\s]*type=(secret|ssh)/.test(rest)) problems.push('RUN --mount=type=secret or ssh is refused: a build gets no secrets and no ssh agent.');
      if (/--network(=|\s)/.test(rest)) problems.push('RUN --network is refused: builds run with no network.');
      if (/--security=insecure/.test(rest)) problems.push('RUN --security=insecure is refused.');
    }
  }
  if (bases.length === 0) problems.push('The Dockerfile has no FROM.');
  return { bases, sources, problems };
}

export interface Skip {
  readonly path: string;
  readonly reason: string;
}

export interface ContextReport {
  readonly copied: readonly string[];
  readonly skipped: readonly Skip[];
}

const NEVER = new Set(['.git', 'node_modules', '.hn', '.svn', '.hg']);
const MAX_CONTEXT_FILES = 20_000;

/**
 * Copies only the named sources from the project into `out`. Never a secret, never `.git`, `node_modules` or `.hn`,
 * never a link (it could point anywhere), never a path that climbs out of the project. `.` means the whole project,
 * still filtered the same way.
 */
export async function buildContext(projectRoot: string, sources: readonly string[], out: string): Promise<ContextReport> {
  const copied: string[] = [];
  const skipped: Skip[] = [];
  await mkdir(out, { recursive: true });
  const visit = async (relativePath: string): Promise<void> => {
    if (copied.length >= MAX_CONTEXT_FILES) return;
    const posix = relativePath.split(sep).join('/');
    const parts = posix.split('/');
    if (parts.some((part) => NEVER.has(part))) return void skipped.push({ path: posix, reason: 'never part of a build context' });
    if (posix !== '' && isSecretPath(posix)) return void skipped.push({ path: posix, reason: 'a secret file' });
    const absolute = join(projectRoot, relativePath);
    const info = await lstat(absolute).catch(() => null);
    if (info === null) return void skipped.push({ path: posix, reason: 'not found' });
    if (info.isSymbolicLink()) return void skipped.push({ path: posix, reason: 'a link, which could point anywhere' });
    if (info.isDirectory()) {
      for (const entry of await readdir(absolute)) await visit(relativePath === '' ? entry : join(relativePath, entry));
      return;
    }
    if (!info.isFile()) return void skipped.push({ path: posix, reason: 'not a regular file' });
    if (info.nlink > 1) return void skipped.push({ path: posix, reason: 'a hard link, which could be a secret by another name' });
    await mkdir(dirname(join(out, relativePath)), { recursive: true });
    await copyFile(absolute, join(out, relativePath));
    copied.push(posix);
  };
  for (const source of [...new Set(sources)]) {
    // Only an exact "./" prefix is dropped: "../x" must stay "../x" and be refused, not become "x".
    const cleaned = normalize(source.replace(/^\.\//, '') || '.');
    if (cleaned.startsWith('..') || /^([a-zA-Z]:|[\\/])/.test(cleaned)) {
      skipped.push({ path: source, reason: 'outside the project' });
      continue;
    }
    if (/[*?[]/.test(cleaned)) {
      skipped.push({ path: source, reason: 'wildcards are not expanded; name the files' });
      continue;
    }
    await visit(cleaned === '.' ? '' : cleaned);
  }
  return { copied: copied.sort(), skipped };
}

/** The `docker build` arguments. Pure, so every flag is visible to a test. */
export function buildArgs(contextDir: string, dockerfile: string, tag: string): string[] {
  if (!/^[a-z0-9][a-z0-9._-]{0,63}(:[\w.-]{1,64})?$/.test(tag)) throw new Error(`${tag} is not a plain image tag.`);
  return ['build', '--network', 'none', '--no-cache', '--file', dockerfile, '--tag', tag, '--label', 'hn.recipe=1', contextDir];
}

/** Runs `docker build` with a small, fixed environment: no build arguments, secrets or ssh from this machine. */
export function dockerBuild(docker: string, args: readonly string[]): Promise<{ code: number; output: string }> {
  const env: NodeJS.ProcessEnv = { DOCKER_BUILDKIT: '1' };
  for (const name of ['PATH', 'Path', 'SystemRoot', 'USERPROFILE', 'HOME', 'TEMP', 'TMP', 'ProgramData', 'APPDATA', 'LOCALAPPDATA']) if (process.env[name] !== undefined) env[name] = process.env[name];
  return new Promise((resolve) => {
    execFile(docker, [...args], { env, maxBuffer: 16 * 1024 * 1024, windowsHide: true, timeout: 30 * 60 * 1000 }, (error, stdout, stderr) => {
      resolve({ code: error === null ? 0 : typeof error.code === 'number' ? error.code : 1, output: `${stdout}${stderr}` });
    });
  });
}

/** The image ID of a tag, which is content-addressed, so it pins exactly what was built. */
export function imageId(docker: string, tag: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(docker, ['image', 'inspect', '--format', '{{.Id}}', tag], { windowsHide: true, timeout: 60_000 }, (error, stdout) => {
      const id = stdout.trim();
      resolve(error === null && /^sha256:[0-9a-f]{64}$/.test(id) ? id : null);
    });
  });
}

export const relativeTo = (root: string, path: string): string => relative(root, path).split(sep).join('/');
