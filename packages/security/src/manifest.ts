import { canonicalForRules } from './rules.ts';
import { isControlPath } from './trust.ts';

/**
 * The host-exec manifest. The worktree a box wrote is hostile output (invariant 13): a file in it
 * can make the HOST run code the next time anything touches it, such as `git status`, an editor,
 * `make` or a CI job. Changes to these paths are never applied without a human seeing the diff.
 */

/** File names (lowercase, after NTFS normalisation) that the host or its tools will execute or obey. */
const EXEC_FILES: Readonly<Record<string, string>> = {
  '.gitattributes': 'git runs filters named here',
  '.gitmodules': 'git fetches and runs what submodules name',
  '.git': 'a gitfile or git directory redirects git',
  '.envrc': 'direnv runs this when you enter the folder',
  '.pre-commit-config.yaml': 'pre-commit runs these hooks',
  'mise.toml': 'mise runs tasks and sets the environment',
  '.mise.toml': 'mise runs tasks and sets the environment',
  '.npmrc': 'npm reads scripts, registries and tokens from here',
  '.yarnrc': 'yarn reads plugins and scripts from here',
  '.yarnrc.yml': 'yarn loads plugins from here',
  makefile: 'make runs the recipes in it',
  gnumakefile: 'make runs the recipes in it',
  justfile: 'just runs the recipes in it',
  '.mcp.json': 'an agent starts the servers it names',
  '.tool-versions': 'asdf picks the programs that run',
};

/** Folders whose contents the host or its tools will run or obey. */
const EXEC_FOLDERS: Readonly<Record<string, string>> = {
  '.git': 'git internals run code on the host',
  '.vscode': 'the editor runs tasks and settings from here',
  '.husky': 'git hooks run on commit',
  '.githooks': 'git hooks run on commit',
  '.cargo': 'cargo reads build scripts and linkers from here',
  '.claude': 'another agent obeys what is here',
  '.cursor': 'another agent obeys what is here',
  '.devcontainer': 'the editor builds and runs this container',
  '.idea': 'the IDE runs configurations from here',
};

export interface ChangeFacts {
  /** The old and new text, for files whose meaning depends on one field. Null when absent. */
  readonly before?: string | null;
  readonly after?: string | null;
  /** The new file mode, when known. */
  readonly mode?: number;
}

function scriptsOf(text: string | null | undefined): string {
  // No file and a file with no scripts mean the same thing, so they compare equal.
  if (text === null || text === undefined) return 'null';
  try {
    const parsed = JSON.parse(text) as { scripts?: unknown };
    return JSON.stringify(parsed.scripts ?? null);
  } catch {
    // A package.json that does not parse cannot be shown to be safe, so it counts as changed.
    return `unparseable:${text.length}`;
  }
}

/** Directories that look like a bare git repository: `HEAD`, `objects` and `refs` side by side. */
export function bareRepoRoots(paths: readonly string[]): Set<string> {
  const children = new Map<string, Set<string>>();
  for (const path of paths) {
    const segments = canonicalForRules(path);
    for (let i = 0; i < segments.length; i += 1) {
      const dir = segments.slice(0, i).join('/');
      const set = children.get(dir) ?? new Set<string>();
      set.add(segments[i] as string);
      children.set(dir, set);
    }
  }
  const roots = new Set<string>();
  for (const [dir, names] of children) if (names.has('head') && names.has('objects') && names.has('refs')) roots.add(dir);
  return roots;
}

/**
 * Why a path in a hand-back needs a human, or an empty list if it does not. `bareRoots` comes from
 * `bareRepoRoots` over the whole change set, because a bare repo is only recognisable from its siblings.
 */
export function hostExecReasons(relativePath: string, facts: ChangeFacts = {}, bareRoots: ReadonlySet<string> = new Set()): string[] {
  const reasons: string[] = [];
  const segments = canonicalForRules(relativePath);
  const name = segments.at(-1) ?? '';
  const folders = segments.slice(0, -1);

  const byName = EXEC_FILES[name];
  if (byName !== undefined) reasons.push(`${name}: ${byName}`);
  for (const folder of folders) {
    const why = EXEC_FOLDERS[folder];
    if (why !== undefined) reasons.push(`${folder}/: ${why}`);
  }
  if (folders.includes('workflows') && folders.includes('.github')) reasons.push('.github/workflows/: CI runs these with the repository\'s secrets');
  if (segments.join('/') === '.cargo/config' || segments.join('/') === '.cargo/config.toml') reasons.push('.cargo/config.toml: cargo runs linkers and wrappers named here');
  for (let i = 0; i < segments.length; i += 1) {
    if (bareRoots.has(segments.slice(0, i).join('/')) && i < segments.length) {
      reasons.push('a bare git repository shape: git will treat this folder as a repository');
      break;
    }
  }
  if (name === 'package.json' && scriptsOf(facts.before) !== scriptsOf(facts.after)) reasons.push('package.json: the scripts changed, and npm runs them on install and test');
  if (facts.mode !== undefined && (facts.mode & 0o6000) !== 0) reasons.push('the file has a setuid or setgid bit');
  if (isControlPath(relativePath)) reasons.push('a control file: it can steer the agent or run code');
  return [...new Set(reasons)];
}
