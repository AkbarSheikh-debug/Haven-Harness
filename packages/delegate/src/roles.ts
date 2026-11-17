import { createHash } from 'node:crypto';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { InstructionReader, InstructionTrust, Quarantined } from '@hn/context';
import { MODES, scanThreat, type Mode } from '@hn/security';

export const ROLE_NAME = /^[a-z][a-z0-9-]{0,39}$/;
export const ROLE_DESCRIPTION_MAX = 300;
export const ROLE_BODY_MAX = 8_000;
const ROLE_FILE_MAX = 32 * 1024;
const KNOWN_KEYS = new Set(['name', 'description', 'tools', 'model', 'mode']);

/** `cheap` is the route's cheap tier (the summary model), `main` the parent's model; anything else names a model. */
export type RoleModel = 'main' | 'cheap' | (string & {});

export interface Role {
  readonly name: string;
  readonly description: string;
  /** The tools this role may be offered, a subset of what the parent has. Null means everything the parent may pass on. */
  readonly tools: readonly string[] | null;
  readonly model: RoleModel;
  /** The highest mode this role runs in. The child gets the lower of this and the parent's mode, so a role can never widen. */
  readonly mode: Mode;
  /** The role's system prompt, added after the harness's own. */
  readonly body: string;
  readonly scope: 'built-in' | 'user' | 'project';
  /** SHA-256 of the role file, so a grant names exactly the role a person approved. */
  readonly hash: string;
}

const READ_TOOLS = ['read_file', 'list_files', 'grep', 'read_image', 'web_fetch', 'web_search', 'skill'];

function builtIn(role: Omit<Role, 'scope' | 'hash'>): Role {
  return { ...role, scope: 'built-in', hash: createHash('sha256').update(JSON.stringify(role)).digest('hex') };
}

/** The built-in crew. */
export const BUILT_IN_ROLES: readonly Role[] = [
  builtIn({
    name: 'scout',
    description: 'Cheap and read-only. Finds where things are and reports back with paths and short quotes.',
    tools: READ_TOOLS,
    model: 'cheap',
    mode: 'read-only',
    body: 'You are a scout. Find what the brief asks for and report it: file paths, line numbers, short quotes. Do not change anything. Keep the report short and factual, and say what you could not find.',
  }),
  builtIn({
    name: 'planner',
    description: 'Read-only. Turns a goal and a scout report into a numbered, verifiable plan.',
    tools: [...READ_TOOLS, 'todo_write'],
    model: 'main',
    mode: 'read-only',
    body: 'You are a planner. Read what you need, then write a numbered plan: each step names the files to change, the change, and how to check it. Do not change anything yourself. End with the risks you see.',
  }),
  builtIn({
    name: 'worker',
    description: 'Full tools and the strong model. Carries out a plan, runs the checks, reports what changed.',
    tools: null,
    model: 'main',
    mode: 'yolo',
    body: 'You are a worker. Carry out the brief exactly, in small edits. Run the project checks after changing code and read the result. Report every file you changed and what you verified; say plainly what you did not do.',
  }),
  builtIn({
    name: 'reviewer',
    description: 'Read-only. Reviews a change against its brief and lists concrete problems.',
    tools: ['read_file', 'list_files', 'grep', 'skill'],
    model: 'main',
    mode: 'read-only',
    body: 'You are a reviewer. Compare what was done with what was asked. List concrete problems with file and line, most serious first. Say "no problems found" only if you checked. Do not change anything.',
  }),
];

export interface RoleNotice {
  readonly file: string;
  readonly message: string;
}

export interface RoleSet {
  readonly roles: readonly Role[];
  readonly notices: readonly RoleNotice[];
  /** Project role files nobody approved yet, for the same card instruction files use. */
  readonly pending: readonly Quarantined[];
}

export interface RoleRoots {
  /** `~/.hn/agents`: the user's own, loaded without approval. */
  readonly user: string | null;
  /** `<project>/.hn/agents`: loaded only when the file's exact content is approved. */
  readonly project: string | null;
  readonly projectRoot: string | null;
  readonly reader: InstructionReader;
  readonly trust: InstructionTrust;
  readonly list?: (directory: string) => Promise<string[]>;
}

export interface ParsedRole {
  readonly role: Omit<Role, 'scope' | 'hash'> | null;
  readonly problems: readonly string[];
}

/** The same tiny front-matter reader skills use: `key: value` lines, no YAML library. */
export function parseRole(text: string): ParsedRole {
  const problems: string[] = [];
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (match === null) return { role: null, problems: ['The role has no front matter between --- lines.'] };
  const fields = new Map<string, string>();
  for (const line of (match[1] ?? '').split(/\r?\n/)) {
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
    const pair = /^([A-Za-z_][\w-]*):\s*(.*)$/.exec(line);
    if (pair === null) {
      problems.push(`Front matter line is not "key: value": ${line.slice(0, 80)}`);
      continue;
    }
    const key = (pair[1] ?? '').toLowerCase();
    let value = (pair[2] ?? '').trim();
    if (/^(["']).*\1$/.test(value)) value = value.slice(1, -1);
    if (!KNOWN_KEYS.has(key)) problems.push(`Unknown front matter key: ${key}`);
    else if (fields.has(key)) problems.push(`Front matter key repeated: ${key}`);
    else fields.set(key, value);
  }
  const name = fields.get('name') ?? '';
  const description = fields.get('description') ?? '';
  const body = (match[2] ?? '').trim();
  if (!ROLE_NAME.test(name)) problems.push('name must be 1 to 40 lowercase letters, digits or hyphens, starting with a letter.');
  if (description === '' || description.length > ROLE_DESCRIPTION_MAX) problems.push(`description must be 1 to ${ROLE_DESCRIPTION_MAX} characters.`);
  if (body === '' || body.length > ROLE_BODY_MAX) problems.push(`The body (the role's prompt) must be 1 to ${ROLE_BODY_MAX} characters.`);
  const modeText = fields.get('mode') ?? 'read-only';
  if (!(MODES as readonly string[]).includes(modeText)) problems.push(`mode must be one of: ${MODES.join(', ')}.`);
  const toolsText = (fields.get('tools') ?? '').replace(/^\[|\]$/g, '').trim();
  const tools = toolsText === '' || toolsText === '*' ? null : toolsText.split(',').map((tool) => tool.trim()).filter(Boolean);
  if (tools?.some((tool) => !/^[a-z][a-z0-9_]{0,63}$/.test(tool)) === true) problems.push('tools must be a comma-separated list of tool names.');
  const model = fields.get('model') ?? 'main';
  if (!/^[A-Za-z0-9._:/-]{1,100}$/.test(model)) problems.push('model must be main, cheap, or a model name.');
  if (problems.length > 0) return { role: null, problems };
  return { role: { name, description, tools, model, mode: modeText as Mode, body }, problems };
}

async function listRoleFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
  return entries.filter((entry) => entry.isFile() && !entry.isSymbolicLink() && entry.name.endsWith('.md') && !entry.name.startsWith('.')).map((entry) => entry.name);
}

/**
 * Roles from the user's and the project's agents folders, after the built-in crew. A role's body sits in a child's
 * system prompt for its whole life, so it gets the strict scan. The built-in crew cannot be replaced,
 * and a project role is offered on a card first; without a person it stays out.
 */
export async function loadRoles(options: RoleRoots): Promise<RoleSet> {
  const list = options.list ?? listRoleFiles;
  const notices: RoleNotice[] = [];
  const pending: Quarantined[] = [];
  const roles = new Map<string, Role>(BUILT_IN_ROLES.map((role) => [role.name, role]));
  const sources: [scope: 'user' | 'project', base: string | null, root: string | null][] = [
    ['user', options.user, options.user],
    ['project', options.project, options.projectRoot],
  ];
  for (const [scope, base, root] of sources) {
    if (base === null || root === null) continue;
    for (const file of (await list(base)).sort()) {
      const display = `${scope}/${file}`;
      const note = (message: string): void => {
        notices.push({ file: display, message });
      };
      const path = join(base, file);
      const read = await options.reader.read(root, path, ROLE_FILE_MAX);
      if (read.kind === 'absent') continue;
      if (read.kind === 'refused') {
        note(`not loaded (${read.reason})`);
        continue;
      }
      if (read.bytes.length >= ROLE_FILE_MAX) {
        note('not loaded, the file is too large');
        continue;
      }
      if (scope === 'project') {
        const check = options.trust.check(path, read.bytes);
        if (check.state !== 'trusted') {
          pending.push({ path, display, state: check.state, diff: check.diff ?? null, content: read.bytes });
          note('not loaded until you approve it');
          continue;
        }
      }
      const parsed = parseRole(read.bytes.toString('utf8'));
      if (parsed.role === null) {
        note(`not loaded: ${parsed.problems.join(' ')}`);
        continue;
      }
      const verdict = await scanThreat([parsed.role.name, parsed.role.description, parsed.role.body], 'strict');
      if (!verdict.clean) {
        note(`blocked by the threat scan (${verdict.reason ?? 'unsafe'})`);
        continue;
      }
      if (roles.has(parsed.role.name)) {
        note(`not loaded, a role named ${parsed.role.name} already exists`);
        continue;
      }
      roles.set(parsed.role.name, { ...parsed.role, scope, hash: createHash('sha256').update(read.bytes).digest('hex') });
    }
  }
  return { roles: [...roles.values()], notices, pending };
}

/** One line per role, for the `subagent` tool's description of who it can start. */
export function rosterText(roles: readonly Role[]): string {
  return roles.map((role) => `${role.name}: ${role.description}`).join('\n');
}
