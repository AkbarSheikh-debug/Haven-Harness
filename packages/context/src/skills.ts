import { createHash } from 'node:crypto';
import { readdir } from 'node:fs/promises';
import { isAbsolute, join, normalize, sep } from 'node:path';
import { scanThreat } from '@hn/security';
import type { InstructionReader, InstructionTrust, Quarantined } from './instructions.ts';

export const SKILL_NAME_MAX = 64;
export const SKILL_DESCRIPTION_MAX = 1_024;
export const SKILL_BODY_MAX_LINES = 500;
/** The catalogue in the prompt is capped; past this, skills are counted rather than listed. */
export const CATALOGUE_MAX_CHARS = 8_000;
const SKILL_FILE_MAX = 256 * 1024;
const NAME = /^[a-z0-9][a-z0-9-]*$/;
/** `created_by`, `pinned` and `locked` are for the curator: only `created_by: agent` skills are ever moved. */
const KNOWN_KEYS = new Set(['name', 'description', 'validate', 'created_by', 'pinned', 'locked']);
/** Markdown links and images. The target is checked afterwards for being a local path. */
const LINK = /!?\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g;

export interface SkillMeta {
  readonly name: string;
  readonly description: string;
  readonly validate: string | null;
  readonly createdBy: string | null;
  readonly pinned: boolean;
  readonly locked: boolean;
}

export interface ParsedSkill {
  readonly meta: SkillMeta | null;
  readonly body: string;
  readonly problems: readonly string[];
}

/**
 * A tiny front-matter reader: `key: value` lines between `---` fences, values optionally quoted.
 * No YAML library, so no anchors, aliases, tags or merge keys can reach the harness.
 */
export function parseSkill(text: string): ParsedSkill {
  const problems: string[] = [];
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(text);
  if (match === null) return { meta: null, body: text, problems: ['SKILL.md has no front matter between --- lines.'] };
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
  const validate = fields.get('validate') ?? '';
  const flag = (key: string): boolean => (fields.get(key) ?? '').toLowerCase() === 'true';
  const meta = {
    name: fields.get('name') ?? '',
    description: fields.get('description') ?? '',
    validate: validate === '' ? null : validate,
    createdBy: fields.get('created_by') ?? null,
    pinned: flag('pinned'),
    locked: flag('locked'),
  };
  return { meta, body: match[2] ?? '', problems };
}

/** Local link targets in markdown, relative to the file. URLs, mail links and anchors are not files. */
export function localLinks(markdown: string): string[] {
  const targets: string[] = [];
  for (const found of markdown.matchAll(LINK)) {
    const target = (found[1] ?? '').split('#')[0] ?? '';
    if (target === '' || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
    try {
      targets.push(decodeURIComponent(target));
    } catch {
      targets.push(target);
    }
  }
  return targets;
}

/** The items of a checklist body: `- [ ] step` lines. A body with any is a checklist that feeds `todo_write`. */
export function checklistItems(body: string): string[] {
  return [...body.matchAll(/^\s*[-*]\s+\[[ xX]\]\s+(.+)$/gm)].map((found) => (found[1] ?? '').trim());
}

/** A file reader for one skill folder: returns null for a missing or refused file. */
export type SkillFileReader = (relativePath: string) => Promise<string | null>;

export interface LintReport {
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
}

/** A link target inside the skill folder, or a reason it is not one. */
export function insideSkill(target: string): string | { problem: string } {
  if (isAbsolute(target) || /^[a-z]:/i.test(target) || target.startsWith('/') || target.startsWith('\\')) {
    return { problem: `links to an absolute path: ${target}` };
  }
  const clean = normalize(target);
  if (clean.split(/[\\/]/).includes('..')) return { problem: `links outside the skill folder: ${target}` };
  return clean;
}

function lintMeta(folderName: string, meta: SkillMeta, body: string, errors: string[], warnings: string[]): void {
  const { name, description, validate } = meta;
  if (name === '') errors.push('The name is missing.');
  else if (name.length > SKILL_NAME_MAX) errors.push(`The name is ${name.length} characters; the limit is ${SKILL_NAME_MAX}.`);
  else if (!NAME.test(name)) errors.push('The name may use only lowercase letters, digits and hyphens.');
  if (name !== '' && name !== folderName) warnings.push(`The name "${name}" differs from its folder "${folderName}".`);
  if (description === '') errors.push('The description is missing; it is the only reason the skill gets used.');
  if (description.length > SKILL_DESCRIPTION_MAX) {
    errors.push(`The description is ${description.length} characters; the limit is ${SKILL_DESCRIPTION_MAX}.`);
  }
  if (validate !== null && /[\r\n]/.test(validate)) errors.push('validate: must be one command on one line.');
  const lines = body.split('\n').length;
  if (lines >= SKILL_BODY_MAX_LINES) {
    errors.push(`The body is ${lines} lines; keep it under ${SKILL_BODY_MAX_LINES} and move detail to bundled files.`);
  }
}

/**
 * A skill is three levels. Name and description (64 and 1,024 characters), a body
 * under 500 lines, and bundled files linked straight from SKILL.md. A bundled file that links on to another
 * local file is two levels down, and that is an error.
 */
export async function lintSkill(folderName: string, text: string, read: SkillFileReader): Promise<LintReport> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const parsed = parseSkill(text);
  if (parsed.meta === null) return { errors: [...parsed.problems], warnings };
  for (const problem of parsed.problems) (problem.startsWith('Unknown') ? warnings : errors).push(problem);
  lintMeta(folderName, parsed.meta, parsed.body, errors, warnings);
  for (const target of new Set(localLinks(parsed.body))) {
    const inside = insideSkill(target);
    if (typeof inside !== 'string') {
      errors.push(`SKILL.md ${inside.problem}`);
      continue;
    }
    const linked = await read(inside);
    if (linked === null) {
      errors.push(`SKILL.md links to a missing file: ${target}`);
      continue;
    }
    for (const deeper of localLinks(linked)) {
      errors.push(`${target} links further down to ${deeper}. Link every reference straight from SKILL.md.`);
    }
  }
  return { errors, warnings };
}

export interface Skill {
  readonly name: string;
  readonly description: string;
  readonly validate: string | null;
  readonly folder: string;
  /** The root the safe reader must stay inside when reading this skill's files. */
  readonly root: string;
  readonly path: string;
  readonly scope: 'user' | 'project';
  /** SHA-256 of SKILL.md, so an approval of its `validate:` command dies when the file changes. */
  readonly hash: string;
  readonly body: string;
  readonly checklist: readonly string[];
}

export interface SkillNotice {
  readonly folder: string;
  readonly message: string;
}

export interface SkillSet {
  readonly skills: readonly Skill[];
  readonly notices: readonly SkillNotice[];
  /** Project SKILL.md files nobody approved yet, for the same card instruction files use. */
  readonly pending: readonly Quarantined[];
}

export interface SkillRoots {
  /** `~/.hn/skills`: the user's own, loaded without approval. */
  readonly user: string | null;
  /** `<project>/.hn/skills`: loaded only when SKILL.md's exact content is approved. */
  readonly project: string | null;
  /** The jail root for project skills. */
  readonly projectRoot: string | null;
  readonly reader: InstructionReader;
  readonly trust: InstructionTrust;
  /** Folder names under a skills root. Default: the real directory listing, links skipped. */
  readonly list?: (directory: string) => Promise<string[]>;
}

async function listFolders(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
  // Dot folders (`.quarantine`, `.archive`) hold skills that are not in use.
  return entries.filter((entry) => entry.isDirectory() && !entry.isSymbolicLink() && !entry.name.startsWith('.')).map((entry) => entry.name);
}

/** Reads a file of a skill through the safe reader, as text, or null. */
export function skillFileReader(reader: InstructionReader, root: string, folder: string): SkillFileReader {
  return async (relativePath) => {
    const inside = insideSkill(relativePath);
    if (typeof inside !== 'string') return null;
    const result = await reader.read(root, join(folder, inside), SKILL_FILE_MAX);
    return result.kind === 'ok' && result.bytes.length < SKILL_FILE_MAX ? result.bytes.toString('utf8') : null;
  };
}

interface LoadPlace {
  readonly scope: 'user' | 'project';
  readonly root: string;
  readonly folder: string;
  readonly display: string;
}

async function loadOne(
  options: SkillRoots,
  place: LoadPlace,
  notices: SkillNotice[],
  pending: Quarantined[],
): Promise<Skill | null> {
  const note = (message: string): null => {
    notices.push({ folder: place.display, message });
    return null;
  };
  const path = join(place.folder, 'SKILL.md');
  const result = await options.reader.read(place.root, path, SKILL_FILE_MAX);
  if (result.kind === 'absent') return null;
  if (result.kind === 'refused') return note(`not loaded (${result.reason})`);
  if (result.bytes.length >= SKILL_FILE_MAX) return note('not loaded, SKILL.md is too large');
  if (place.scope === 'project') {
    const check = options.trust.check(path, result.bytes);
    if (check.state !== 'trusted') {
      const display = `${place.display}/SKILL.md`;
      pending.push({ path, display, state: check.state, diff: check.diff ?? null, content: result.bytes });
      return note('not loaded until you approve its SKILL.md');
    }
  }
  const text = result.bytes.toString('utf8');
  const folderName = place.folder.split(sep).at(-1) ?? '';
  const lint = await lintSkill(folderName, text, skillFileReader(options.reader, place.root, place.folder));
  if (lint.errors.length > 0) return note(`not loaded, it fails the skill linter: ${lint.errors.join(' ')}`);
  const parsed = parseSkill(text);
  const meta = parsed.meta as SkillMeta;
  const verdict = await scanThreat([meta.name, meta.description, parsed.body], 'context');
  if (!verdict.clean) return note(`blocked by the threat scan (${verdict.reason ?? 'unsafe'})`);
  const hash = createHash('sha256').update(result.bytes).digest('hex');
  const { root, folder, scope } = place;
  return { ...meta, folder, root, path, scope, hash, body: parsed.body, checklist: checklistItems(parsed.body) };
}

/**
 * Every skill under the user's and the project's skills folders. When two share a name the user's wins,
 * because the project is the less trusted side.
 */
export async function loadSkills(options: SkillRoots): Promise<SkillSet> {
  const list = options.list ?? listFolders;
  const notices: SkillNotice[] = [];
  const pending: Quarantined[] = [];
  const skills = new Map<string, Skill>();
  const sources: [scope: 'user' | 'project', base: string | null, root: string | null][] = [
    ['user', options.user, options.user],
    ['project', options.project, options.projectRoot],
  ];
  for (const [scope, base, root] of sources) {
    if (base === null || root === null) continue;
    for (const name of (await list(base)).sort()) {
      const place = { scope, root, folder: join(base, name), display: `${scope}/${name}` };
      const skill = await loadOne(options, place, notices, pending);
      if (skill === null) continue;
      if (skills.has(skill.name)) notices.push({ folder: place.display, message: `not loaded, a skill named ${skill.name} is already loaded` });
      else skills.set(skill.name, skill);
    }
  }
  return { skills: [...skills.values()], notices, pending };
}

const escape = (text: string): string => text.replace(/<\/(system-reminder|skills)/gi, '<\\/$1');

/** The catalogue row: names and descriptions only (level 1), capped, inside a frame a description cannot close. */
export function catalogueText(set: SkillSet): string {
  const lines: string[] = [];
  let used = 0;
  let left = 0;
  for (const skill of set.skills) {
    const line = escape(`- ${skill.name}: ${skill.description.replace(/\s+/g, ' ')}`);
    if (used + line.length > CATALOGUE_MAX_CHARS) {
      left += 1;
      continue;
    }
    lines.push(line);
    used += line.length + 1;
  }
  const notices = set.notices.map((notice) => escape(`- ${notice.folder}: ${notice.message}`));
  return [
    '<system-reminder>',
    set.skills.length === 0
      ? 'No skills are available.'
      : 'Skills available. Load one with call_tool({"name":"skill","args":{"name":"<skill>"}}) when its description fits the task.',
    ...lines,
    ...(left === 0 ? [] : [`(${left} more skills are not listed, to keep this short.)`]),
    ...(notices.length === 0 ? [] : ['Skill notices:', ...notices]),
    '</system-reminder>',
  ].join('\n');
}
