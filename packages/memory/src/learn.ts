import { mkdir, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { lintSkill, parseSkill } from '@hn/context';
import { scanThreat, type ThreatVerdict } from '@hn/security';
import { readOrNull } from './disk.ts';

/** House standards for a learned skill (10.6). */
export const LEARN = {
  descriptionMax: 60,
  sections: ['When to Use', 'Prerequisites', 'How to Run', 'Quick Reference', 'Procedure', 'Pitfalls', 'Verification'],
  maxFiles: 8,
  maxFileChars: 60_000,
} as const;

export type LearnSource = { readonly kind: 'folder' | 'url'; readonly value: string } | { readonly kind: 'conversation' };

/** The prompt `/learn` sends. It is a prompt, not an engine: the model reads the source with its own tools. */
export function learnPrompt(source: LearnSource): string {
  const what =
    source.kind === 'conversation' ? 'this conversation so far'
    : source.kind === 'folder' ? `the folder ${source.value} (read it with list_files and read_file first)`
    : `the page ${source.value} (fetch it with web_fetch first)`;
  return [
    `Write a skill from ${what}. This request comes from /learn, run by the user.`,
    '',
    'House standards:',
    '- Front matter between --- lines with name (lowercase letters, digits and hyphens) and description (at most 60 characters, saying when to use it).',
    `- Body sections, as "## " headings, in exactly this order: ${LEARN.sections.join(', ')}.`,
    '- Never invent a flag, option or command. Use only what the source shows.',
    '- For a large source, keep SKILL.md lean and put detail in references/<name>.md files linked straight from SKILL.md. A reference file links to nothing else.',
    '',
    'Reply with the files only, each written as:',
    '<<<FILE SKILL.md>>>',
    '(file text)',
    '<<<END FILE>>>',
  ].join('\n');
}

/** The files in a reply, by path. Only SKILL.md and `references/<name>.md` are accepted. */
export function parseLearnReply(reply: string): Map<string, string> | string {
  const files = new Map<string, string>();
  for (const found of reply.matchAll(/<<<FILE ([^>\n]+)>>>\r?\n([\s\S]*?)\r?\n<<<END FILE>>>/g)) {
    const path = (found[1] ?? '').trim();
    if (path !== 'SKILL.md' && !/^references\/[a-z0-9][a-z0-9._-]*\.md$/.test(path)) return `The reply names a file hn will not write: ${path.slice(0, 80)}`;
    if (files.has(path)) return `The reply has ${path} twice.`;
    files.set(path, found[2] ?? '');
  }
  if (!files.has('SKILL.md')) return 'The reply has no SKILL.md written as <<<FILE SKILL.md>>> ... <<<END FILE>>>.';
  if (files.size > LEARN.maxFiles) return `The reply has ${files.size} files; at most ${LEARN.maxFiles}.`;
  for (const [path, text] of files) if (text.length > LEARN.maxFileChars) return `${path} is too long.`;
  return files;
}

/** Long flags (`--name`) in a text. Short flags are too easy to confuse with prose, list markers and ranges. */
export function flagsIn(text: string): string[] {
  return [...new Set([...text.matchAll(/(?<![\w-])--[a-zA-Z][\w-]*/g)].map((found) => found[0]))];
}

export interface LearnCheck {
  readonly name: string | null;
  readonly errors: readonly string[];
  /** The files to write, with `created_by: agent` added to SKILL.md. */
  readonly files: ReadonlyMap<string, string>;
}

/**
 * Everything a learned skill must pass before it is even quarantined: the Phase 3 linter, the house
 * standards, no flag the source does not show, and the strict scan.
 */
export async function checkLearned(files: ReadonlyMap<string, string>, sourceText: string, scan?: (texts: readonly string[]) => Promise<ThreatVerdict>): Promise<LearnCheck> {
  const skill = files.get('SKILL.md') ?? '';
  const parsed = parseSkill(skill);
  const errors: string[] = [];
  const name = parsed.meta?.name ?? null;
  if (parsed.meta === null) return { name: null, errors: [...parsed.problems], files };
  if (parsed.meta.createdBy !== null) errors.push('SKILL.md sets created_by itself; hn sets it.');
  if (parsed.meta.description.length > LEARN.descriptionMax) errors.push(`The description is ${parsed.meta.description.length} characters; house standard is at most ${LEARN.descriptionMax}.`);
  const headings = [...parsed.body.matchAll(/^##\s+(.+?)\s*$/gm)].map((found) => found[1] ?? '');
  const order = LEARN.sections.map((section) => headings.indexOf(section));
  const missing = LEARN.sections.filter((_, i) => order[i] === -1);
  if (missing.length > 0) errors.push(`Missing sections: ${missing.join(', ')}.`);
  else if (order.some((position, i) => i > 0 && position < (order[i - 1] as number))) errors.push(`The sections are out of order; the order is ${LEARN.sections.join(', ')}.`);
  const lint = await lintSkill(name ?? '', skill, async (relative) => files.get(relative.replace(/\\/g, '/')) ?? null);
  errors.push(...lint.errors);
  const invented = [...files.values()].flatMap(flagsIn).filter((flag) => !sourceText.includes(flag));
  if (invented.length > 0) errors.push(`It uses flags the source never shows: ${[...new Set(invented)].join(', ')}.`);
  const verdict = await (scan ?? ((texts) => scanThreat(texts, 'strict')))([...files.values()]);
  if (!verdict.clean) errors.push(`It did not pass the strict scan: ${verdict.findings.map((finding) => finding.label).join('; ') || verdict.reason}.`);
  const stamped = new Map(files);
  stamped.set('SKILL.md', skill.replace(/^---\r?\n/, '---\ncreated_by: agent\n'));
  return { name, errors, files: stamped };
}

const quarantineDir = (skillsRoot: string): string => join(skillsRoot, '.quarantine');

/** Writes a checked skill where nothing loads it. Refuses a name already learned or in use. */
export async function quarantineSkill(skillsRoot: string, name: string, files: ReadonlyMap<string, string>): Promise<string> {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) throw new Error('The skill name is not valid.');
  if ((await readOrNull(join(skillsRoot, name, 'SKILL.md'))) !== null) throw new Error(`A skill named ${name} already exists.`);
  const folder = join(quarantineDir(skillsRoot), name);
  await rm(folder, { recursive: true, force: true });
  for (const [path, text] of files) {
    const target = join(folder, path);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, text, { mode: 0o600, flag: 'wx' });
  }
  return folder;
}

export async function listQuarantined(skillsRoot: string): Promise<string[]> {
  return (await readdir(quarantineDir(skillsRoot), { withFileTypes: true }).catch(() => [])).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
}

/** A person said yes: the skill moves into the user's skills folder, where it loads from the next session. */
export async function approveLearned(skillsRoot: string, name: string): Promise<void> {
  if (!(await listQuarantined(skillsRoot)).includes(name)) throw new Error(`No learned skill named ${name} is waiting.`);
  if ((await readOrNull(join(skillsRoot, name, 'SKILL.md'))) !== null) throw new Error(`A skill named ${name} already exists.`);
  await rename(join(quarantineDir(skillsRoot), name), join(skillsRoot, name));
}

export async function discardLearned(skillsRoot: string, name: string): Promise<void> {
  if (!(await listQuarantined(skillsRoot)).includes(name)) throw new Error(`No learned skill named ${name} is waiting.`);
  await rm(join(quarantineDir(skillsRoot), name), { recursive: true, force: true });
}
