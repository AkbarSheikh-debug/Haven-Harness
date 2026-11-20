// Writes the public attack catalog (docs/guide/attacks.md) from the attack registry and the test files, or checks that
// the committed page is exactly what they say. A developer tool, not part of hn. No dependencies.
//
//   node --disable-proto=throw scripts/attack-catalog.ts            # rewrite the page
//   node --disable-proto=throw scripts/attack-catalog.ts --check    # exit 1 if the page is stale, or the registry and the tests disagree
//
// Every registry name must have a test whose title carries it; the page links that test's file. A test titled
// `attack: <name>` for a name that is not in the registry is an error too, so an attack cannot be tested and left off the
// public list, or listed with no test.

import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AREAS, ATTACKS, type Attack } from '../packages/testkit/src/attack-registry.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const PAGE = join(ROOT, 'docs', 'guide', 'attacks.md');
const TITLE = /(?:^|\s)(?:it|describe|test)\(\s*(['"`])((?:\\.|(?!\1).)*)\1/;

export interface TestTitle {
  readonly file: string;
  readonly title: string;
}

/** Every test title in `packages/<name>/test/*.test.ts`, with the file it is in (a repository path, forward slashes). */
export function testTitles(root: string = ROOT): TestTitle[] {
  const found: TestTitle[] = [];
  for (const pkg of readdirSync(join(root, 'packages')).sort()) {
    let files: string[];
    try {
      files = readdirSync(join(root, 'packages', pkg, 'test')).filter((file) => file.endsWith('.test.ts')).sort();
    } catch {
      continue;
    }
    for (const file of files) {
      for (const line of readFileSync(join(root, 'packages', pkg, 'test', file), 'utf8').split('\n')) {
        const match = TITLE.exec(line);
        if (match !== null) found.push({ file: `packages/${pkg}/test/${file}`, title: (match[2] as string).replace(/\\(.)/g, '$1') });
      }
    }
  }
  return found;
}

const NAME = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;

/** The names a title claims: `attack: a b c - words` claims a, b and c; `name: words` claims name. */
export function namesIn(title: string): string[] {
  const body = title.startsWith('attack: ') ? title.slice('attack: '.length) : title;
  const names: string[] = [];
  for (const word of body.split(/\s+/)) {
    const bare = word.replace(/[.:,;]+$/, '');
    if (!NAME.test(bare)) break;
    names.push(bare);
    if (bare !== word) break;
  }
  return title.startsWith('attack: ') || names.length > 0 ? names : [];
}

export interface Problems {
  readonly untested: string[];
  readonly unregistered: string[];
  readonly duplicates: string[];
  readonly badArea: string[];
  readonly noDescription: string[];
}

/** Where each registry name is tested, and what disagrees. */
export function reconcile(titles: readonly TestTitle[], attacks: readonly Attack[] = ATTACKS): { files: Map<string, string>; problems: Problems } {
  const files = new Map<string, string>();
  const claimed = new Set<string>();
  for (const { file, title } of titles) {
    for (const name of namesIn(title)) {
      claimed.add(name);
      if (!files.has(name)) files.set(name, file);
    }
  }
  const seen = new Set<string>();
  const duplicates: string[] = [];
  for (const entry of attacks) {
    if (seen.has(entry.name)) duplicates.push(entry.name);
    seen.add(entry.name);
  }
  const registered = new Set(attacks.map((entry) => entry.name));
  const attackTitled = new Set(titles.filter(({ title }) => title.startsWith('attack: ')).flatMap(({ title }) => namesIn(title)));
  return {
    files,
    problems: {
      untested: attacks.filter((entry) => !claimed.has(entry.name)).map((entry) => entry.name),
      unregistered: [...attackTitled].filter((name) => !registered.has(name)).sort(),
      duplicates,
      badArea: attacks.filter((entry) => !(AREAS as readonly string[]).includes(entry.area)).map((entry) => entry.name),
      noDescription: attacks.filter((entry) => entry.description.trim().length < 20 || !entry.description.trim().endsWith('.')).map((entry) => entry.name),
    },
  };
}

export const hasProblems = (problems: Problems): boolean => Object.values(problems).some((list) => list.length > 0);

const cell = (text: string): string => text.replace(/\|/g, '\\|');

/** The page, as it must be committed. */
export function renderCatalog(files: ReadonlyMap<string, string>, attacks: readonly Attack[] = ATTACKS): string {
  const lines: string[] = [
    '# The attack catalog',
    '',
    `${attacks.length} named attacks, in ${AREAS.length} areas. Each one is a test in this repository, titled with its name. **A pass means the effect did not happen**, judged on the far side (a canary file that was never written, a listener that saw no connection, a remote repository with no new ref, a chain that verifies), never by the model's or the system's own words. A test suite with a red attack does not ship.`,
    '',
    'This page is written by a script from the attack registry and the test files. If you add an attack, add it to the registry; if a test and the registry disagree, or this page is not what the script writes, the build fails. To check an entry yourself, open its test file and search for the name.',
    '',
    'Found a way past one of these, or past something that is not listed? See the [security policy](../../SECURITY.md); people who report real holes are credited in the [hall of fame](hall-of-fame.md).',
    '',
  ];
  for (const area of AREAS) {
    const rows = attacks.filter((entry) => entry.area === area).sort((a, b) => a.name.localeCompare(b.name));
    if (rows.length === 0) continue;
    lines.push(`## ${area}`, '', '| Attack | What is tried, and what must not happen | Test |', '| --- | --- | --- |');
    for (const row of rows) {
      const file = files.get(row.name);
      lines.push(`| \`${row.name}\` | ${cell(row.description)} | ${file === undefined ? 'MISSING' : `[${file}](../../${file})`} |`);
    }
    lines.push('');
  }
  return `${lines.join('\n').trimEnd()}\n`;
}

/** What `docs/guide/attacks.md` must contain, or the problems that stop it being written. */
export function expectedPage(root: string = ROOT): { page: string; problems: Problems } {
  const { files, problems } = reconcile(testTitles(root));
  return { page: renderCatalog(files), problems };
}

function describeProblems(problems: Problems): string[] {
  const out: string[] = [];
  if (problems.untested.length > 0) out.push(`In the registry with no test titled with the name: ${problems.untested.join(', ')}`);
  if (problems.unregistered.length > 0) out.push(`Tests titled "attack: ..." for names not in the registry: ${problems.unregistered.join(', ')}`);
  if (problems.duplicates.length > 0) out.push(`Listed twice in the registry: ${problems.duplicates.join(', ')}`);
  if (problems.badArea.length > 0) out.push(`With an area that is not in AREAS: ${problems.badArea.join(', ')}`);
  if (problems.noDescription.length > 0) out.push(`With a missing or unfinished description: ${problems.noDescription.join(', ')}`);
  return out;
}

if (import.meta.main) {
  const check = process.argv.includes('--check');
  const { page, problems } = expectedPage();
  if (hasProblems(problems)) {
    for (const line of describeProblems(problems)) process.stderr.write(`${line}\n`);
    process.exit(1);
  }
  if (check) {
    if (readFileSync(PAGE, 'utf8').replace(/\r\n/g, '\n') !== page) {
      process.stderr.write('docs/guide/attacks.md is not what the registry and tests say. Run: node --disable-proto=throw scripts/attack-catalog.ts\n');
      process.exit(1);
    }
    process.stdout.write(`The attack catalog is current (${ATTACKS.length} attacks).\n`);
  } else {
    writeFileSync(PAGE, page);
    process.stdout.write(`Wrote docs/guide/attacks.md (${ATTACKS.length} attacks).\n`);
  }
}
