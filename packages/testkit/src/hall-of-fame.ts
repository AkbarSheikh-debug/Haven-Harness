// The logic behind scripts/hall-of-fame.ts, kept here so tests can use it (the package build compiles tests and may not reach into scripts/).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATTACKS } from './attack-registry.ts';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
export const CREDITS_DATA = join(ROOT, 'docs', 'security', 'credits.json');
export const HALL_PAGE = join(ROOT, 'docs', 'guide', 'hall-of-fame.md');

export const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface Credit {
  /** A GitHub login. The page links to it. */
  readonly handle?: string;
  /** A name to show instead of, or beside, the handle. */
  readonly name?: string;
  readonly reported: string;
  readonly fixed: string;
  readonly severity: Severity;
  /** One plain sentence: what the hole was. No markup. */
  readonly summary: string;
  /** The full commit that fixed it. */
  readonly fix: string;
  /** The registry name of the attack test that now guards against it. */
  readonly attack: string;
  /** The reporter agreed to be listed. Anything but `true` is refused. */
  readonly consent: true;
  /** A published advisory, when there is one. */
  readonly advisory?: string;
}

const KEYS: ReadonlySet<string> = new Set(['handle', 'name', 'reported', 'fixed', 'severity', 'summary', 'fix', 'attack', 'consent', 'advisory']);
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const EMAILISH = /[^\s@]+@[^\s@]+\.[^\s@]+/;
// Control characters, and the characters that reverse or hide text, so a name cannot make the page read differently.
// eslint-disable-next-line no-control-regex
const HIDDEN = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/;
const MARKUP = /[<>[\]`|\\]/;
const ADVISORY = /^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9._-]+\/security\/advisories\/GHSA(?:-[a-z0-9]{4}){3}$/;

function realDay(value: string): number | null {
  if (!DAY.test(value)) return null;
  const time = Date.parse(`${value}T00:00:00Z`);
  return Number.isNaN(time) || new Date(time).toISOString().slice(0, 10) !== value ? null : time;
}

/** Everything wrong with the data, one line each. Empty means it can be published. */
export function validateCredits(data: unknown, options: { today?: string; attackNames?: readonly string[] } = {}): string[] {
  const errors: string[] = [];
  const today = options.today ?? new Date().toISOString().slice(0, 10);
  const known = new Set(options.attackNames ?? ATTACKS.map((attack) => attack.name));
  if (typeof data !== 'object' || data === null || Array.isArray(data) || Object.keys(data).some((key) => key !== 'credits')) return ['The file must be an object with one key, "credits".'];
  const list = (data as { credits?: unknown }).credits;
  if (!Array.isArray(list)) return ['"credits" must be a list.'];
  const fixes = new Set<string>();
  list.forEach((raw: unknown, index: number) => {
    const at = `credits[${index}]`;
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      errors.push(`${at}: must be an object.`);
      return;
    }
    const item = raw as Record<string, unknown>;
    for (const key of Object.keys(item)) if (!KEYS.has(key)) errors.push(`${at}: "${key}" is not a field this page takes (contact details are never kept here).`);
    if (item['consent'] !== true) errors.push(`${at}: consent must be true. Nobody is listed without agreeing to it.`);
    const handle = item['handle'];
    const name = item['name'];
    if (handle === undefined && name === undefined) errors.push(`${at}: needs a handle or a name.`);
    if (handle !== undefined && (typeof handle !== 'string' || !LOGIN.test(handle))) errors.push(`${at}: handle must be a GitHub login.`);
    if (name !== undefined && (typeof name !== 'string' || name.trim() === '' || name.length > 60 || HIDDEN.test(name) || MARKUP.test(name) || EMAILISH.test(name) || /https?:|www\./i.test(name))) {
      errors.push(`${at}: name must be 1 to 60 plain characters, with no markup, link, email address or hidden character.`);
    }
    const summary = item['summary'];
    if (typeof summary !== 'string' || summary.trim().length < 20 || summary.length > 240 || HIDDEN.test(summary) || MARKUP.test(summary) || /https?:|www\./i.test(summary)) {
      errors.push(`${at}: summary must be 20 to 240 plain characters, with no markup or link.`);
    } else if (EMAILISH.test(summary)) errors.push(`${at}: summary must not contain an email address.`);
    if (!(SEVERITIES as readonly unknown[]).includes(item['severity'])) errors.push(`${at}: severity must be one of ${SEVERITIES.join(', ')}.`);
    const reported = typeof item['reported'] === 'string' ? realDay(item['reported']) : null;
    const fixed = typeof item['fixed'] === 'string' ? realDay(item['fixed']) : null;
    if (reported === null) errors.push(`${at}: reported must be a real date, YYYY-MM-DD.`);
    if (fixed === null) errors.push(`${at}: fixed must be a real date, YYYY-MM-DD.`);
    if (reported !== null && fixed !== null && fixed < reported) errors.push(`${at}: fixed is before reported.`);
    if (typeof item['fixed'] === 'string' && item['fixed'] > today) errors.push(`${at}: fixed is in the future.`);
    const fix = item['fix'];
    if (typeof fix !== 'string' || !/^[0-9a-f]{40}$/.test(fix)) errors.push(`${at}: fix must be the full 40-character commit.`);
    else if (fixes.has(fix)) errors.push(`${at}: the commit ${fix.slice(0, 7)} is already credited.`);
    else fixes.add(fix);
    const attack = item['attack'];
    if (typeof attack !== 'string' || !known.has(attack)) errors.push(`${at}: attack must name an attack in the registry, so the hole stays closed by a test.`);
    const advisory = item['advisory'];
    if (advisory !== undefined && (typeof advisory !== 'string' || !ADVISORY.test(advisory))) errors.push(`${at}: advisory must be a GitHub security advisory address.`);
  });
  return errors;
}

const SEVERITY_TEXT: Readonly<Record<Severity, string>> = {
  critical: 'a way past the sandbox or the gate with no help from the user',
  high: 'a way past a boundary hn claims, with a normal setup',
  medium: 'a way past a boundary that needs an unusual setup or a lucky moment',
  low: 'a weakness that gives an attacker little, or a claim that was stated too strongly',
};

const cell = (text: string): string => text.replace(/\|/g, '\\|');

function who(credit: Credit): string {
  const handle = credit.handle === undefined ? null : `[${credit.handle}](https://github.com/${credit.handle})`;
  if (credit.name === undefined) return handle ?? '';
  return handle === null ? cell(credit.name) : `${cell(credit.name)} (${handle})`;
}

/** The page, as it must be committed. */
export function renderHallOfFame(credits: readonly Credit[]): string {
  const sorted = [...credits].sort((a, b) => (a.fixed === b.fixed ? a.fix.localeCompare(b.fix) : b.fixed.localeCompare(a.fixed)));
  const lines: string[] = [
    '# Hall of fame',
    '',
    'These are the people who found a real hole in Haven Harness and told us privately, so it could be fixed before anyone else could use it. Thank you.',
    '',
    'An entry is here only if the reporter agreed to be named, and every entry names the attack in the [attack catalog](attacks.md) that now guards against what they found, so a hole that was reported once is held shut by a test. This page is written by a script from `docs/security/credits.json`; the build fails if the two disagree.',
    '',
    '## How to get on it',
    '',
    'Report a vulnerability the way the [security policy](../../SECURITY.md) describes: privately, through the repository\'s Security tab. If it is real, we will fix it, add a test for it to the attack catalog, and ask whether you want to be listed and how. You can be credited by a GitHub name, by a name you choose, or not at all. Nothing is published without your yes, and no email address is ever kept here.',
    '',
    '## Credits',
    '',
  ];
  if (sorted.length === 0) {
    lines.push('No report has been credited yet, so this list is empty. It will not be filled with anyone who did not report something real.', '');
  } else {
    lines.push('| Who | Fixed | Severity | What it was | Test |', '| --- | --- | --- | --- | --- |');
    for (const credit of sorted) {
      const fixLink = `[${credit.fix.slice(0, 7)}](https://github.com/AkbarSheikh-debug/Haven-Harness/commit/${credit.fix})`;
      const advisory = credit.advisory === undefined ? '' : ` ([advisory](${credit.advisory}))`;
      lines.push(`| ${who(credit)} | ${credit.fixed} | ${credit.severity} | ${cell(credit.summary)} (fix ${fixLink})${advisory} | \`${credit.attack}\` |`);
    }
    lines.push('');
  }
  lines.push('## What the severities mean', '');
  for (const severity of [...SEVERITIES].reverse()) lines.push(`- **${severity}:** ${SEVERITY_TEXT[severity]}.`);
  lines.push('');
  return lines.join('\n');
}

export function loadCredits(path: string = CREDITS_DATA): { credits: Credit[]; errors: string[] } {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    return { credits: [], errors: [`docs/security/credits.json cannot be read as JSON: ${error instanceof Error ? error.message : 'unknown error'}`] };
  }
  const errors = validateCredits(data);
  return { credits: errors.length === 0 ? (data as { credits: Credit[] }).credits : [], errors };
}

/** What `docs/guide/hall-of-fame.md` must contain, or why it cannot be written. */
export function expectedHallOfFame(path: string = CREDITS_DATA): { page: string; errors: string[] } {
  const { credits, errors } = loadCredits(path);
  return { page: renderHallOfFame(credits), errors };
}
