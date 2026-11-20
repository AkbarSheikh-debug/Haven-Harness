// Breaks the attack registry, the hall of fame and the replay screen on purpose, one way at a time, and checks that a test
// notices each break. A mutant that survives is a hole in the tests, not in this script. A developer tool; it edits files in
// the working copy and restores each one, so run it on a clean tree:
//
//   node --disable-proto=throw scripts/trust/mutation-check.ts                 # all of them
//   node --disable-proto=throw scripts/trust/mutation-check.ts --check-only    # only check each target text exists
//   node --disable-proto=throw scripts/trust/mutation-check.ts <part of a name>
//
// The mutants marked `browser` need a real Chrome or Edge (HN_BROWSER names one); without one they are reported as not
// run, never as caught.

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { findBrowser } from '../../packages/surfaces/test/browser-fixture.ts';

interface Mutant {
  readonly name: string;
  readonly file: string;
  readonly find: string;
  readonly replace: string;
  /** The test files that should fail. */
  readonly tests: readonly string[];
  readonly browser?: boolean;
}

const T = {
  replay: 'packages/surfaces/test/replay.test.ts',
  serve: 'packages/surfaces/test/replay-serve.test.ts',
  liveServe: 'packages/surfaces/test/serve.test.ts',
  browser: 'packages/surfaces/test/replay-browser.test.ts',
  attacks: 'packages/surfaces/test/attacks.test.ts',
  catalog: 'packages/surfaces/test/attack-catalog.test.ts',
  hall: 'packages/release/test/hall-of-fame.test.ts',
} as const;

const REPLAY = 'packages/surfaces/src/replay.ts';
const CLIENT = 'packages/surfaces/src/replay-client.ts';
const SERVE = 'packages/surfaces/src/serve.ts';
const ROUTES = 'packages/surfaces/src/serve-replay.ts';
const GUARD = 'packages/surfaces/src/serve-guard.ts';
const RENDER = 'packages/surfaces/src/serve-render.ts';
const MAIN = 'packages/surfaces/src/main.ts';
const CATALOG = 'packages/testkit/src/attack-catalog.ts';
const HALL = 'packages/testkit/src/hall-of-fame.ts';

const mutants: Mutant[] = [
  // The replay model.
  { name: 'a log that does not verify is shown anyway', file: REPLAY, find: "if (log.trust !== 'verified' || log.header === null) {", replace: 'if (log.header === null) {', tests: [T.replay, T.serve, T.browser] },
  { name: 'a log with no header is not refused', file: REPLAY, find: "if (log.trust !== 'verified' || log.header === null) {", replace: "if (log.trust !== 'verified') {", tests: [T.replay] },
  { name: 'hidden characters are stripped instead of written out', file: REPLAY, find: 'const revealed = revealHidden(value);', replace: 'const revealed = value;', tests: [T.replay] },
  { name: 'titles keep hidden characters', file: REPLAY, find: "const flat = revealHidden(value).replace(/\\s+/g, ' ').trim();", replace: "const flat = value.replace(/\\s+/g, ' ').trim();", tests: [T.replay] },
  { name: 'text is not capped', file: REPLAY, find: 'export const MAX_DETAIL = 1_500;', replace: 'export const MAX_DETAIL = 1_500_000_000;', tests: [T.replay] },
  { name: 'there is no limit on steps', file: REPLAY, find: 'if (steps.length >= MAX_STEPS) {', replace: 'if (false) {', tests: [T.replay] },
  { name: 'the taint step is not marked when untrusted input enters', file: REPLAY, find: "const first = !state.untrusted && data['untrusted'] === true;", replace: 'const first = false;', tests: [T.replay, T.browser] },
  { name: 'the state after a taint change is not updated', file: REPLAY, find: "state = { ...state, untrusted: data['untrusted'] === true, private: data['private'] === true, external: data['external'] === true };", replace: '', tests: [T.replay, T.browser] },
  { name: 'a refused or failed write counts as a file change', file: REPLAY, find: 'FILE_TOOLS.has(call.name) && !isError && !refusedCalls.has(id)', replace: 'FILE_TOOLS.has(call.name)', tests: [T.replay] },
  { name: 'a gate refusal is shown as an allow', file: REPLAY, find: "push(event, 'gate', 'refused', `Gate REFUSED", replace: "push(event, 'gate', 'ok', `Gate REFUSED", tests: [T.replay, T.browser] },
  { name: 'a denied approval is shown as allowed', file: REPLAY, find: "const denied = data['answer'] === 'deny';", replace: 'const denied = false;', tests: [T.replay, T.browser] },
  { name: 'refusals are not counted', file: REPLAY, find: 'state = { ...state, refused: state.refused + 1 };', replace: '', tests: [T.replay, T.browser] },
  { name: 'a session id is not checked before the log is opened', file: REPLAY, find: "if (!SESSION_ID.test(sessionId)) return { kind: 'missing' };", replace: '', tests: [T.replay] },
  { name: 'a session id may be longer and wider than the pattern', file: REPLAY, find: 'export const SESSION_ID = /^[A-Za-z0-9-]{1,64}$/;', replace: 'export const SESSION_ID = /^.{1,64}$/;', tests: [T.replay, T.serve] },
  { name: 'a log is opened with any key it finds', file: REPLAY, find: 'return { kind: \'replay\', replay: buildReplay(log, sessionId) };', replace: "return { kind: 'replay', replay: buildReplay({ ...log, trust: 'verified' }, sessionId) };", tests: [T.replay, T.serve] },
  // The page.
  { name: 'the page writes log text as HTML', file: CLIENT, find: 'if (text !== undefined) node.textContent = text;', replace: 'if (text !== undefined) node.innerHTML = text;', tests: [T.serve, T.browser], browser: false },
  { name: 'the page writes log text as HTML (a browser sees it)', file: CLIENT, find: 'if (text !== undefined) node.textContent = text;', replace: 'if (text !== undefined) { node.innerHTML = text; }', tests: [T.browser], browser: true },
  { name: 'the page keeps the previous session when a log is refused', file: CLIENT, find: "['summary', 'timeline', 'detail', 'state', 'filters'].forEach(function (name) { clear($(name)); });", replace: '', tests: [T.browser], browser: true },
  { name: 'the stylesheet lets a hidden panel be drawn', file: CLIENT, find: '[hidden]{display:none !important}', replace: '', tests: [T.browser], browser: true },
  { name: 'a refused log still shows its controls', file: CLIENT, find: "      wipe();\n      return;\n    }\n    box.className = 'verified';", replace: "      $('controls').hidden = false;\n      return;\n    }\n    box.className = 'verified';", tests: [T.browser], browser: true },
  { name: 'the diff shows the new text as removed', file: CLIENT, find: "lineSet(diff.after, 'add', '+');", replace: "lineSet(diff.after, 'del', '+');", tests: [T.browser], browser: true },
  // The server.
  { name: 'the replay screen needs no login', file: SERVE, find: "    if (!guard.loggedIn(req)) {\n      if (req.method === 'GET' && (path === '/' || path === '/replay')) return guard.reply(res, 303", replace: "    if (false) {\n      if (req.method === 'GET' && (path === '/' || path === '/replay')) return guard.reply(res, 303", tests: [T.serve] },
  { name: 'any cookie counts as logged in', file: GUARD, find: 'return found !== null && same(found[1] as string, this.#cookie);', replace: 'return found !== null;', tests: [T.serve, T.liveServe] },
  { name: 'any Host is accepted', file: GUARD, find: 'if (!this.allowedHosts().includes(host)) return [421,', replace: 'if (false) return [421,', tests: [T.serve, T.liveServe] },
  { name: 'any Origin is accepted', file: GUARD, find: 'if (origin !== undefined && !this.allowedHosts()', replace: 'if (false && origin !== undefined && !this.allowedHosts()', tests: [T.serve, T.liveServe] },
  { name: 'the replay screen answers a POST', file: ROUTES, find: "if (req.method !== 'GET') return guard.reply(res, 405,", replace: "if (false) return guard.reply(res, 405,", tests: [T.serve] },
  { name: 'the response headers are dropped', file: RENDER, find: "'content-security-policy': CSP,", replace: '', tests: [T.serve, T.liveServe] },
  { name: 'the referrer policy goes back to no-referrer, which makes a browser send Origin: null', file: RENDER, find: "'referrer-policy': 'same-origin',", replace: "'referrer-policy': 'no-referrer',", tests: [T.liveServe, T.browser] },
  { name: 'hn serve --replay starts the live session instead', file: MAIN, find: 'if (values.replay === true) {', replace: 'if (false) {', tests: [T.serve] },
  // The registry and its page.
  { name: 'a registry name with no test is accepted', file: CATALOG, find: 'untested: attacks.filter((entry) => !claimed.has(entry.name)).map((entry) => entry.name),', replace: 'untested: [],', tests: [T.catalog, T.attacks] },
  { name: 'a test titled as an attack, not in the registry, is accepted', file: CATALOG, find: 'unregistered: [...attackTitled].filter((name) => !registered.has(name)).sort(),', replace: 'unregistered: [],', tests: [T.catalog, T.attacks] },
  { name: 'a name listed twice is accepted', file: CATALOG, find: 'if (seen.has(entry.name)) duplicates.push(entry.name);', replace: '', tests: [T.catalog] },
  { name: 'the public page leaves out each description', file: CATALOG, find: '${cell(row.description)}', replace: '${cell(row.name)}', tests: [T.attacks, T.catalog] },
  { name: 'the public page makes up a link for a test it did not find', file: CATALOG, find: "${file === undefined ? 'MISSING' :", replace: "${file === undefined ? '[x](../../x)' :", tests: [T.catalog] },
  // The hall of fame.
  { name: 'an entry without consent is accepted', file: HALL, find: "if (item['consent'] !== true)", replace: 'if (false)', tests: [T.hall] },
  { name: 'an email address is accepted in a name', file: HALL, find: '|| EMAILISH.test(name) ||', replace: '|| false ||', tests: [T.hall] },
  { name: 'an email address is accepted in a summary', file: HALL, find: 'else if (EMAILISH.test(summary))', replace: 'else if (false)', tests: [T.hall] },
  { name: 'a field the page does not take, such as an email, is accepted', file: HALL, find: 'if (!KEYS.has(key))', replace: 'if (false)', tests: [T.hall] },
  { name: 'a credit need not name an attack in the registry', file: HALL, find: "if (typeof attack !== 'string' || !known.has(attack))", replace: "if (typeof attack !== 'string')", tests: [T.hall] },
  { name: 'markup is accepted in a summary', file: HALL, find: '|| MARKUP.test(summary) ||', replace: '|| false ||', tests: [T.hall] },
  { name: 'a fix before the report is accepted', file: HALL, find: 'if (reported !== null && fixed !== null && fixed < reported)', replace: 'if (false)', tests: [T.hall] },
  { name: 'the same fix may be credited twice', file: HALL, find: 'else if (fixes.has(fix))', replace: 'else if (false)', tests: [T.hall] },
  { name: 'the hall of fame page lists newest last', file: HALL, find: 'b.fixed.localeCompare(a.fixed)', replace: 'a.fixed.localeCompare(b.fixed)', tests: [T.hall] },
];

/** A run that has not finished by now is stuck, not slow. */
const RUN_LIMIT_MS = 12 * 60_000;

const run = (tests: readonly string[]): { ok: boolean; hung: boolean; tail: string } => {
  const env = { ...process.env, ELECTRON_RUN_AS_NODE: '' };
  const result = spawnSync(process.execPath, ['--disable-proto=throw', '--test', '--test-timeout=300000', ...tests], { encoding: 'utf8', env, maxBuffer: 256 * 1024 * 1024, timeout: RUN_LIMIT_MS, killSignal: 'SIGKILL' });
  const lines = `${result.stdout ?? ''}${result.stderr ?? ''}`.split('\n').filter((line) => /^\s*✖/.test(line));
  const hung = result.error !== undefined && (result.error as NodeJS.ErrnoException).code === 'ETIMEDOUT';
  return { ok: result.status === 0, hung, tail: lines.slice(0, 2).join(' | ').slice(0, 200) };
};

const checkOnly = process.argv.includes('--check-only');
const only = process.argv.slice(2).find((arg) => !arg.startsWith('--'));
const haveBrowser = findBrowser() !== null;
const survivors: string[] = [];
let caught = 0;
let skipped = 0;
for (const mutant of mutants) {
  if (only !== undefined && !mutant.name.includes(only)) continue;
  const original = readFileSync(mutant.file, 'utf8').replace(/\r\n/g, '\n');
  if (!original.includes(mutant.find)) {
    console.log(`BROKEN    ${mutant.name}: the text to change is not in ${mutant.file}`);
    survivors.push(`${mutant.name} (script out of date)`);
    continue;
  }
  if (checkOnly) {
    console.log(`found     ${mutant.name}`);
    continue;
  }
  if (mutant.browser === true && !haveBrowser) {
    console.log(`not run   ${mutant.name}: no Chrome or Edge`);
    skipped += 1;
    continue;
  }
  const raw = readFileSync(mutant.file, 'utf8');
  const crlf = raw.includes('\r\n');
  const mutated = original.replace(mutant.find, mutant.replace);
  writeFileSync(mutant.file, crlf ? mutated.replace(/\n/g, '\r\n') : mutated);
  try {
    const outcome = run(mutant.tests);
    if (outcome.ok) {
      console.log(`SURVIVED  ${mutant.name}`);
      survivors.push(mutant.name);
    } else if (outcome.hung) {
      console.log(`HUNG      ${mutant.name}: the tests were still running after ${RUN_LIMIT_MS / 60_000} minutes; they should fail, not hang`);
      survivors.push(`${mutant.name} (tests hang instead of failing)`);
    } else {
      console.log(`caught    ${mutant.name}  ${outcome.tail}`);
      caught += 1;
    }
  } finally {
    writeFileSync(mutant.file, raw);
  }
}
console.log(`\n${caught} caught, ${survivors.length} not caught${skipped === 0 ? '' : `, ${skipped} not run`}.`);
if (survivors.length > 0) {
  console.log(`Not caught:\n- ${survivors.join('\n- ')}`);
  process.exitCode = 1;
}
