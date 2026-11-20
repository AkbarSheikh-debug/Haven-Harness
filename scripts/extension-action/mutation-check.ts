// Breaks the editor extension, the GitHub Action and the code they rely on, on purpose, one way at a time, and checks that a test notices each break. A mutant that
// survives is a hole in the tests, not in this script. A developer tool; it edits files in the working copy and restores
// each one, so run it on a clean tree:
//
//   node --disable-proto=throw scripts/extension-action/mutation-check.ts            # all of them
//   node --disable-proto=throw scripts/extension-action/mutation-check.ts --check-only   # only check each target text exists
//   node --disable-proto=throw scripts/extension-action/mutation-check.ts <part of a name>
//
// The extension's host tests drive a real VS Code: set HN_VSCODE to it (or have the usual install) and the mutants that
// need it run; without one they are reported as not run, never as caught.

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

interface Mutant {
  readonly name: string;
  readonly file: string;
  readonly find: string;
  readonly replace: string;
  /** The test files that should fail. */
  readonly tests: readonly string[];
  /** True when the tests need a real VS Code. */
  readonly vscode?: boolean;
}

const T = {
  preview: 'packages/tools/test/preview.test.ts',
  acp: 'packages/surfaces/test/acp.test.ts',
  client: 'packages/vscode/test/acp-client.test.ts',
  launch: 'packages/vscode/test/launch.test.ts',
  host: 'packages/vscode/test/host.test.ts',
  vsix: 'packages/vscode/test/vsix.test.ts',
  report: 'packages/surfaces/test/report.test.ts',
  gate: 'packages/action/test/gate.test.ts',
  publish: 'packages/action/test/publish.test.ts',
  cli: 'packages/action/test/cli.test.ts',
  workflow: 'packages/action/test/workflow.test.ts',
  e2e: 'packages/action/test/e2e.test.ts',
  origin: 'packages/surfaces/test/prompt-origin.test.ts',
} as const;

const FILES = 'packages/tools/src/file-tools.ts';
const GATE = 'packages/security/src/gate.ts';
const ACP = 'packages/surfaces/src/acp.ts';
const CLIENT = 'packages/vscode/src/acp-client.ts';
const CONTROLLER = 'packages/vscode/src/controller.ts';
const LAUNCH = 'packages/vscode/src/launch.ts';
const MANIFEST = 'packages/vscode/package.json';
const REPORT = 'packages/surfaces/src/report.ts';
const MAIN = 'packages/surfaces/src/main.ts';
const EVENT = 'packages/action/src/event.ts';
const GITHUB = 'packages/action/src/github.ts';
const TASK = 'packages/action/src/task.ts';
const AGENT = 'packages/action/src/agent.ts';
const PATCH = 'packages/action/src/patch.ts';
const PUBLISH = 'packages/action/src/publish.ts';
const GATE_JOB = 'packages/action/src/gate.ts';
const WORKFLOW = 'examples/github-action/hn-issue.yml';

const mutants: Mutant[] = [
  // The diff an approval shows is not what is written.
  { name: 'an edit preview shows the old text as the new text', file: FILES, find: 'newText: after, partial: false, truncated: false', replace: 'newText: decoded.text, partial: false, truncated: false', tests: [T.preview, T.acp, T.client] },
  { name: 'a write over a file shows no old text', file: FILES, find: 'oldText: before === null ? null : before.text,', replace: 'oldText: null,', tests: [T.preview] },
  { name: 'a cut preview does not say it is cut', file: FILES, find: 'truncated: after.truncated || before?.truncated === true', replace: 'truncated: false', tests: [T.preview] },
  { name: 'the gate drops the change from the card', file: GATE, find: '...(change === null ? {} : { change }),', replace: '', tests: [T.preview, T.acp, T.client] },
  { name: 'the ACP door strips hidden characters instead of showing them', file: ACP, find: 'newText: revealHidden(change.newText)', replace: 'newText: sanitizeForDisplay(change.newText)', tests: [T.acp] },
  { name: 'the ACP door reports every tool completed', file: ACP, find: "outcomes[n - before - 1] === 'completed' ? 'completed' : 'failed'", replace: "'completed'", tests: [T.acp, T.client] },
  { name: 'a tool with an error result counts as completed', file: ACP, find: "=== false ? 'completed' : 'failed'", replace: "=== false ? 'completed' : 'completed'", tests: [T.acp, T.client] },
  // The editor's client trusts the agent.
  { name: 'the client answers allow-always as if it were allow-once', file: CLIENT, find: "option['kind'] === 'allow_once' && typeof", replace: "(option['kind'] === 'allow_once' || option['kind'] === 'allow_always') && typeof", tests: [T.client] },
  { name: 'the client asks about a permission for a session it never opened', file: CLIENT, find: "if (typeof sessionId !== 'string' || !this.#sessions.has(sessionId)) throw", replace: "if (typeof sessionId !== 'string') throw", tests: [T.client] },
  { name: 'the client serves file and terminal requests', file: CLIENT, find: "if (method !== 'session/request_permission') throw", replace: "if (false) throw", tests: [T.client] },
  { name: 'the client shows the agent\'s text unsanitized', file: CLIENT, find: 'const chunk = cap(sanitize(raw), MAX_CHUNK_CHARS).text;', replace: 'const chunk = cap(raw, MAX_CHUNK_CHARS).text;', tests: [T.client] },
  { name: 'the client strips hidden characters from a diff instead of showing them', file: CLIENT, find: "cap(revealHidden(found['oldText']), MAX_DIFF_CHARS)", replace: "cap(sanitize(found['oldText']), MAX_DIFF_CHARS)", tests: [T.client] },
  { name: 'the client shows an unlimited diff', file: CLIENT, find: "cap(revealHidden(found['newText'] as string), MAX_DIFF_CHARS)", replace: "cap(revealHidden(found['newText'] as string), Infinity)", tests: [T.client] },
  { name: 'the client has no limit on text in one turn', file: CLIENT, find: 'if (this.#chars > MAX_TURN_CHARS) {', replace: 'if (false) {', tests: [T.client] },
  { name: 'the client accepts any protocol version', file: CLIENT, find: "if (record(init)['protocolVersion'] !== ACP_VERSION) throw", replace: "if (false) throw", tests: [T.client] },
  { name: 'the client believes a made-up stop reason', file: CLIENT, find: "return typeof reason === 'string' && STOP_REASONS.has(reason) ? (reason as StopReason) : 'end_turn';", replace: "return reason as StopReason;", tests: [T.client] },
  { name: 'the client sends the editor\'s MCP servers', file: CLIENT, find: "{ cwd, mcpServers: [] }, 120_000)", replace: "{ cwd, mcpServers: [{ name: 'x', command: 'x', args: [] }] }, 120_000)", tests: [T.client] },
  // The extension.
  { name: 'the extension runs in an untrusted folder', file: CONTROLLER, find: 'if (vscode.workspace.isTrusted) return true;', replace: 'if (true) return true;', tests: [T.host], vscode: true },
  { name: 'the diff editor shows the wrong right-hand side', file: CONTROLLER, find: 'this.#docs.set(after.path, request.diff.newText);', replace: "this.#docs.set(after.path, request.diff.oldText ?? '');", tests: [T.host], vscode: true },
  { name: 'a rejected change is allowed', file: CONTROLLER, find: "return yes && !signal.aborted ? 'allow' : 'reject';", replace: "return 'allow';", tests: [T.host], vscode: true },
  { name: 'the diff tab is left open', file: CONTROLLER, find: 'await this.#closeDiffs(opened).catch(() => undefined);', replace: '', tests: [T.host], vscode: true },
  { name: 'the extension asks nothing when no diff can be shown', file: CONTROLLER, find: 'const yes = signal.aborted ? false : await this.#ui.confirm(request.title, notes.join(\'\\n\'));', replace: 'const yes = true;', tests: [T.host], vscode: true },
  { name: 'a folder\'s own settings can set hn.path', file: MANIFEST, find: '"scope": "machine",', replace: '"scope": "window",', tests: [T.vsix], vscode: true },
  { name: 'the extension claims to support untrusted folders', file: MANIFEST, find: '"supported": false,\n      "description": "Haven Harness reads', replace: '"supported": true,\n      "description": "Haven Harness reads', tests: [T.vsix], vscode: true },
  { name: 'the extension starts by itself', file: MANIFEST, find: '"activationEvents": [],', replace: '"activationEvents": ["*"],', tests: [T.vsix], vscode: true },
  { name: 'the Windows command line accepts shell syntax', file: LAUNCH, find: 'const SAFE_ARG = /^[A-Za-z0-9_.:/\\\\@=,+-]+$/;', replace: 'const SAFE_ARG = /^.*$/;', tests: [T.launch] },
  { name: 'a quoted hn.path reaches cmd.exe', file: LAUNCH, find: 'if (/["%^&|<>\\r\\n]/.test(command)) throw', replace: 'if (false) throw', tests: [T.launch] },
  // The report.
  { name: 'a log that fails its check is summarised', file: REPORT, find: "if (log.trust !== 'verified') return {", replace: "if (false) return {", tests: [T.report] },
  { name: 'model text in a report can carry backticks and pipes', file: REPORT, find: ".replace(/[`|]/g, \"'\")", replace: '', tests: [T.report] },
  { name: 'a refused command is reported as having run', file: REPORT, find: "call.decision === 'refused' ? 'not run: refused' : ", replace: '', tests: [T.report] },
  // The Action.
  { name: 'anyone who can label may ask for a change', file: GATE_JOB, find: 'if (!WRITER_ROLES.has(role))', replace: 'if (false)', tests: [T.gate, T.e2e] },
  { name: 'a triage role counts as a writer', file: GITHUB, find: "new Set(['admin', 'maintain', 'write'])", replace: "new Set(['admin', 'maintain', 'write', 'triage', 'read', 'none'])", tests: [T.gate] },
  { name: 'a bot may add the label', file: EVENT, find: "|| sender['type'] !== 'User')", replace: ')', tests: [T.gate] },
  { name: 'a pull request counts as an issue', file: EVENT, find: "if (issue['pull_request'] !== undefined)", replace: 'if (false)', tests: [T.gate] },
  { name: 'any label starts the Action', file: EVENT, find: "if (record(event['label'])['name'] !== label)", replace: 'if (false)', tests: [T.gate] },
  { name: 'the issue can close its own untrusted frame', file: TASK, find: "text.replace(/<\\s*\\/\\s*untrusted/gi, '<\\\\/untrusted')", replace: 'text', tests: [T.gate] },
  { name: 'the GitHub token is handed to hn', file: AGENT, find: "const keep = ['PATH',", replace: "const keep = ['GITHUB_TOKEN', 'PATH',", tests: [T.e2e] },
  { name: 'the issue is given to hn as the user\'s own words', file: AGENT, find: "    '--prompt-origin',\n    'event',\n", replace: '', tests: [T.e2e] },
  { name: 'hn runs without a verified box', file: AGENT, find: "    '--sandbox',\n    'native',\n", replace: '', tests: [T.e2e] },
  { name: 'a workflow file is not protected', file: PATCH, find: "['.github/', ", replace: "['', ", tests: [T.publish] },
  { name: 'a symbolic link is accepted', file: PATCH, find: "if (value === '120000')", replace: "if (false)", tests: [T.publish] },
  { name: 'a binary change is accepted', file: PATCH, find: "if (added === '-' || removed === '-') problems.push", replace: "if (false) problems.push", tests: [T.publish] },
  { name: 'a patch of any size is accepted', file: PATCH, find: 'if (patch.length > MAX_PATCH_BYTES)', replace: 'if (false)', tests: [T.publish] },
  { name: 'a refused patch becomes a pull request anyway', file: PUBLISH, find: 'if (!inspected.ok) {', replace: 'if (false) {', tests: [T.publish, T.e2e] },
  { name: 'the run id chooses the branch name', file: PUBLISH, find: "/^[0-9A-Za-z]{1,20}$/.test(options.runId) ? options.runId : 'x'", replace: 'options.runId', tests: [T.publish] },
  { name: 'files the box held back are not mentioned', file: PUBLISH, find: '    ...heldBack(result[\'handback\']),\n', replace: '', tests: [T.e2e] },
  { name: 'an unfinished run opens a pull request', file: PUBLISH, find: "if (result['complete'] !== true) {", replace: 'if (false) {', tests: [T.publish] },
  { name: 'the agent job is given a write permission', file: WORKFLOW, find: "    permissions:\n      contents: read\n    outputs:\n      complete:", replace: "    permissions:\n      contents: write\n    outputs:\n      complete:", tests: [T.workflow] },
  { name: 'the agent job leaves a token in git', file: WORKFLOW, find: 'persist-credentials: false', replace: 'persist-credentials: true', tests: [T.workflow] },
  { name: 'the workflow starts with every permission', file: WORKFLOW, find: 'permissions: {}', replace: 'permissions: write-all', tests: [T.workflow] },
  { name: 'the publish job is given the model key', file: WORKFLOW, find: "          token: ${{ github.token }}\n", replace: "          token: ${{ github.token }}\n          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}\n", tests: [T.workflow] },
  { name: 'hn -p accepts any prompt origin', file: MAIN, find: "values['prompt-origin'] !== undefined && values['prompt-origin'] !== 'event'", replace: 'false', tests: [T.origin] },
];

/** A run that has not finished by now is stuck, not slow: the unbroken suites take a few minutes. */
const RUN_LIMIT_MS = 12 * 60_000;

const run = (tests: readonly string[]): { ok: boolean; hung: boolean; tail: string } => {
  const env = { ...process.env, ELECTRON_RUN_AS_NODE: '', HN_REQUIRE_BOX: '1' };
  const result = spawnSync(process.execPath, ['--disable-proto=throw', '--test', '--test-timeout=300000', ...tests], { encoding: 'utf8', env, maxBuffer: 256 * 1024 * 1024, timeout: RUN_LIMIT_MS, killSignal: 'SIGKILL' });
  const lines = `${result.stdout ?? ''}${result.stderr ?? ''}`.split('\n').filter((line) => /^\s*✖/.test(line));
  const hung = result.error !== undefined && (result.error as NodeJS.ErrnoException).code === 'ETIMEDOUT';
  return { ok: result.status === 0, hung, tail: lines.slice(0, 2).join(' | ').slice(0, 200) };
};

const checkOnly = process.argv.includes('--check-only');
const only = process.argv.slice(2).find((arg) => !arg.startsWith('--'));
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
  if (checkOnly || mutant.tests.length === 0) {
    console.log(`found     ${mutant.name}`);
    continue;
  }
  if (mutant.vscode === true && !process.env['HN_VSCODE'] && !process.env['LOCALAPPDATA']) {
    console.log(`not run   ${mutant.name}: no VS Code`);
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
