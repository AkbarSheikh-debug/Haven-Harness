import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

/**
 * The safety of the Action is partly in its YAML: which job has a token, what is pasted where. A later edit that gives the
 * agent job a write permission or pastes an issue title into a shell command would pass every other test, so these read
 * the files and fail on exactly those mistakes. They check text, not a YAML engine's reading of it, and say so.
 */

const root = (path: string): string => fileURLToPath(new URL(`../../../${path}`, import.meta.url));
const read = (path: string): Promise<string> => readFile(root(path), 'utf8');

/** The text of one job in the example workflow: from `  name:` at two spaces to the next job or the end. */
function job(workflow: string, name: string): string {
  const lines = workflow.split('\n');
  const start = lines.findIndex((line) => line === `  ${name}:`);
  assert.ok(start >= 0, `no job named ${name}`);
  let end = lines.length;
  for (let n = start + 1; n < lines.length; n += 1) {
    if (/^ {2}[a-z][a-z-]*:$/.test(lines[n] ?? '')) {
      end = n;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

const FILES = ['action/gate/action.yml', 'action/agent/action.yml', 'action/publish/action.yml', 'examples/github-action/hn-issue.yml'];

describe('the Action\'s YAML', () => {
  it('attack: agent_job_holds_no_write_token - gives only the publish job a write token, and the agent job none', async () => {
    const workflow = await read('examples/github-action/hn-issue.yml');
    assert.match(workflow, /^permissions: \{\}$/m, 'the workflow does not start from no permissions');
    for (const name of ['gate', 'agent']) {
      const text = job(workflow, name);
      assert.match(text, /permissions:\n {6}contents: read\n/, `${name} must have contents: read and nothing else`);
      assert.doesNotMatch(text, /: write/, `${name} has a write permission`);
    }
    const publish = job(workflow, 'publish');
    for (const permission of ['contents: write', 'pull-requests: write', 'issues: write']) assert.match(publish, new RegExp(permission));
  });

  it('keeps the agent job\'s credentials out of git and the model key out of every other job', async () => {
    const workflow = await read('examples/github-action/hn-issue.yml');
    assert.match(job(workflow, 'agent'), /actions\/checkout@[0-9a-f]{40}[^\n]*\n\s+with:\n\s+persist-credentials: false/, 'the agent checkout leaves a token in git config');
    for (const name of ['gate', 'publish']) assert.doesNotMatch(job(workflow, name), /ANTHROPIC_API_KEY/, `${name} sees the model key`);
    assert.match(job(workflow, 'agent'), /secrets\.ANTHROPIC_API_KEY/);
    // Only named files leave the agent job: not hn's home folder, its log key or its logs.
    assert.doesNotMatch(job(workflow, 'agent'), /path: \$\{\{ runner\.temp \}\}\/hn-out\n/);
  });

  it('takes the publish job\'s task from the gate job and its checkout from the default branch', async () => {
    const publish = job(await read('examples/github-action/hn-issue.yml'), 'publish');
    assert.match(publish, /name: hn-task/);
    assert.match(publish, /ref: \$\{\{ github\.event\.repository\.default_branch \}\}/);
    assert.match(publish, /task: \$\{\{ runner\.temp \}\}\/hn-task\/task\.json/);
  });

  it('attack: workflow_never_pastes_issue_text_into_a_command - never pastes issue or user text into a command, and pins every action to a commit', async () => {
    for (const file of FILES) {
      const text = await read(file);
      assert.doesNotMatch(text, /github\.event\.(issue|comment|pull_request)\.(title|body)|github\.head_ref|github\.event\.sender/, `${file} uses text someone else wrote in an expression`);
      for (const line of text.split('\n')) {
        const used = /^\s*(?:- )?uses: (\S+)/.exec(line.replace('<commit sha>', '<commit-sha>'))?.[1];
        if (used === undefined || used.startsWith('./')) continue;
        if (used.startsWith('AkbarSheikh-debug/Haven-Harness/')) assert.match(used, /@(<commit-sha>|[0-9a-f]{40})$/, `${file}: ${used} is not pinned to a commit`);
        else assert.match(used, /@[0-9a-f]{40}$/, `${file}: ${used} is not pinned to a commit`);
      }
    }
    // Inputs reach scripts only through env:, never inside the command text.
    for (const file of FILES.slice(0, 3)) {
      const text = await read(file);
      for (const [, command] of text.matchAll(/run: (.*)\n/g)) assert.doesNotMatch(command ?? '', /\$\{\{/, `${file}: an expression sits inside a command`);
      for (const [, block] of text.matchAll(/run: \|\n((?: {8}.*\n)+)/g)) assert.doesNotMatch(block ?? '', /\$\{\{/, `${file}: an expression sits inside a command block`);
    }
  });

  it('sets only environment variables the entry point reads', async () => {
    const main = await read('packages/action/src/main.ts');
    for (const file of FILES.slice(0, 3)) {
      for (const [, name] of (await read(file)).matchAll(/^ {8}(HN_[A-Z_]+|GITHUB_TOKEN|ANTHROPIC_API_KEY): /gm)) {
        assert.ok(main.includes(`'${name}'`) || main.includes(`${name}`), `${file} sets ${name}, which main.ts never reads`);
      }
    }
  });

  it('builds the Linux box prerequisites in the agent action only, and installs hn from source with scripts off', async () => {
    const agent = await read('action/agent/action.yml');
    assert.match(agent, /pnpm install --frozen-lockfile --ignore-scripts/);
    assert.match(agent, /apparmor_restrict_unprivileged_userns=0/);
    for (const file of ['action/gate/action.yml', 'action/publish/action.yml']) assert.doesNotMatch(await read(file), /pnpm install|sysctl|cargo/, `${file} installs or loosens something it has no need of`);
  });
});
