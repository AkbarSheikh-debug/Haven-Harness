import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { withTempDir } from '@hn/testkit';
import { git, run } from '../src/proc.ts';
import { g, labeledEvent, repoWith, startFakeApi } from './helpers.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

/** The entry point the composite actions run, with the environment GitHub's runner gives it. */
const stage = (name: string, env: Record<string, string>, cwd?: string) =>
  run(process.execPath, ['--disable-proto=throw', main, name], { ...(cwd === undefined ? {} : { cwd }), env: { PATH: process.env['PATH'] ?? '', SystemRoot: process.env['SystemRoot'] ?? '', ...env } });

describe('the Action\'s entry point, as the composite actions run it', () => {
  it('attack: issue_text_cannot_become_a_command - gate: reads the event file, asks the API (at the address the runner sets) for the labeler\'s role, and writes outputs for the next step', { timeout: 60_000 }, async () => {
    const api = await startFakeApi((seen) => (seen.url.includes('/collaborators/maintainer/') ? { status: 200, body: { role_name: 'write' } } : { status: 404, body: {} }));
    try {
      await withTempDir(async (dir) => {
        const top = await realpath(dir);
        const eventPath = join(top, 'event.json');
        await writeFile(eventPath, JSON.stringify(labeledEvent({ issue: { title: '$(touch pwned)', body: '`touch pwned`; "; rm -rf /' } })));
        const output = join(top, 'output.txt');
        await writeFile(output, '');
        const env = { GITHUB_EVENT_PATH: eventPath, GITHUB_EVENT_NAME: 'issues', GITHUB_TOKEN: 'tok', GITHUB_API_URL: api.url, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: join(top, 'summary.md'), HN_ACTION_OUT: join(top, 'task'), HN_ACTION_LABEL: 'hn' };
        const ran = await stage('gate', env, top);
        assert.equal(ran.status, 0, ran.stderr);
        assert.match(await readFile(output, 'utf8'), /^proceed=true$/m);
        const task = JSON.parse(await readFile(join(top, 'task', 'task.json'), 'utf8')) as { issueNumber: number; title: string };
        assert.equal(task.issueNumber, 7);
        assert.equal(task.title, '$(touch pwned)', 'the title is data and is carried as such');
        assert.equal(api.seen[0]?.auth, 'Bearer tok');

        // A different label: nothing is asked of the API, nothing is written, and the answer is no.
        await writeFile(output, '');
        await writeFile(eventPath, JSON.stringify(labeledEvent({ label: 'bug' })));
        const before = api.seen.length;
        const refused = await stage('gate', { ...env, HN_ACTION_OUT: join(top, 'task2') }, top);
        assert.equal(refused.status, 0);
        assert.match(await readFile(output, 'utf8'), /^proceed=false$/m);
        assert.equal(api.seen.length, before);
        assert.match(await readFile(join(top, 'summary.md'), 'utf8'), /hn did not run: The label added was not "hn"/);
        await assert.rejects(readFile(join(top, 'task2', 'task.json')));
        await assert.rejects(readFile(join(top, 'pwned')), 'the issue title ran as a command');
      });
    } finally {
      await api.close();
    }
  });

  it('gate: a failing API fails the job loudly, and a missing setting is named', { timeout: 60_000 }, async () => {
    const api = await startFakeApi(() => ({ status: 500 }));
    try {
      await withTempDir(async (dir) => {
        const top = await realpath(dir);
        const eventPath = join(top, 'event.json');
        await writeFile(eventPath, JSON.stringify(labeledEvent()));
        const env = { GITHUB_EVENT_PATH: eventPath, GITHUB_EVENT_NAME: 'issues', GITHUB_TOKEN: 'tok', GITHUB_API_URL: api.url, GITHUB_OUTPUT: join(top, 'o.txt'), HN_ACTION_OUT: join(top, 'task') };
        const down = await stage('gate', env, top);
        assert.notEqual(down.status, 0, 'a failing API was read as a yes or as a quiet no');
        const { GITHUB_TOKEN: _token, ...noToken } = env;
        const missing = await stage('gate', noToken, top);
        assert.notEqual(missing.status, 0);
        assert.match(missing.stderr, /GITHUB_TOKEN is not set/);
      });
    } finally {
      await api.close();
    }
  });

  it('publish: opens the pull request through the API, from a task file and a result folder', { timeout: 60_000 }, async () => {
    const api = await startFakeApi((seen) => (seen.url.endsWith('/pulls') ? { status: 201, body: { number: 5, html_url: 'https://github.com/acme/widgets/pull/5' } } : { status: 201, body: {} }));
    try {
      await withTempDir(async (dir) => {
        const top = await realpath(dir);
        const { work, origin } = await repoWith(top, { 'a.txt': 'one\n' });
        await writeFile(join(work, 'a.txt'), 'two\n');
        await g(work, 'add', '-A');
        const patch = (await git(['diff', '--cached', '--binary', '--full-index', '--no-renames', 'HEAD'], { cwd: work })).stdout;
        await g(work, 'reset', '-q', '--hard');
        const result = join(top, 'result');
        await mkdir(result);
        await writeFile(join(result, 'hn.patch'), patch);
        await writeFile(join(result, 'result.json'), JSON.stringify({ complete: true, end: 'done' }));
        await writeFile(join(result, 'report.md'), '## hn session report\n');
        const task = join(top, 'task.json');
        await writeFile(task, JSON.stringify({ repo: 'acme/widgets', defaultBranch: 'main', issueNumber: 7, title: 't', body: 'b', labeler: 'maintainer', issueAuthor: 'reporter' }));
        const output = join(top, 'output.txt');
        await writeFile(output, '');
        const ran = await stage('publish', { GITHUB_TOKEN: 'tok', GITHUB_API_URL: api.url, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: join(top, 's.md'), GITHUB_RUN_ID: '4242', HN_ACTION_TASK: task, HN_ACTION_OUT: result }, work);
        assert.equal(ran.status, 0, ran.stderr);
        assert.match(await readFile(output, 'utf8'), /^outcome=pull-request$/m);
        assert.match(await g(origin, 'branch', '--list'), /hn\/issue-7-4242/);
        assert.equal(JSON.parse(api.seen[0]?.body ?? '{}').head, 'hn/issue-7-4242');
        // A task file that is not what the gate writes is refused before anything is pushed.
        await writeFile(task, JSON.stringify({ repo: '../x', issueNumber: 7 }));
        const bad = await stage('publish', { GITHUB_TOKEN: 'tok', GITHUB_API_URL: api.url, GITHUB_OUTPUT: output, GITHUB_RUN_ID: '1', HN_ACTION_TASK: task, HN_ACTION_OUT: result }, work);
        assert.notEqual(bad.status, 0);
        assert.match(bad.stderr, /not what the gate job writes/);
      });
    } finally {
      await api.close();
    }
  });
});
