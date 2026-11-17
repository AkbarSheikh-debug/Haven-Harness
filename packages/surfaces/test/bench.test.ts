import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadTasks, runBench, tomlNumber } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, type FakeOpenAI } from '@hn/testkit';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const tasksRoot = fileURLToPath(new URL('../../evals/terminal-bench/local/', import.meta.url));
const windows = process.platform === 'win32' ? false : 'the bench runner uses the Windows native box';

describe('hn bench: Terminal-Bench-format tasks in the Windows box', { skip: windows }, () => {
  let model: FakeOpenAI;
  before(async () => {
    // A scripted agent for csv-total: it writes the answer, then says it is done.
    model = await startFakeOpenAI((request) => {
      const done = request.messages.some((message) => message.role === 'tool');
      if (lastContent(request, 'user').includes('total.txt') && !done) return { calls: [{ id: 'w', name: 'write_file', args: { path: 'total.txt', content: '600\n' } }] };
      return { text: 'Wrote total.txt.' };
    });
  });
  after(async () => {
    await model.close();
  });

  it('reads the task layout', async () => {
    const tasks = await loadTasks(tasksRoot);
    assert.deepEqual(tasks.map((task) => task.name), ['count-errors', 'csv-total', 'fix-function', 'fix-json', 'rename-logs']);
    assert.ok(tasks.every((task) => task.timeoutSec === 600 && task.instruction.length > 20));
    assert.equal(tomlNumber('[verifier]\ntimeout_sec = 120\n[agent]\ntimeout_sec = 900 # comment\n', 'agent', 'timeout_sec'), 900);
  });

  it('every task can be solved, and every test fails an untouched workspace: the tests can tell', { timeout: 300_000 }, async () => {
    const tasks = await loadTasks(tasksRoot);
    const quiet = (): void => undefined;
    const oracle = await runBench({ tasks, mode: 'oracle', args: [], env: process.env, repoRoot, out: quiet });
    assert.deepEqual(oracle.map((result) => result.passed), [true, true, true, true, true]);
    const none = await runBench({ tasks, mode: 'none', args: [], env: process.env, repoRoot, out: quiet });
    assert.deepEqual(none.map((result) => result.reward), [0, 0, 0, 0, 0]);
  });

  it('runs a real hn -p --sandbox native agent on a task and scores it in a box', { timeout: 300_000 }, async () => {
    const tasks = (await loadTasks(tasksRoot)).filter((task) => task.name === 'csv-total');
    const lines: string[] = [];
    const results = await runBench({ tasks, mode: 'hn', args: ['--model', 'fake', '--base-url', model.url, '--window', '64000'], env: process.env, repoRoot, out: (text) => lines.push(text) });
    assert.equal(results[0]?.exitCode, 0, results[0]?.note);
    assert.equal(results[0]?.passed, true, lines.join(''));
    assert.match(lines.join(''), /1 of 1 passed \(hn\)/);
  });
});
