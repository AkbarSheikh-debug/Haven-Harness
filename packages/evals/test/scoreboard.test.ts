import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { TASKS, runSuite, scoreboardRow, type Execute } from '@hn/evals';

const solutions: Record<string, [file: string, content: string] | null> = {
  'fix-off-by-one': ['sum.js', 'export function sumTo(n) {\n  let total = 0;\n  for (let i = 1; i <= n; i += 1) total += i;\n  return total;\n}\n'],
  'rename-across-files': null,
  'add-a-function': ['math.js', 'export function add(a, b) { return a + b; }\nexport function multiply(a, b) { return a * b; }\n'],
  'answer-from-the-repo': null,
  'preserve-crlf': ['notes.txt', 'alpha\r\ndelta\r\ngamma\r\n'],
};

const solver: Execute = async (task, directory) => {
  const solution = solutions[task.name];
  if (solution !== undefined && solution !== null) await writeFile(join(directory, solution[0]), solution[1]);
  if (task.name === 'rename-across-files') {
    await writeFile(join(directory, 'lib.js'), 'export function loadUser(id) { return { id }; }\n');
    await writeFile(join(directory, 'app.js'), "import { loadUser } from './lib.js';\n");
  }
  return { text: task.name === 'answer-from-the-repo' ? '4.7.31' : 'done', tokens: 10, costUsd: null };
};

describe('the scoreboard', () => {
  it('passes a correct solver on all five tasks', async () => {
    const board = await runSuite('solver', TASKS, solver);
    assert.equal(board.passed, 5, JSON.stringify(board.results));
    assert.equal(scoreboardRow(board), 'solver | 5/5 passed | 50 tokens');
  });

  it('fails an agent that claims success and does nothing', async () => {
    const liar: Execute = async () => ({ text: 'All done, every test passes!', tokens: 1, costUsd: null });
    const board = await runSuite('liar', TASKS, liar);
    assert.equal(board.passed, 0);
  });

  it('counts a crash as a failure, not an error in the suite', async () => {
    const board = await runSuite('crash', TASKS, async () => {
      throw new Error('boom');
    });
    assert.equal(board.passed, 0);
    assert.equal(board.total, 5);
    assert.equal(board.results[0]?.error, 'boom', 'a broken run must not read as the model failing');
  });
});
