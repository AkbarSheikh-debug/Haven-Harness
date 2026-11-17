// Usage: node packages/evals/src/cli.ts <label> [hn arguments such as --model ollama/qwen3:14b]
import { TASKS, hnExecutor, runSuite, scoreboardRow } from './index.ts';

const [label = 'run', ...hnArgs] = process.argv.slice(2);
const board = await runSuite(label, TASKS, hnExecutor(hnArgs));
for (const result of board.results) {
  const status = result.error !== undefined ? 'BROKE' : result.passed ? 'PASS' : 'FAIL';
  process.stdout.write(`${status} ${result.name} (${result.tokens} tokens)${result.error === undefined ? '' : `: ${result.error}`}\n`);
}
process.stdout.write(`${scoreboardRow(board)}\n`);
process.exitCode = board.passed === board.total ? 0 : 1;
