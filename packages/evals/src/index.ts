import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { withTempDir } from '@hn/testkit';

export interface EvalTask {
  readonly name: string;
  readonly files: Readonly<Record<string, string>>;
  readonly prompt: string;
  /** The hidden check. The agent never sees it, so it cannot be argued with. */
  check(directory: string, answer: string): Promise<boolean>;
}

const runs = (directory: string, script: string): boolean => {
  try {
    execFileSync(process.execPath, ['-e', script], { cwd: directory, stdio: 'ignore', timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
};

export const TASKS: readonly EvalTask[] = [
  {
    name: 'fix-off-by-one',
    files: {
      'sum.js': 'export function sumTo(n) {\n  let total = 0;\n  for (let i = 1; i < n; i += 1) total += i;\n  return total;\n}\n',
      'sum.test.js': "import { sumTo } from './sum.js';\nif (sumTo(3) !== 6) throw new Error('sumTo(3) should be 6');\n",
      'package.json': '{ "type": "module" }\n',
    },
    prompt: 'node sum.test.js fails. Fix the bug in sum.js, then run the test.',
    check: async (directory) =>
      runs(directory, "import('./sum.js').then(({ sumTo }) => { if (sumTo(10) !== 55 || sumTo(0) !== 0) process.exit(1); })"),
  },
  {
    name: 'rename-across-files',
    files: {
      'lib.js': 'export function fetchUser(id) {\n  return { id };\n}\n',
      'app.js': "import { fetchUser } from './lib.js';\nconsole.log(fetchUser(1));\n",
      'package.json': '{ "type": "module" }\n',
    },
    prompt: 'Rename fetchUser to loadUser everywhere.',
    check: async (directory) => {
      const app = await readFile(join(directory, 'app.js'), 'utf8');
      const lib = await readFile(join(directory, 'lib.js'), 'utf8');
      return !`${app}${lib}`.includes('fetchUser') && app.includes('loadUser') && lib.includes('loadUser');
    },
  },
  {
    name: 'add-a-function',
    files: {
      'math.js': 'export function add(a, b) {\n  return a + b;\n}\n',
      'package.json': '{ "type": "module" }\n',
    },
    prompt: 'Add an exported function multiply(a, b) to math.js.',
    check: async (directory) =>
      runs(directory, "import('./math.js').then(({ multiply, add }) => { if (multiply(3, 4) !== 12 || add(1, 1) !== 2) process.exit(1); })"),
  },
  {
    name: 'answer-from-the-repo',
    files: { 'package.json': '{ "name": "demo", "version": "4.7.31" }\n' },
    prompt: 'What version is this package? Reply with just the version.',
    check: async (_directory, answer) => answer.includes('4.7.31'),
  },
  {
    name: 'preserve-crlf',
    files: { 'notes.txt': 'alpha\r\nbeta\r\ngamma\r\n' },
    prompt: 'In notes.txt, change beta to delta. Change nothing else.',
    check: async (directory) => (await readFile(join(directory, 'notes.txt'), 'utf8')) === 'alpha\r\ndelta\r\ngamma\r\n',
  },
];

export interface RunReport {
  readonly text: string;
  readonly tokens: number;
  readonly costUsd: number | null;
}

export type Execute = (task: EvalTask, directory: string) => Promise<RunReport>;

export interface TaskResult {
  readonly name: string;
  readonly passed: boolean;
  readonly tokens: number;
  /** Set when the run itself broke, so a crash never reads as the model failing. */
  readonly error?: string;
}

export interface Scoreboard {
  readonly label: string;
  readonly passed: number;
  readonly total: number;
  readonly tokens: number;
  readonly results: readonly TaskResult[];
}

export async function runSuite(label: string, tasks: readonly EvalTask[], execute: Execute): Promise<Scoreboard> {
  const results: TaskResult[] = [];
  for (const task of tasks) {
    results.push(
      await withTempDir(async (scratch) => {
        const directory = await realpath(scratch);
        for (const [name, content] of Object.entries(task.files)) {
          await mkdir(dirname(join(directory, name)), { recursive: true });
          await writeFile(join(directory, name), content);
        }
        let error: string | undefined;
        const report = await execute(task, directory).catch((failure: unknown) => {
          error = failure instanceof Error ? failure.message : String(failure);
          return { text: '', tokens: 0, costUsd: null };
        });
        return {
          name: task.name,
          passed: error === undefined && (await task.check(directory, report.text).catch(() => false)),
          tokens: report.tokens,
          ...(error === undefined ? {} : { error }),
        };
      }),
    );
  }
  return {
    label,
    passed: results.filter((result) => result.passed).length,
    total: results.length,
    tokens: results.reduce((sum, result) => sum + result.tokens, 0),
    results,
  };
}

export function scoreboardRow(board: Scoreboard): string {
  return `${board.label} | ${board.passed}/${board.total} passed | ${board.tokens} tokens`;
}

/** Runs each task through the real `hn` door, exactly as a user would. */
export function hnExecutor(extraArgs: readonly string[]): Execute {
  const launcher = fileURLToPath(new URL('../../surfaces/bin/hn.mjs', import.meta.url));
  return async (task, directory) => {
    const child = spawn(
      process.execPath,
      [launcher, '-p', task.prompt, '--json', '--mode', 'dont-ask', '--allow', 'write_file,edit_file,bash', ...extraArgs],
      { cwd: directory, stdio: ['ignore', 'pipe', 'inherit'], env: { ...process.env, HN_HOME: join(directory, '.hn-home') } },
    );
    let stdout = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    const [code] = (await once(child, 'close')) as [number | null];
    if (stdout.trim() === '') throw new Error(`hn crashed with exit code ${code}`);
    const result = JSON.parse(stdout) as { text: string; usage: { input: number; output: number; cacheRead: number; cacheWrite: number } };
    const { input, output, cacheRead, cacheWrite } = result.usage;
    return { text: result.text, tokens: input + output + cacheRead + cacheWrite, costUsd: null };
  };
}
