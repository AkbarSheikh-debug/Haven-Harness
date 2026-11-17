import { appendFile, cp, mkdir, mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { NativeBox, NonceSinks, createCopy, findHelper, loadBoxConfig, startHnProcess, verifyNativeTier } from '@hn/operations';
import { HN_ENTRY } from './rpc-client.ts';

/**
 * `hn bench`: runs tasks laid out as Terminal-Bench 2 tasks are for Harbor (`instruction.md`, `task.toml`,
 * `environment/`, `tests/`, `solution/`). Docker is off on this machine and the public tasks are Linux images, so this
 * runner uses the Windows native box instead: the agent is a real headless `hn -p --sandbox native` session on a fresh
 * copy of `environment/workspace`, and the task's test runs in a box of its own, so nothing the agent wrote ever runs
 * unboxed on the host. A test writes its reward (0 to 1) to the file named by HN_REWARD, as Harbor's tests write
 * /logs/verifier/reward.txt. `--oracle` runs `solution/solve.ps1` instead of the agent, to prove a task can be solved
 * and that its test can tell.
 */

/** `hn`: the agent; `oracle`: the task's own solution; `none`: nothing, so the test must fail on the untouched workspace. */
export type BenchMode = 'hn' | 'oracle' | 'none';

export interface BenchTask {
  readonly name: string;
  readonly dir: string;
  readonly instruction: string;
  readonly timeoutSec: number;
}

export interface BenchResult {
  readonly task: string;
  readonly agent: BenchMode;
  readonly reward: number;
  readonly passed: boolean;
  readonly seconds: number;
  readonly exitCode: number | null;
  readonly note?: string;
}

/** The few task.toml values this runner reads: `[agent] timeout_sec`. Anything it does not know is left alone. */
export function tomlNumber(text: string, section: string, key: string): number | null {
  let current = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header !== null) current = header[1] as string;
    const pair = /^([A-Za-z0-9_]+)\s*=\s*([0-9.]+)$/.exec(line);
    if (pair !== null && current === section && pair[1] === key) return Number(pair[2]);
  }
  return null;
}

export async function loadTasks(root: string): Promise<BenchTask[]> {
  const tasks: BenchTask[] = [];
  for (const name of (await readdir(root)).sort()) {
    const dir = join(root, name);
    const toml = await readFile(join(dir, 'task.toml'), 'utf8').catch(() => null);
    if (toml === null) continue;
    const instruction = await readFile(join(dir, 'instruction.md'), 'utf8').catch(() => null);
    if (instruction === null) throw new HnError('BAD_TASK', `${name} has a task.toml but no instruction.md.`);
    tasks.push({ name, dir, instruction: instruction.trim(), timeoutSec: tomlNumber(toml, 'agent', 'timeout_sec') ?? 600 });
  }
  return tasks;
}

const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);

interface BoxRunner {
  readonly helper: string;
  readonly home: string;
}

/** Runs PowerShell scripts in a fresh box over the project: the oracle's solution, then the test. Returns the reward. */
async function inBox(runner: BoxRunner, project: string, scripts: readonly string[], timeoutMs: number): Promise<{ reward: number; output: string }> {
  const boxDir = await mkdtemp(join(runner.home, 'bench-box-'));
  const box = await NativeBox.open({ helper: runner.helper, boxDir, sessionId: `bench-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, config: await loadBoxConfig(runner.home) });
  try {
    await createCopy(project, box.work);
    const reward = join(box.tmp, 'reward.txt');
    let output = '';
    for (const script of scripts) {
      // The script's text runs through the box shell (PowerShell, in a drive rooted at the copy), so it never has to
      // open a path whose parents the box cannot see. The oracle's solution changes the copy; the test then reads it.
      const text = await readFile(script, 'utf8');
      const result = await box.exec(`$env:HN_REWARD = '${reward.replaceAll("'", "''")}'\n${text}`, { cwd: box.work, timeoutMs, signal: new AbortController().signal });
      output += result.stdout.toString('utf8') + result.stderr.toString('utf8');
    }
    const text = await readFile(reward, 'utf8').catch(() => '0');
    const value = Number(text.trim());
    return { reward: Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0, output };
  } finally {
    await box.forget();
    await rm(boxDir, { recursive: true, force: true, maxRetries: 10 }).catch(() => undefined);
  }
}

export interface BenchOptions {
  readonly tasks: readonly BenchTask[];
  readonly mode: BenchMode;
  /** Model flags passed to each agent run. */
  readonly args: readonly string[];
  readonly env: NodeJS.ProcessEnv;
  readonly repoRoot: string;
  readonly results?: string;
  readonly out: (text: string) => void;
}

export async function runBench(options: BenchOptions): Promise<BenchResult[]> {
  const helper = await findHelper({ env: options.env, repoRoot: options.repoRoot });
  if (helper === null) throw new HnError('SANDBOX_HELPER_MISSING', 'hn-sandbox is not built. Build it with: pnpm build:sandbox');
  const scratch = await mkdtemp(join(tmpdir(), 'hn-bench-'));
  const runner: BoxRunner = { helper, home: scratch };
  // The test boxes run what the agent wrote, so they are verified from outside before any test runs.
  const probe = await NativeBox.open({ helper, boxDir: join(scratch, 'probe'), sessionId: `bench-probe-${process.pid}`, config: await loadBoxConfig(scratch) });
  const sinks = await NonceSinks.open();
  try {
    const report = await verifyNativeTier(probe, sinks, { outside: scratch, interpreter: process.execPath });
    if (!report.real) throw new HnError('SANDBOX_NOT_VERIFIED', `The test box did not pass the outside-in check, so no test runs:\n- ${report.evidence.join('\n- ')}`);
  } finally {
    await sinks.close();
    await probe.forget();
  }
  const results: BenchResult[] = [];
  try {
    for (const task of options.tasks) {
      const started = Date.now();
      const project = join(scratch, task.name, 'project');
      await mkdir(project, { recursive: true });
      if (await exists(join(task.dir, 'environment', 'workspace'))) await cp(join(task.dir, 'environment', 'workspace'), project, { recursive: true });
      let exitCode: number | null = null;
      let note: string | undefined;
      const scripts: string[] = [];
      if (options.mode === 'oracle') {
        scripts.push(join(task.dir, 'solution', 'solve.ps1'));
      } else if (options.mode === 'hn') {
        const child = startHnProcess({
          entry: HN_ENTRY,
          args: ['-p', task.instruction, '--sandbox', 'native', '--mode', 'yolo', '--verify', 'off', ...options.args],
          cwd: project,
          env: { ...options.env, HN_HOME: join(scratch, task.name, 'home') },
        });
        let stderr = '';
        child.stdout.resume();
        child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
        const timer = setTimeout(() => child.kill(), task.timeoutSec * 1000);
        exitCode = await child.exited;
        clearTimeout(timer);
        if (exitCode !== 0) note = sanitizeForDisplay(stderr.trim().split('\n').slice(-3).join(' ')).slice(0, 300);
      }
      scripts.push(join(task.dir, 'tests', 'test.ps1'));
      const { reward } = await inBox(runner, project, scripts, 120_000);
      const result: BenchResult = { task: task.name, agent: options.mode, reward, passed: reward >= 1, seconds: Math.round((Date.now() - started) / 100) / 10, exitCode, ...(note === undefined ? {} : { note }) };
      results.push(result);
      options.out(`${result.passed ? 'PASS' : 'FAIL'}  ${task.name}  reward ${reward}  ${result.seconds}s${note === undefined ? '' : `  (${note})`}\n`);
      if (options.results !== undefined) await appendFile(options.results, `${JSON.stringify(result)}\n`);
    }
  } finally {
    await rm(scratch, { recursive: true, force: true, maxRetries: 10 }).catch(() => undefined);
  }
  const passed = results.filter((result) => result.passed).length;
  options.out(`${passed} of ${results.length} passed (${options.mode})\n`);
  return results;
}
