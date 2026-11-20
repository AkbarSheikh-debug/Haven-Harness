import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { readTask } from './event.ts';
import { git, run } from './proc.ts';
import { buildPrompt } from './task.ts';

export interface AgentOptions {
  /** `task.json`, written by the gate job. */
  readonly taskPath: string;
  /** The checked-out repository the agent works on. */
  readonly workdir: string;
  readonly outDir: string;
  /** How to start hn: the node program and hn's launcher script. */
  readonly node: string;
  readonly hnScript: string;
  readonly model?: string;
  readonly baseUrl?: string;
  readonly window?: number;
  /** The few variables hn needs, such as a model key. Nothing else from this job's environment reaches hn. */
  readonly passEnv: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
}

export interface AgentResult {
  readonly sessionId: string | null;
  /** Why the turn ended: `done`, or a stop such as `budget` or `refusal`. */
  readonly end: string;
  readonly complete: boolean;
  readonly hnExit: number | null;
  readonly patchBytes: number;
  readonly handback: { readonly applied: readonly string[]; readonly held: readonly unknown[]; readonly notImported: readonly unknown[] } | null;
}

/** What hn gets of this job's environment. Not the GitHub token, and no other secret: only the basics and what is named. */
export function hnEnvironment(outDir: string, passEnv: Readonly<Record<string, string>>, from: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const keep = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'windir', 'ComSpec', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL'];
  const env: NodeJS.ProcessEnv = {};
  for (const name of keep) if (from[name] !== undefined) env[name] = from[name];
  const home = join(outDir, 'home');
  return { ...env, HOME: home, USERPROFILE: home, HN_HOME: join(outDir, 'hn-home'), ...passEnv };
}

const lastJson = (text: string): Record<string, unknown> | null => {
  for (const line of text.split('\n').reverse()) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const value: unknown = JSON.parse(trimmed);
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) return value as Record<string, unknown>;
    } catch {
      // Not the result line.
    }
  }
  return null;
};

/**
 * The second job: the model works, and nothing else. hn runs in a verified native box (`--sandbox native`, which refuses
 * to start unless the box passes the outside-in check, so there is no unboxed fallback), on a copy of the project, with
 * the issue as an `event` and never as the user's words. This job holds no write token. What leaves it is a patch and a
 * report, as files; the third job decides what to do with them.
 */
export async function runAgent(options: AgentOptions): Promise<AgentResult> {
  const task = readTask(JSON.parse(await readFile(options.taskPath, 'utf8')));
  if (task === null) throw new Error('The task file is not what the gate job writes.');
  await mkdir(options.outDir, { recursive: true });
  await mkdir(join(options.outDir, 'home'), { recursive: true });
  const env = hnEnvironment(options.outDir, options.passEnv);
  const args = [
    '--disable-proto=throw',
    options.hnScript,
    '-p',
    buildPrompt(task),
    '--prompt-origin',
    'event',
    '--sandbox',
    'native',
    '--json',
    ...(options.model === undefined ? [] : ['--model', options.model]),
    ...(options.baseUrl === undefined ? [] : ['--base-url', options.baseUrl]),
    ...(options.window === undefined ? [] : ['--window', String(options.window)]),
  ];
  const ran = await run(options.node, args, { cwd: options.workdir, env, timeoutMs: options.timeoutMs ?? 55 * 60_000 });
  const stdout = ran.stdout.toString('utf8');
  await writeFile(join(options.outDir, 'hn-stderr.txt'), ran.stderr.slice(-20_000));
  const result = lastJson(stdout);
  const sessionId = typeof result?.['sessionId'] === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(result['sessionId']) ? result['sessionId'] : null;
  const end = typeof result?.['end'] === 'string' ? result['end'] : 'failed';
  const handback = result?.['handback'] as { applied?: unknown; held?: unknown; notImported?: unknown } | undefined;

  // What changed, as the patch the next job will check: staged so new files are in it, with no filters or drivers that
  // the repository's own configuration could use to run something.
  await git(['add', '-A'], { cwd: options.workdir });
  const diff = await git(['diff', '--cached', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', '--no-renames', 'HEAD'], { cwd: options.workdir, env, });
  await writeFile(join(options.outDir, 'hn.patch'), diff.stdout);

  // The report, made from the session's own log. A session that never started has none.
  if (sessionId !== null) {
    const report = await run(options.node, ['--disable-proto=throw', options.hnScript, 'report', sessionId], { cwd: options.workdir, env, timeoutMs: 60_000 });
    await writeFile(join(options.outDir, 'report.md'), report.stdout);
    await writeFile(join(options.outDir, 'report-exit.txt'), String(report.status));
  }
  const summary: AgentResult = {
    sessionId,
    end,
    complete: end === 'done' && ran.status === 0,
    hnExit: ran.status,
    patchBytes: (await stat(join(options.outDir, 'hn.patch'))).size,
    handback:
      handback === undefined
        ? null
        : { applied: Array.isArray(handback.applied) ? (handback.applied as string[]) : [], held: Array.isArray(handback.held) ? handback.held : [], notImported: Array.isArray(handback.notImported) ? handback.notImported : [] },
  };
  await writeFile(join(options.outDir, 'result.json'), `${JSON.stringify(summary)}\n`);
  return summary;
}
