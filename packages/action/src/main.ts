// The Action's three stages, started by the composite actions in /action. Settings come from environment variables the
// action files set from their inputs, never from text pasted into a shell command.
//
//   node --disable-proto=throw packages/action/src/main.ts gate | agent | publish

import { appendFile, readFile } from 'node:fs/promises';
import { readTask } from './event.ts';
import { runAgent } from './agent.ts';
import { runGate } from './gate.ts';
import { RestGitHub } from './github.ts';
import { runPublish } from './publish.ts';

const env = (name: string): string | undefined => (process.env[name] === undefined || process.env[name] === '' ? undefined : process.env[name]);
const need = (name: string): string => {
  const value = env(name);
  if (value === undefined) throw new Error(`${name} is not set.`);
  return value;
};

/** A line for a later step to read, and one for the run's summary page. Values here are fixed words or numbers. */
async function output(name: string, value: string): Promise<void> {
  const file = env('GITHUB_OUTPUT');
  if (file !== undefined) await appendFile(file, `${name}=${value}\n`);
  else console.log(`${name}=${value}`);
}
async function summary(markdown: string): Promise<void> {
  const file = env('GITHUB_STEP_SUMMARY');
  if (file !== undefined) await appendFile(file, `${markdown}\n`);
  else console.log(markdown);
}

const stage = process.argv[2];
if (stage === 'gate') {
  const result = await runGate({ eventPath: need('GITHUB_EVENT_PATH'), eventName: need('GITHUB_EVENT_NAME'), label: env('HN_ACTION_LABEL') ?? 'hn', api: new RestGitHub(need('GITHUB_TOKEN')), outDir: need('HN_ACTION_OUT') });
  await output('proceed', String(result.proceed));
  await summary(result.proceed ? `hn will work on issue #${result.task.issueNumber}.` : `hn did not run: ${result.reason}`);
} else if (stage === 'agent') {
  const passEnv: Record<string, string> = {};
  // Only these may reach hn, and only if the workflow set them for this step.
  for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'HN_RATE_RPM', 'HN_RATE_TPM']) if (env(name) !== undefined) passEnv[name] = need(name);
  const result = await runAgent({
    taskPath: need('HN_ACTION_TASK'),
    workdir: process.cwd(),
    outDir: need('HN_ACTION_OUT'),
    node: process.execPath,
    hnScript: need('HN_SCRIPT'),
    ...(env('HN_MODEL') === undefined ? {} : { model: need('HN_MODEL') }),
    ...(env('HN_BASE_URL') === undefined ? {} : { baseUrl: need('HN_BASE_URL') }),
    ...(env('HN_WINDOW') === undefined ? {} : { window: Number(need('HN_WINDOW')) }),
    passEnv,
  });
  await output('complete', String(result.complete));
  await summary(`hn ended: ${result.end}. Patch: ${result.patchBytes} bytes.`);
} else if (stage === 'publish') {
  const task = readTask(JSON.parse(await readFile(need('HN_ACTION_TASK'), 'utf8')));
  if (task === null) throw new Error('The task file is not what the gate job writes.');
  const outcome = await runPublish({
    task,
    resultDir: need('HN_ACTION_OUT'),
    repoDir: process.cwd(),
    api: new RestGitHub(need('GITHUB_TOKEN')),
    runId: env('GITHUB_RUN_ID') ?? 'x',
    ...(env('HN_PROTECTED_PATHS') === undefined ? {} : { protectedPaths: need('HN_PROTECTED_PATHS').split(',').map((part) => part.trim()).filter(Boolean) }),
  });
  await output('outcome', outcome.kind);
  await summary(outcome.kind === 'pull-request' ? `Opened ${outcome.url}` : `No pull request: ${outcome.kind}.`);
} else {
  console.error('Usage: main.ts gate | agent | publish');
  process.exitCode = 2;
}
