import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { orderChecks, runFleet, sameFailure, validateJobs, type CheckOutcome, type FleetJob, type JobRunner, type RunRequest } from '@hn/orchestrate';
import { withTempDir } from '@hn/testkit';

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const jobsIn = (root: string, count: number, folders = count): FleetJob[] =>
  Array.from({ length: count }, (_unused, index) => ({ name: `job-${index + 1}`, workdir: join(root, `repo-${(index % folders) + 1}`), task: `task ${index + 1}` }));

/** A fake runner that records every call. */
function recorder(behave: Partial<JobRunner> = {}) {
  const runs: { job: string; request: RunRequest }[] = [];
  const checks: string[] = [];
  let active = 0;
  let peak = 0;
  const activeFolders = new Set<string>();
  let folderClash = false;
  const runner: JobRunner = {
    run: async (job, request) => {
      runs.push({ job: job.name, request });
      active += 1;
      peak = Math.max(peak, active);
      if (activeFolders.has(job.workdir)) folderClash = true;
      activeFolders.add(job.workdir);
      try {
        await sleep(5 + (job.name.length % 3) * 3);
        return behave.run === undefined ? { end: 'done', text: `did ${job.name}`, tokens: 1_000 } : await behave.run(job, request);
      } finally {
        active -= 1;
        activeFolders.delete(job.workdir);
      }
    },
    check: async (job, check, sessionId, signal) => {
      checks.push(`${job.name}:${check.command}`);
      return behave.check === undefined ? { ran: true, passed: true, output: 'ok' } : behave.check(job, check, sessionId, signal);
    },
    ...(behave.review === undefined ? {} : { review: behave.review }),
  };
  return { runner, runs, checks, peak: () => peak, folderClash: () => folderClash };
}

describe('the fleet', () => {
  it('runs every job at most maxWorkers at once and returns results in input order', async () => {
    await withTempDir(async (root) => {
      // Each job waits (up to 5 s) until three run at once, so concurrency is shown, not left to timing.
      const deadline = Date.now() + 5_000;
      const fake: ReturnType<typeof recorder> = recorder({
        run: async (job) => {
          while (fake.peak() < 3 && Date.now() < deadline) await sleep(5);
          return { end: 'done', text: `did ${job.name}`, tokens: 1_000 };
        },
      });
      const jobs = jobsIn(root, 10);
      const report = await runFleet({ jobs, runner: fake.runner, resultsFile: join(root, 'results.jsonl'), maxWorkers: 3 });
      assert.deepEqual(report.results.map((result) => result.name), jobs.map((job) => job.name));
      assert.equal(report.counts.done, 10);
      assert.equal(fake.peak(), 3, 'three at once, never more');
      assert.equal(report.tokens, 10_000);
      assert.ok(fake.runs.every((run) => run.request.origin === 'user' && !run.request.resume), 'the task is the person\'s words');
      const rows = (await readFile(join(root, 'results.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line) as Record<string, unknown>);
      assert.equal(rows.filter((row) => row['kind'] === 'start').length, 10);
      assert.equal(rows.filter((row) => row['kind'] === 'end').length, 10);
    });
  });

  it('never runs two jobs in one folder at once', async () => {
    await withTempDir(async (root) => {
      const fake = recorder();
      const report = await runFleet({ jobs: jobsIn(root, 12, 3), runner: fake.runner, resultsFile: join(root, 'r.jsonl'), maxWorkers: 6 });
      assert.equal(report.counts.done, 12);
      assert.equal(fake.folderClash(), false);
      assert.ok(fake.peak() <= 3, 'three folders allow at most three at once');
    });
  });

  it('turns a crash into a result and goes on', async () => {
    await withTempDir(async (root) => {
      const fake = recorder({
        run: async (job) => {
          if (job.name === 'job-2') throw new Error('the provider fell over');
          return { end: 'done', text: 'ok', tokens: 10 };
        },
      });
      const report = await runFleet({ jobs: jobsIn(root, 3), runner: fake.runner, resultsFile: join(root, 'r.jsonl') });
      assert.deepEqual(report.results.map((result) => result.status), ['done', 'crashed', 'done']);
      assert.match(report.results[1]?.reason ?? '', /fell over/);
      const failing = recorder({ run: async () => ({ end: 'budget', text: 'ran out', tokens: 5, detail: 'spent' }) });
      const second = await runFleet({ jobs: jobsIn(join(root, 'b'), 1), runner: failing.runner, resultsFile: join(root, 'r2.jsonl') });
      assert.equal(second.results[0]?.status, 'failed');
      assert.match(second.results[0]?.reason ?? '', /budget: spent/);
    });
  });

  it('resumes from its results file: finished jobs are not run again, a started one is resumed on its own session', async () => {
    await withTempDir(async (root) => {
      const file = join(root, 'r.jsonl');
      const jobs = jobsIn(root, 4);
      const ended = (name: string, index: number) => JSON.stringify({ v: 1, kind: 'end', index, name, result: { index, name, status: 'done', sessionId: `s-${name}`, text: `old ${name}`, tokens: 7, attempts: 1, checks: [] } });
      await writeFile(file, [
        JSON.stringify({ v: 1, kind: 'start', index: 0, name: 'job-1', sessionId: 's-job-1' }), ended('job-1', 0),
        JSON.stringify({ v: 1, kind: 'start', index: 1, name: 'job-2', sessionId: 's-job-2' }), ended('job-2', 1),
        JSON.stringify({ v: 1, kind: 'start', index: 2, name: 'job-3', sessionId: 'session-of-job-3' }),
        '{"v":1,"kind":"end","index":3,"na', // a death mid-write
      ].join('\n'));
      const fake = recorder();
      const report = await runFleet({ jobs, runner: fake.runner, resultsFile: file });
      assert.deepEqual(fake.runs.map((run) => run.job), ['job-3', 'job-4'], 'jobs 1 and 2 are not asked again');
      const resumed = fake.runs[0]?.request;
      assert.equal(resumed?.sessionId, 'session-of-job-3');
      assert.equal(resumed?.resume, true);
      assert.equal(resumed?.origin, 'harness');
      assert.match(resumed?.prompt ?? '', /fleet stopped[\s\S]*task 3/);
      assert.equal(fake.runs[1]?.request.resume, false);
      assert.equal(report.resumedFromFile, 2);
      assert.equal(report.results[0]?.text, 'old job-1');
      assert.equal(report.counts.done, 4);
      // And a third run does nothing at all.
      const idle = recorder();
      await runFleet({ jobs, runner: idle.runner, resultsFile: file });
      assert.equal(idle.runs.length, 0);
    });
  });

  it('stops starting jobs when the fleet budget is spent, counting what earlier runs spent', async () => {
    await withTempDir(async (root) => {
      const budgets: number[] = [];
      const fake = recorder({ run: async (_job, request) => (budgets.push(request.budgetTokens), { end: 'done', text: 'ok', tokens: 12_000 }) });
      const report = await runFleet({ jobs: jobsIn(root, 4), runner: fake.runner, resultsFile: join(root, 'r.jsonl'), maxWorkers: 1, budgetTokens: 25_000 });
      assert.deepEqual(report.results.map((result) => result.status), ['done', 'done', 'skipped', 'skipped']);
      assert.deepEqual(budgets, [25_000, 13_000], 'each job gets at most what is left');
      assert.match(report.results[2]?.reason ?? '', /budget is spent/);
    });
  });

  it('runs hidden checks cheapest first, retries once with the output, and escalates the same failure twice', async () => {
    await withTempDir(async (root) => {
      const job = (name: string): FleetJob => ({ name, workdir: join(root, name), task: 'fix it', checks: [{ command: 'slow-test', cost: 10 }, { command: 'lint' }, { command: 'quick-test', cost: 1 }] });
      assert.deepEqual(orderChecks(job('x').checks ?? []).map((check) => check.command), ['quick-test', 'slow-test', 'lint']);
      let calls = 0;
      const outcomes: Record<string, (attempt: number) => CheckOutcome> = {
        fixed: (attempt) => (attempt === 1 ? { ran: true, passed: false, output: 'expected 6, got 5 (12 ms)' } : { ran: true, passed: true, output: 'ok' }),
        stuck: () => ({ ran: true, passed: false, output: `expected 6, got 5 (${(calls += 1)} ms)` }),
        moved: (attempt) => ({ ran: true, passed: false, output: attempt === 1 ? 'expected 6, got 5' : 'TypeError: x is undefined' }),
        nobody: () => ({ ran: false, passed: false, output: '', reason: 'below tier 3 a check needs a person, and nobody is here' }),
      };
      const fake = recorder({
        check: async (fleetJob, check) => {
          if (check.command !== 'quick-test') return { ran: true, passed: true, output: 'ok' };
          const attempt = fake.runs.filter((run) => run.job === fleetJob.name).length;
          return (outcomes[fleetJob.name] as (attempt: number) => CheckOutcome)(attempt);
        },
      });
      const report = await runFleet({ jobs: ['fixed', 'stuck', 'moved', 'nobody'].map(job), runner: fake.runner, resultsFile: join(root, 'r.jsonl') });
      assert.deepEqual(report.results.map((result) => result.status), ['done', 'escalated', 'failed', 'unchecked']);
      assert.equal(report.results[0]?.attempts, 2);
      const retry = fake.runs.find((run) => run.job === 'fixed' && run.request.resume);
      assert.equal(retry?.request.origin, 'harness', 'check output is never the user');
      assert.match(retry?.request.prompt ?? '', /<check-output>\nexpected 6, got 5/);
      assert.match(report.results[3]?.reason ?? '', /nobody is here/);
      assert.equal(fake.checks.filter((entry) => entry.startsWith('fixed:'))[0], 'fixed:quick-test', 'the cheapest check ran first');
      assert.equal(sameFailure({ command: 'a', ran: true, passed: false, output: 'x  1 ms' }, { command: 'a', ran: true, passed: false, output: 'x 99 ms' }), true);
    });
  });

  it('a fresh-context checker can send work back once; a second rejection goes to a person', async () => {
    await withTempDir(async (root) => {
      const reviews: Record<string, boolean[]> = { picky: [false, true], hopeless: [false, false] };
      const fake = recorder({
        review: async (job) => {
          const verdict = (reviews[job.name] as boolean[]).shift() as boolean;
          return { approve: verdict, reason: verdict ? 'fine' : 'missing a test for zero', tokens: 50 };
        },
      });
      const jobs = ['picky', 'hopeless'].map((name) => ({ name, workdir: join(root, name), task: 'do it', checker: true }));
      const report = await runFleet({ jobs, runner: fake.runner, resultsFile: join(root, 'r.jsonl') });
      assert.deepEqual(report.results.map((result) => result.status), ['done', 'escalated']);
      assert.match(fake.runs.find((run) => run.job === 'picky' && run.request.resume)?.request.prompt ?? '', /<review>\nmissing a test for zero/);
      assert.equal(report.results[0]?.tokens, 2_100);
    });
  });

  it('refuses a fleet with duplicate names, relative folders or no task before anything runs', () => {
    assert.match(validateJobs([]) ?? '', /at least one/);
    assert.match(validateJobs([{ name: 'a', workdir: '/x', task: 't' }, { name: 'a', workdir: '/y', task: 't' }]) ?? '', /unique/);
    assert.match(validateJobs([{ name: 'a', workdir: 'relative', task: 't' }]) ?? '', /absolute/);
    assert.match(validateJobs([{ name: 'a b', workdir: '/x', task: 't' }]) ?? '', /name/);
    assert.match(validateJobs([{ name: 'a', workdir: '/x', task: ' ' }]) ?? '', /no task/);
  });
});
