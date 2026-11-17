import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { findGit } from '@hn/operations';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const REPOS = 25;
const JOBS = 50;
const RPM = 60;
const pad = (n: number): string => String(n).padStart(2, '0');
const jobNumber = (text: string): number => Number(/TASK job-(\d+)/.exec(text)?.[1] ?? 0);

interface Row {
  readonly kind: string;
  readonly name: string;
  readonly sessionId?: string;
  readonly resumed?: boolean;
  readonly result?: { readonly status: string; readonly sessionId: string };
}

/**
 * A 25-repo fleet under a rate limit; it dies at job 31 and resumes at 32.
 * 25 repositories, two jobs each, 4 workers, a real HN_RATE_RPM limit and a 429 with Retry-After, a fake
 * model; the fleet process is killed with SIGKILL once job 31's result is on disk while jobs 32 to 35 are held.
 */
describe('a 25-repo fleet under a rate limit dies at job 31 and resumes at 32', () => {
  let model: FakeOpenAI;
  let holding = true;
  const held: (() => void)[] = [];
  const heldJobs = new Set<number>();
  let throttledAt = -1;
  before(async () => {
    model = await startFakeOpenAI(async (request) => {
      const users = request.messages.filter((message) => message.role === 'user').map((message) => String(message.content)).join('\n');
      const job = jobNumber(users);
      if (holding && job >= 32) {
        heldJobs.add(job);
        await new Promise<void>((resolve) => held.push(resolve));
        return { text: 'too late' };
      }
      // One 429 with Retry-After: every holder of the bucket must pause, not only the one that got it.
      if (throttledAt === -1 && model.requests.length === 20) {
        throttledAt = model.requests.length - 1;
        return { status: 429, retryAfter: 1 };
      }
      const tools = request.messages.filter((message) => message.role === 'tool').length;
      if (tools === 0) return { calls: [{ id: `w${job}`, name: 'write_file', args: { path: `job-${pad(job)}.txt`, content: `written by job ${job}\n` } }] };
      return { text: `job ${job} wrote its file` };
    });
  });
  after(async () => {
    holding = false;
    for (const release of held.splice(0)) release();
    await model.close();
  });

  it('kills the fleet after job 31 with 32 to 35 in flight, resumes them on their own sessions, and never runs 1 to 31 again', { timeout: 300_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const git = await findGit();
      assert.ok(git !== null, 'git is needed to make the repositories');
      for (let repo = 1; repo <= REPOS; repo += 1) {
        const folder = join(root, `repo-${pad(repo)}`);
        await mkdir(folder);
        execFileSync(git, ['init', '-q'], { cwd: folder });
        await writeFile(join(folder, 'README.md'), `repository ${repo}\n`);
      }
      const jobs = Array.from({ length: JOBS }, (_unused, index) => ({ name: `job-${pad(index + 1)}`, workdir: `repo-${pad((index % REPOS) + 1)}`, task: `TASK job-${pad(index + 1)}: write job-${pad(index + 1)}.txt` }));
      await writeFile(join(root, 'fleet.json'), JSON.stringify({ maxWorkers: 4, jobs }));
      const results = join(root, 'fleet.json.results.jsonl');
      const env = { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => name !== 'HN_PARENT_SESSION')), HN_HOME: join(root, '.home'), HN_RATE_RPM: String(RPM) };
      const start = () => spawn(process.execPath, ['--disable-proto=throw', main, 'fleet', 'fleet.json', '--model', 'fake', '--base-url', model.url, '--window', '64000'], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
      const rows = async (): Promise<Row[]> =>
        (await readFile(results, 'utf8').catch(() => '')).split('\n').filter((line) => line.trim() !== '').map((line) => JSON.parse(line) as Row);
      const ended = (all: readonly Row[]): Set<string> => new Set(all.filter((row) => row.kind === 'end').map((row) => row.name));

      // Run 1: wait until jobs 1 to 31 are on disk and 32 to 35 hold all four workers, then kill it without warning.
      const first = start();
      let firstErr = '';
      first.stderr.setEncoding('utf8').on('data', (chunk: string) => (firstErr += chunk));
      const deadline = Date.now() + 180_000;
      for (;;) {
        const done = ended(await rows());
        const allFirst = Array.from({ length: 31 }, (_unused, index) => `job-${pad(index + 1)}`).every((name) => done.has(name));
        if (allFirst && heldJobs.size === 4) break;
        assert.ok(Date.now() < deadline, `run 1 stalled: ${done.size} ended, held ${[...heldJobs].join(',')}; ${firstErr.slice(-500)}`);
        assert.equal(first.exitCode, null, `run 1 exited early: ${firstErr.slice(-500)}`);
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      const firstRequests = model.requests.length;
      first.kill('SIGKILL');
      await once(first, 'close');
      const afterDeath = await rows();
      assert.equal(ended(afterDeath).size, 31, 'exactly jobs 1 to 31 were settled when it died');
      assert.deepEqual([...heldJobs].sort((a, b) => a - b), [32, 33, 34, 35]);
      const startedBefore = new Map(afterDeath.filter((row) => row.kind === 'start').map((row) => [row.name, row.sessionId]));

      // The rate limit held in run 1: never more than the bucket plus one request a second (RPM 60).
      const times = model.arrivals.slice(0, firstRequests);
      for (let i = 0; i < times.length; i += 1) {
        for (let j = i; j < times.length; j += 1) {
          const allowed = RPM + Math.floor(((times[j] as number) - (times[i] as number)) / (60_000 / RPM)) + 1;
          assert.ok(j - i + 1 <= allowed, `requests ${i}..${j} broke the limit`);
        }
      }
      assert.ok(firstRequests > RPM, `run 1 made ${firstRequests} requests, more than one bucket, so the limit had to make some wait`);
      assert.ok((times.at(-1) as number) - (times[0] as number) >= (firstRequests - RPM - 2) * 900, 'and they did wait');
      // The 429 paused every holder: nothing new arrived during its Retry-After second.
      const pauseStart = (times[throttledAt] as number) + 100;
      assert.ok(!times.some((time) => time > pauseStart && time < (times[throttledAt] as number) + 900), 'a request arrived during the shared pause');

      // Run 2: the same command resumes. Jobs 1 to 31 are never asked again; 32 to 35 resume on their own sessions.
      holding = false;
      for (const release of held.splice(0)) release();
      const resumeFrom = model.requests.length;
      const second = start();
      let stdout = '';
      second.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
      let secondErr = '';
      second.stderr.setEncoding('utf8').on('data', (chunk: string) => (secondErr += chunk));
      const [code] = (await once(second, 'close')) as [number | null];
      assert.equal(code, 0, `run 2 failed: ${secondErr.slice(-800)}\n${stdout.slice(-800)}`);
      assert.match(stdout, /50 jobs: 50 done\./);
      assert.match(stdout, /31 were already done in the results file/);
      const asked = new Set(model.requests.slice(resumeFrom).map((request) => jobNumber(request.messages.filter((message) => message.role === 'user').map((message) => String(message.content)).join('\n'))));
      assert.ok([...asked].every((job) => job >= 32), `run 2 asked about jobs ${[...asked].sort((a, b) => a - b).join(',')}`);
      assert.equal(Math.min(...asked), 32, 'it resumed at 32');

      const final = await rows();
      const ends = final.filter((row) => row.kind === 'end');
      assert.equal(ends.length, JOBS, 'one end row per job, none twice');
      assert.ok(ends.every((row) => row.result?.status === 'done'));
      for (const job of [32, 33, 34, 35]) {
        const starts = final.filter((row) => row.kind === 'start' && row.name === `job-${job}`);
        assert.equal(starts.length, 2);
        assert.equal(starts[1]?.resumed, true);
        assert.equal(starts[1]?.sessionId, startedBefore.get(`job-${job}`), `job ${job} resumed on its own session`);
      }
      for (let job = 1; job <= JOBS; job += 1) {
        const folder = join(root, `repo-${pad(((job - 1) % REPOS) + 1)}`);
        assert.equal(await readFile(join(folder, `job-${pad(job)}.txt`), 'utf8'), `written by job ${job}\n`);
      }
      process.stdout.write(`# gate: run 1 made ${firstRequests} requests over ${(((times.at(-1) as number) - (times[0] as number)) / 1000).toFixed(1)} s at RPM ${RPM}; run 2 made ${model.requests.length - resumeFrom}\n`);
    });
  });
});
