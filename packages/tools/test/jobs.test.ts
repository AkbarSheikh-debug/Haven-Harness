import assert from 'node:assert/strict';
import { realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type { SessionEvent } from '@hn/core';
import { localOperations, scrubJobEnv } from '@hn/operations';
import { Gate, Jail } from '@hn/security';
import { createDispatcher, JobManager, MAX_JOBS } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

interface Kit {
  run(name: string, args: unknown): Promise<{ content: string; isError: boolean }>;
  jobs: JobManager;
  records: { type: string; data: Record<string, unknown> }[];
}

async function kit(dir: string, history: SessionEvent[] = []): Promise<Kit> {
  const root = await realpath(dir);
  const ops = localOperations(join(root, '..', 'spill-jobs'));
  const records: { type: string; data: Record<string, unknown> }[] = [];
  const processes = ops.processes as NonNullable<typeof ops.processes>;
  const jobs = new JobManager({ processes, record: (type, data) => records.push({ type, data }) });
  const jail = new Jail({ root, realpath: ops.read.realpath });
  const gate = new Gate({ mode: 'yolo', workdir: root, audit: () => undefined, jail, tier: 4 });
  const dispatcher = createDispatcher({ gate, ops, workdir: root, jobs, history: () => history });
  return {
    jobs,
    records,
    run: async (name, args) => {
      const request = { id: `c-${name}-${Math.random()}`, name, args };
      const check = dispatcher.check(request);
      if (check.kind !== 'ok') return { content: check.message, isError: true };
      return dispatcher.run({ ...request, name: check.name, args: check.args }, new AbortController().signal);
    },
  };
}

const idIn = (text: string): string => /(job|term)-[0-9a-f]{8}/.exec(text)?.[0] ?? '';
const settle = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('bash and background jobs', () => {
  it('keeps a command that outlives its timeout as a background job instead of killing it', async () => {
    await withTempDir(async (dir) => {
      const { run, jobs, records } = await kit(dir);
      const started = await run('bash', { command: 'echo first; sleep 1; echo finished', timeout_ms: 300 });
      assert.equal(started.isError, false);
      assert.match(started.content, /kept as background job job-/);
      assert.match(started.content, /first/);
      const id = idIn(started.content);
      await jobs.get(id)?.process.exited;
      await settle(50);
      const later = await run('job_output', { id });
      assert.match(later.content, /finished/);
      assert.doesNotMatch(later.content, /first/, 'output already shown is not shown again');
      assert.match(later.content, /exited with code 0/);
      assert.deepEqual(records.map((record) => record.type), ['job/registered', 'job/settled']);
    });
  });

  it('leaves no job and no log record behind when a command ends in time', async () => {
    await withTempDir(async (dir) => {
      const { run, records } = await kit(dir);
      assert.match((await run('bash', { command: 'echo quick' })).content, /quick/);
      assert.equal((await run('job_list', {})).content, 'None.');
      assert.deepEqual(records, []);
      assert.match((await run('bash', { command: 'exit 3' })).content, /Exit code 3/);
    });
  });

  it('starts a background job on request and stops it, and everything it started, with job_kill', async () => {
    await withTempDir(async (dir) => {
      const { run, jobs } = await kit(dir);
      // A plain child, a double fork and an exec: on Windows all three escape a process-tree kill.
      const command = 'sleep 30 & (sleep 30 &) ; exec sleep 30';
      const id = idIn((await run('bash', { command, run_in_background: true })).content);
      assert.match((await run('job_list', {})).content, new RegExp(`${id} {2}running`));
      await settle(1_500);
      assert.match((await run('job_kill', { id })).content, /Stopped/);
      const job = jobs.get(id);
      const failSafe = new Promise((resolve) => setTimeout(() => resolve('a process survived'), 8_000));
      assert.equal(await Promise.race([job?.process.exited.then(() => 'exited'), failSafe]), 'exited', 'every process it started is gone');
      assert.equal(job?.status, 'killed');
    });
  });

  it('refuses an eleventh running job rather than queueing it', async () => {
    await withTempDir(async (dir) => {
      const { run, jobs } = await kit(dir);
      for (let i = 0; i < MAX_JOBS; i += 1) await run('bash', { command: 'sleep 30', run_in_background: true });
      const eleventh = await run('bash', { command: 'sleep 30', run_in_background: true });
      assert.equal(eleventh.isError, true);
      assert.match(eleventh.content, /10 jobs are already running/);
      await jobs.stopAll();
    });
  });

  it('reaches a job only from the session that owns it', async () => {
    await withTempDir(async (dir) => {
      const owner = await kit(dir);
      const stranger = await kit(dir);
      const id = idIn((await owner.run('bash', { command: 'sleep 30', run_in_background: true })).content);
      const result = await stranger.run('job_kill', { id });
      assert.equal(result.isError, true);
      assert.match(result.content, /belongs to this session/);
      await owner.jobs.stopAll();
    });
  });

  it('lists a job a crash closed as lost, from the log', async () => {
    await withTempDir(async (dir) => {
      const event = (seq: number, type: SessionEvent['type'], data: Record<string, unknown>): SessionEvent => ({
        seq,
        ts: '2026-11-06T00:00:00.000Z',
        type,
        origin: 'harness',
        data,
      });
      const history = [
        event(1, 'job/registered', { jobId: 'job-0000aaaa', kind: 'bash', command: 'npm run dev' }),
        event(2, 'job/settled', { jobId: 'job-0000aaaa', status: 'lost' }),
      ];
      const { run } = await kit(dir, history);
      assert.match((await run('job_list', {})).content, /job-0000aaaa {2}lost {2}npm run dev/);
    });
  });
});

describe('terminals', () => {
  it('keeps a shell open across sends and reads, and closes it', async () => {
    await withTempDir(async (dir) => {
      const { run, jobs, records } = await kit(dir);
      const id = idIn((await run('terminal_open', { command: 'bash' })).content);
      assert.match(id, /^term-/);
      await run('terminal_send', { id, input: 'X=42' });
      await run('terminal_send', { id, input: 'echo "value $X"' });
      let read = '';
      for (let i = 0; i < 40 && !read.includes('value 42'); i += 1) {
        await settle(50);
        read += (await run('terminal_read', { id })).content;
      }
      assert.match(read, /value 42/, 'state carried from one send to the next');
      assert.match((await run('terminal_close', { id })).content, /Stopped/);
      assert.notEqual(jobs.get(id)?.status, 'running');
      assert.equal(records[0]?.type, 'job/registered', 'a terminal is logged at once, so a crash closes it as lost');
    });
  });
});

describe('the job environment', () => {
  it('attack: box_job_cannot_use_tool_socket (no harness socket, token or model key reaches a job)', async () => {
    const planted: Record<string, string> = {
      HN_TOOL_SOCKET: '/tmp/hn-tools.sock',
      HN_TOOL_TOKEN: 'tool-token-0123456789',
      HN_STEER_PIPE: 'hn-steer-pipe-0001',
      ANTHROPIC_API_KEY: 'sk-ant-planted-0123456789',
    };
    const before = { ...process.env };
    Object.assign(process.env, planted, { HN_PARENT_SESSION: 'parent-1' });
    try {
      await withTempDir(async (dir) => {
        const { run } = await kit(dir);
        const env = (await run('bash', { command: 'env' })).content;
        for (const [name, value] of Object.entries(planted)) {
          assert.ok(!env.includes(name), `${name} reached the job`);
          assert.ok(!env.includes(value), `the value of ${name} reached the job`);
        }
        assert.match(env, /HN_PARENT_SESSION=parent-1/, 'a nested hn still knows it is nested');
      });
    } finally {
      for (const name of [...Object.keys(planted), 'HN_PARENT_SESSION']) {
        if (before[name] === undefined) delete process.env[name];
        else process.env[name] = before[name];
      }
    }
  });

  it('scrubs by name, keeping ordinary variables', () => {
    const out = scrubJobEnv({ PATH: '/bin', HN_EXEC: 'm', HN_X: '1', OPENAI_API_KEY: 'k', GITHUB_TOKEN: 'g' });
    assert.deepEqual(Object.keys(out).sort(), ['GITHUB_TOKEN', 'HN_EXEC', 'PATH']);
  });
});
