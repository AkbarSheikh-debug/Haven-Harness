import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { JobManager } from '@hn/tools';
import { withTempDir } from '@hn/testkit';
import { ScriptedProvider, config, fakeTools, open, text } from '../../loop/test/helpers.ts';

/**
 * Found by a real benchmark: a task that starts a background job (a VM) left it running when hn finished. `hn` closed
 * the session log first and killed the job after, so the job's exit was recorded into a log that was already closed.
 * That threw inside a promise nobody was waiting on, and Node ended the whole process before it wrote its result.
 */
describe('a record that arrives after the session has closed', () => {
  it('is dropped, not thrown, and the log keeps everything written before the close', async () => {
    await withTempDir(async (dir) => {
      const agent = await open(dir, config(new ScriptedProvider([text('done')]), fakeTools()), 'late-1');
      await agent.run('hello');
      agent.record('job/registered', { jobId: 'before' });
      await agent.close();
      assert.doesNotThrow(() => agent.record('job/settled', { jobId: 'after', status: 'killed', code: 137 }));
      const reopened = await open(dir, config(new ScriptedProvider([]), fakeTools()), 'late-1');
      const jobs = reopened.events.filter((event) => event.type.startsWith('job/'));
      assert.ok(jobs.some((event) => event.data['jobId'] === 'before'), 'what was written before the close is kept');
      assert.ok(!jobs.some((event) => event.data['jobId'] === 'after'), 'what came after was not written');
      await reopened.close();
    });
  });

  it('a background job that exits after the session closed does not crash the process', async () => {
    await withTempDir(async (dir) => {
      const unhandled: unknown[] = [];
      const listen = (reason: unknown): void => void unhandled.push(reason);
      process.on('unhandledRejection', listen);
      try {
        const agent = await open(dir, config(new ScriptedProvider([text('done')]), fakeTools()), 'late-2');
        await agent.run('start a vm');
        let exit: (value: { code: number | null }) => void = () => undefined;
        const exited = new Promise<{ code: number | null }>((resolve) => (exit = resolve));
        const empty = { since: () => Buffer.alloc(0) };
        const processes = { start: () => ({ stdout: empty, stderr: empty, exited, signal: () => undefined }) } as never;
        const jobs = new JobManager({ processes, record: (type, data) => agent.record(type, data) });
        const job = jobs.start('bash', 'qemu-system-x86_64 ...', dir);
        assert.ok(typeof job !== 'string');
        jobs.register(job);
        // The order hn used to close in: the log first, the job after.
        await agent.close();
        exit({ code: 137 });
        await new Promise((resolve) => setTimeout(resolve, 50));
        assert.deepEqual(unhandled, [], 'the late exit raised nothing');
      } finally {
        process.off('unhandledRejection', listen);
      }
    });
  });
});
