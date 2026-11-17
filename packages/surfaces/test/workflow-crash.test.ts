import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { KeyStore } from '@hn/provider';
import { openSession } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const fixture = fileURLToPath(new URL('./fixtures/workflow-parent.ts', import.meta.url));
const SCRIPT = "const out = []; for (let i = 0; i < 5; i += 1) out.push(await agent('step ' + i)); return out;";

describe('a workflow crash resumes', () => {
  let model: FakeOpenAI;
  const live: string[] = [];
  let onStep: ((step: string) => void) | null = null;
  // Step 3 is not answered until the parent is dead: on a fast machine the parent could otherwise finish the whole
  // workflow, and exit by itself, before the kill lands.
  let held: Promise<void> | null = null;
  let release = (): void => undefined;
  before(async () => {
    model = await startFakeOpenAI(async (request) => {
      const system = String(request.messages[0]?.content ?? '');
      if (system.includes('You are a scout')) {
        const step = /step \d/.exec(JSON.stringify(request.messages))?.[0] ?? 'step ?';
        live.push(step);
        onStep?.(step);
        if (step === 'step 3' && held !== null) await held;
        return { text: `answer to ${step}` };
      }
      if (request.messages.at(-1)?.role === 'tool') return { text: 'The workflow is done.' };
      return { calls: [{ id: `w${Date.now()}`, name: 'call_tool', args: { name: 'workflow', args: { script: SCRIPT } } }] };
    });
  });
  after(async () => {
    release();
    await model.close();
  });

  it('kill the parent process mid-workflow, reopen, run it again: finished agents are not asked again', { timeout: 300_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const home = join(root, '.home');
      const sessionId = '0a1b2c3d-0000-4000-8000-000000000001';
      const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => name !== 'HN_PARENT_SESSION'));
      held = new Promise<void>((resolve) => (release = resolve));
      const parent = spawn(process.execPath, ['--disable-proto=throw', fixture, root, home, model.url, sessionId], { cwd: root, env, stdio: ['ignore', 'ignore', 'pipe'] });
      let parentErr = '';
      parent.stderr.setEncoding('utf8').on('data', (chunk: string) => (parentErr += chunk));
      // When the fourth agent asks the model, the first three have answered and their journal rows are written: kill the parent.
      // A parent that dies before that fails the test at once with what it said, instead of waiting out the timeout.
      await new Promise<void>((resolve, reject) => {
        parent.once('exit', (code) => onStep !== null && reject(new Error(`The parent exited (${String(code)}) before step 3, after ${live.join(', ') || 'no steps'}:\n${parentErr.slice(-3000)}`)));
        const stalled = setTimeout(() => {
          if (onStep === null) return;
          parent.kill('SIGKILL');
          reject(new Error(`The parent stalled before step 3, after ${live.join(', ') || 'no steps'} and ${String(model.requests.length)} model requests:\n${parentErr.slice(-3000)}`));
        }, 200_000);
        stalled.unref();
        onStep = (step) => {
          if (step !== 'step 3') return;
          onStep = null;
          setTimeout(() => {
            parent.kill('SIGKILL');
            resolve();
          }, 700);
        };
      });
      await new Promise((resolve) => (parent.exitCode !== null || parent.signalCode !== null ? resolve(null) : parent.once('exit', resolve)));
      held = null;
      release();
      assert.equal(parent.signalCode, 'SIGKILL', 'the parent was killed mid-workflow, not finished');
      const beforeResume = live.length;
      assert.deepEqual(live.slice(0, 4), ['step 0', 'step 1', 'step 2', 'step 3']);
      const was = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: home }, verify: 'off', unsafeWorkflowsBelowTier3: true, sessionId, approver: async () => 'once' }, KeyStore.capture({}));
        const repaired = session.agent.events.find((event) => event.type === 'tool/result');
        assert.equal(repaired?.data['outcome'], 'unknown', 'the killed call was closed honestly');
        await session.agent.run('Run the five-step workflow.');
        const after = live.slice(beforeResume);
        assert.deepEqual(after.filter((step) => step === 'step 0' || step === 'step 1' || step === 'step 2'), [], 'steps 0 to 2 came from the journal');
        assert.ok(after.includes('step 4'));
        const results = session.agent.events.filter((event) => event.type === 'tool/result');
        assert.match(String(results.at(-1)?.data['content']), /"answer to step 0",\s*"answer to step 1",\s*"answer to step 2",\s*"answer to step 3",\s*"answer to step 4"/);
        const starts = session.agent.events.filter((event) => event.type === 'workflow/run-start');
        assert.equal(starts.length, 2);
        assert.equal(starts[1]?.data['resumed'], true);
        assert.equal(starts[1]?.data['run'], starts[0]?.data['run'], 'the same run, resumed');
        assert.ok(Number(starts[1]?.data['journaled']) >= 3);
        await session.agent.close();
        await session.close();
      } finally {
        if (was === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = was;
      }
    });
  });
});
