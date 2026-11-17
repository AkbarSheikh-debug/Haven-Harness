import assert from 'node:assert/strict';
import { access, readFile, realpath, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import { Harness } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const exists = (path: string): Promise<boolean> => access(path).then(() => true, () => false);
const toolResults = (request: { messages: readonly { role: string; content?: unknown }[] }): string[] =>
  request.messages.filter((message) => message.role === 'tool').map((message) => String(message.content));

describe('the Harness SDK', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const prompt = request.messages.find((message) => message.role === 'user' && String(message.content).startsWith('TASK'))?.content as string | undefined;
      const results = toolResults(request);
      if (prompt === undefined) return { text: 'no task' };
      // Each instance's model reports the session id its own tools see, and tries to reach the other's folder.
      if (prompt.startsWith('TASK whoami')) {
        if (results.length === 0) return { calls: [{ id: 'b1', name: 'bash', args: { command: 'printf %s "$HN_PARENT_SESSION" > who.txt' } }] };
        if (results.length === 1) return { calls: [{ id: 'r1', name: 'read_file', args: { path: prompt.split(' ')[2] } }] };
        return { text: `done: ${results[1]?.slice(0, 80)}` };
      }
      if (prompt.startsWith('TASK write')) {
        if (results.length === 0) return { calls: [{ id: 'w1', name: 'write_file', args: { path: 'new.txt', content: 'x' } }] };
        return { text: `result: ${results[0]}` };
      }
      return { text: `answer to ${lastContent(request, 'user').slice(0, 40)}` };
    });
  });
  after(async () => {
    await model.close();
  });

  const base = (root: string) => ({ workdir: root, model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: join(root, '.home') } });

  it('runs two instances at once in one process; each tool sees only its own session id and neither reaches the other folder', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const [a, b] = [join(top, 'a'), join(top, 'b')];
      await mkdir(a);
      await mkdir(b);
      await writeFile(join(b, 'secret-plan.txt'), 'only for b\n');
      await writeFile(join(a, 'secret-plan.txt'), 'only for a\n');
      const before = process.env['HN_PARENT_SESSION'];
      const approve = async () => 'once' as const;
      const first = new Harness({ ...base(a), mode: 'safe', approver: approve });
      const second = new Harness({ ...base(b), mode: 'safe', approver: approve });
      try {
        const [one, two] = await Promise.all([first.run(`TASK whoami ${join(b, 'secret-plan.txt')}`), second.run(`TASK whoami ${join(a, 'secret-plan.txt')}`)]);
        assert.equal(await readFile(join(a, 'who.txt'), 'utf8'), one.sessionId);
        assert.equal(await readFile(join(b, 'who.txt'), 'utf8'), two.sessionId);
        assert.notEqual(one.sessionId, two.sessionId);
        assert.equal(process.env['HN_PARENT_SESSION'], before, 'no instance touches the process environment');
        // Each one's jail is its own folder: the other's file is outside it.
        assert.doesNotMatch(one.text, /only for b/);
        assert.doesNotMatch(two.text, /only for a/);
        assert.match(one.text, /outside|Blocked/i);
        const state = await first.state();
        assert.equal(state.turns, 1);
        assert.equal(state.mode, 'safe');
        assert.equal(state.busy, false);
        assert.ok(state.spentTokens > 0);
      } finally {
        await first.close();
        await second.close();
      }
    });
  });

  it('defaults to read-only, where a write is refused', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const harness = new Harness(base(root));
      try {
        const result = await harness.run('TASK write');
        assert.match(result.text, /read-only/);
        assert.equal(await exists(join(root, 'new.txt')), false);
      } finally {
        await harness.close();
      }
    });
  });

  it('persist: false leaves no log, home or memory behind', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const harness = new Harness({ ...base(root), persist: false });
      const result = await harness.run('TASK hello');
      assert.match(result.text, /answer to TASK hello/);
      const home = harness.throwawayHome;
      assert.ok(home !== null && (await exists(home)));
      await harness.close();
      await harness.close();
      assert.equal(await exists(home), false, 'the throwaway home is removed');
      assert.equal(await exists(join(root, '.home')), false, 'the configured home was never used');
      await assert.rejects(harness.run('again'), /closed/);
    });
  });

  it('forks a session into a new one that holds the finished turns and names its parent', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const harness = new Harness(base(root));
      let forked: string;
      let parent: string;
      try {
        parent = (await harness.run('TASK remember the colour blue')).sessionId;
        forked = await harness.fork();
        assert.notEqual(forked, parent);
      } finally {
        await harness.close();
      }
      const copy = new Harness({ ...base(root), sessionId: forked });
      try {
        const session = await copy.open();
        const texts = session.agent.events.filter((event) => event.type === 'user/message').map((event) => String(event.data['text']));
        assert.ok(texts.includes('TASK remember the colour blue'));
        assert.ok(session.agent.events.some((event) => event.type === 'session/link' && event.data['kind'] === 'fork' && event.data['parent'] === parent));
        const next = await copy.run('TASK more');
        assert.equal(next.sessionId, forked);
      } finally {
        await copy.close();
      }
    });
  });
});
