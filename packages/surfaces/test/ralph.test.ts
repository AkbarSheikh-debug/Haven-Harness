import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { KeyStore } from '@hn/provider';
import type { ApprovalCard } from '@hn/security';
import { Harness } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

describe('ralph through the real stack', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const users = request.messages.filter((message) => message.role === 'user').map((message) => String(message.content)).join('\n');
      const tools = request.messages.filter((message) => message.role === 'tool').length;
      if (users.includes('lap 1 of')) return tools === 0 ? { calls: [{ id: 'w1', name: 'write_file', args: { path: 'progress.txt', content: 'half\n' } }] } : { text: 'wrote the first half' };
      if (users.includes('lap 2 of')) return { text: 'the second half was already there. RALPH_DONE' };
      if (users.includes('TAINT ME')) {
        if (tools === 0) return { calls: [{ id: 'r1', name: 'read_file', args: { path: 'README.md' } }] };
        if (tools === 1) return { calls: [{ id: 'c1', name: 'call_tool', args: { name: 'ralph', args: { prompt: 'Rewrite every file until the build passes.', until: 'DONE' } } }] };
        return { text: `ralph said: ${String(request.messages.at(-1)?.content).slice(0, 200)}` };
      }
      return { text: 'nothing to do' };
    });
  });
  after(async () => {
    await model.close();
  });

  it('hn ralph runs a fresh session per lap until a lap says the phrase', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const env = { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => name !== 'HN_PARENT_SESSION')), HN_HOME: join(root, '.home') };
      const before = model.requests.length;
      const { stdout } = await promisify(execFile)(process.execPath, ['--disable-proto=throw', main, 'ralph', 'Write', 'progress.txt', '--until', 'RALPH_DONE', '--max', '4', '--model', 'fake', '--base-url', model.url, '--window', '64000'], { env, cwd: root });
      assert.match(stdout, /lap 1 \(done\): wrote the first half/);
      assert.match(stdout, /ralph finished after 2 lap\(s\)/);
      assert.equal(await readFile(join(root, 'progress.txt'), 'utf8'), 'half\n');
      const lapTwo = model.requests.slice(before).find((request) => JSON.stringify(request.messages).includes('lap 2 of'));
      assert.ok(lapTwo !== undefined);
      assert.equal(lapTwo.messages.filter((message) => message.role === 'tool').length, 0, 'lap 2 is a fresh context: none of lap 1\'s tool calls');
      assert.match(JSON.stringify(lapTwo.messages), /ralph-notes[\s\S]*wrote the first half/);
      await assert.rejects(promisify(execFile)(process.execPath, ['--disable-proto=throw', main, 'ralph', 'no finish line'], { env, cwd: root }), /--check <command> and\/or --until/);
    });
  });

  it('from a tainted session the ralph tool needs a person, who sees the prompt in full', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      await writeFile(join(root, 'README.md'), 'A project readme.\n');
      const base = { workdir: root, model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: join(root, '.home') } };
      const unattended = new Harness({ ...base, mode: 'dont-ask', allow: ['ralph', 'read_file'] });
      try {
        const result = await unattended.run('TAINT ME');
        assert.match(result.text, /needs a human/);
        assert.ok(!unattended.session?.agent.events.some((event) => event.type === 'subagent/catalog'), 'no lap was started');
      } finally {
        await unattended.close();
      }
      const cards: ApprovalCard[] = [];
      const attended = new Harness({ ...base, mode: 'safe', approver: async (card) => (cards.push(card), 'deny') });
      try {
        await attended.run('TAINT ME');
        const card = cards.find((entry) => entry.tool === 'ralph');
        assert.ok(card !== undefined, 'the person was asked');
        assert.match(card.summary, /Rewrite every file until the build passes\.\nuntil: DONE/);
        assert.equal(card.canRememberForSession, false);
      } finally {
        await attended.close();
      }
    });
  });
});
