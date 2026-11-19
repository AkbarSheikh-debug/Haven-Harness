import assert from 'node:assert/strict';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import type { ApprovalCard } from '@hn/security';
import { PRESETS, openSession, presetChain, runPreset } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

describe('presets', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const system = String(request.messages[0]?.content ?? '');
      const brief = lastContent(request, 'user');
      const last = request.messages.at(-1);
      if (system.includes('You are a scout')) return { text: 'SCOUT: greet() lives in hello.ts and says hello.' };
      if (system.includes('You are a planner')) return { text: brief.includes('SCOUT:') ? 'PLAN: 1. In hello.ts make greet() say hi.' : 'PLAN: no scout report' };
      if (system.includes('You are a worker')) {
        if (!JSON.stringify(request.messages).includes('PLAN: 1.')) return { text: 'WORKER: no plan' };
        const tools = request.messages.filter((message) => message.role === 'tool').length;
        // A worker reads before it writes; the harness refuses a write to a file it has not seen.
        if (tools === 0) return { calls: [{ id: 'r1', name: 'read_file', args: { path: 'hello.ts' } }] };
        if (tools === 1) return { calls: [{ id: 'e1', name: 'write_file', args: { path: 'hello.ts', content: "export const greet = () => 'hi';\n" } }] };
        return { text: `WORKER: changed hello.ts (${String(last?.content).slice(0, 40)})` };
      }
      if (system.includes('You are a reviewer')) return { text: brief.includes('WORKER: changed') ? 'REVIEW: no problems found.' : 'REVIEW: nothing to review' };
      return { text: 'parent' };
    });
  });
  after(async () => {
    await model.close();
  });

  it('defines the three presets from the plan as chains of the crew', () => {
    assert.deepEqual(PRESETS['implement'], ['scout', 'planner', 'worker']);
    assert.deepEqual(PRESETS['scout-and-plan'], ['scout', 'planner']);
    assert.deepEqual(PRESETS['implement-and-review'], ['scout', 'planner', 'worker', 'reviewer']);
    const chain = presetChain('implement', 'make greet say hi');
    assert.ok(chain?.every((step) => step.task.includes('make greet say hi')));
    assert.ok(chain?.slice(1).every((step) => step.task.includes('{previous}')));
    assert.equal(presetChain('nope', 'x'), null);
  });

  it('each preset runs through the real stack in safe mode; the worker edit is approved by the person through routing', { timeout: 240_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      await writeFile(join(root, 'hello.ts'), "export const greet = () => 'hello';\n");
      const cards: ApprovalCard[] = [];
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: join(root, '.home') }, verify: 'off', approver: async (card) => (cards.push(card), 'once') }, KeyStore.capture({}));
        const outputs: Record<string, string> = {};
        for (const name of ['scout-and-plan', 'implement', 'implement-and-review']) {
          let text = '';
          assert.equal(await runPreset(session, `/${name} make greet say hi`, (chunk) => (text += chunk)), true);
          outputs[name] = text;
        }
        assert.match(outputs['scout-and-plan']!, /step 1 of 2: scout \(done\)[\s\S]*SCOUT: greet\(\)[\s\S]*step 2 of 2: planner \(done\)[\s\S]*PLAN: 1\./);
        assert.match(outputs['implement']!, /step 3 of 3: worker \(done\)[\s\S]*WORKER: changed hello\.ts/);
        assert.match(outputs['implement-and-review']!, /step 4 of 4: reviewer \(done\)[\s\S]*REVIEW: no problems found/);
        assert.equal(await readFile(join(root, 'hello.ts'), 'utf8'), "export const greet = () => 'hi';\n");
        assert.equal(cards.length, 2, 'one routed card per worker edit, in the two presets with a worker');
        assert.ok(cards.every((card) => card.tool === 'write_file' && /^child worker /.test(card.summary)));
        const added = session.agent.events.filter((event) => event.type === 'user/message' && String(event.data['text']).startsWith('The person ran /'));
        assert.equal(added.length, 3);
        assert.ok(added.every((event) => event.origin === 'child'), 'the reports are child data, never the user');
        let usage = '';
        assert.equal(await runPreset(session, '/implement', (chunk) => (usage += chunk)), true);
        assert.match(usage, /Use: \/implement <what you want done>/);
        assert.equal(await runPreset(session, '/compact', () => undefined), false);
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });
});
