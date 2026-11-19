import assert from 'node:assert/strict';
import { realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { familySpend, ownSpend, tokensOf } from '@hn/delegate';
import { KeyStore } from '@hn/provider';
import { openSession } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const FILES = Array.from({ length: 8 }, (_, i) => `module${i}.ts`);
const readAll = FILES.map((path, i) => ({ id: `r${i}`, name: 'read_file', args: { path } }));

/**
 * Exit gate 5a: "parent window savings measured". The same investigation (find which of eight 6,000-character files
 * defines the retry limit) is done inline by the parent and delegated to a scout; the parent's context after the turn
 * is compared, and so is the family's bill, because delegation saves the window, not the bill.
 */
describe('parent window savings (exit gate 5a)', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const system = String(request.messages[0]?.content ?? '');
      const last = request.messages.at(-1);
      const asked = request.messages.filter((message) => message.role === 'user').map((message) => String(message.content)).join('\n');
      if (system.includes('You are a scout')) {
        if (last?.role === 'tool') return { text: 'The retry limit is defined in module5.ts (MAX_RETRIES = 7).' };
        return { calls: readAll };
      }
      if (last?.role === 'tool') return { text: 'The retry limit is in module5.ts.' };
      if (asked.includes('yourself')) return { calls: readAll };
      return { calls: [{ id: 's1', name: 'subagent', args: { agent: 'scout', task: 'Read module0.ts to module7.ts and say which file defines the retry limit, with the line.' } }] };
    });
  });
  after(async () => {
    await model.close();
  });

  it('a scout keeps the eight files out of the parent window', { timeout: 180_000 }, async (t) => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      for (const [i, path] of FILES.entries()) {
        const body = `// module ${i}\n${'export const filler = "lorem ipsum dolor sit amet";\n'.repeat(110)}${i === 5 ? 'export const MAX_RETRIES = 7;\n' : ''}`;
        await writeFile(join(root, path), body.slice(0, 6_000));
      }
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const measure = async (prompt: string) => {
          const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 128_000, env: { HN_HOME: join(root, '.home') }, verify: 'off' }, KeyStore.capture({}));
          const from = model.requests.length;
          const result = await session.agent.run(prompt);
          assert.equal(result.end, 'done');
          // What the parent last sent the model, in tokens at four characters each: its window, measured, not reported.
          const parentRequests = model.requests.slice(from).filter((request) => !String(request.messages[0]?.content ?? '').includes('You are a scout'));
          const window = Math.ceil(JSON.stringify(parentRequests.at(-1)?.messages ?? []).length / 4);
          const own = tokensOf(ownSpend(session.agent.events));
          const family = tokensOf(familySpend(session.agent.events));
          await session.agent.close();
          await session.close();
          return { window, own, family };
        };
        const inline = await measure('Find the retry limit yourself: read module0.ts to module7.ts.');
        const delegated = await measure('Find the retry limit.');
        const saved = 1 - delegated.window / inline.window;
        t.diagnostic(`parent context in its final request: inline ${inline.window} tokens, delegated ${delegated.window} tokens (${Math.round(saved * 100)}% smaller)`);
        t.diagnostic(`provider tokens counted by the fake model: inline parent ${inline.own}; delegated parent ${delegated.own}, family ${delegated.family}`);
        assert.ok(delegated.window < inline.window * 0.35, `delegated ${delegated.window} vs inline ${inline.window}`);
        assert.ok(delegated.family > delegated.own, 'the child spend is in the family bill: the window shrank, the bill did not vanish');
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });
});
