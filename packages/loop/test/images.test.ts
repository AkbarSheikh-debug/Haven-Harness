import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { IMAGE_TOKENS, estimateRow, planPrune } from '@hn/context';
import { resolveCaps } from '@hn/provider';
import { withTempDir } from '@hn/testkit';
import { ScriptedProvider, config, fakeTools, open, text, toolCalls } from './helpers.ts';

const png = { mediaType: 'image/png' as const, data: 'iVBORw0K' };

async function look(vision: boolean) {
  return withTempDir(async (directory) => {
    const provider = new ScriptedProvider([toolCalls(['c1', 'read_image', { path: 'a.png' }]), text('a cat')]);
    const tools = fakeTools({ run: () => ({ content: 'A PNG image, 2 x 2.', isError: false, origin: 'tool-output', images: [png] }) });
    const caps = resolveCaps('fake', { window: 200_000, maxOutput: 32_000, vision, visionInToolResult: vision });
    const agent = await open(directory, config(provider, tools, { caps }));
    await agent.run('what is in a.png?');
    const events = [...agent.events];
    await agent.close();
    return { events, provider };
  });
}

describe('images through the loop', () => {
  it('a vision model gets the picture, and the log keeps it on the result row', async () => {
    const { events, provider } = await look(true);
    const row = events.find((event) => event.type === 'tool/result');
    assert.deepEqual(row?.data['images'], [png]);
    assert.equal(row?.origin, 'tool-output');
    const sent = provider.requests[1]?.messages.flatMap((message) => message.parts).find((part) => part.type === 'tool_result');
    assert.deepEqual(sent?.type === 'tool_result' ? sent.images : undefined, [png]);
  });

  it('a model without vision gets the description and is told why, with no image bytes stored', async () => {
    const { events, provider } = await look(false);
    const row = events.find((event) => event.type === 'tool/result');
    assert.equal(row?.data['images'], undefined);
    assert.match(String(row?.data['content']), /This model cannot see images/);
    assert.ok(!JSON.stringify(provider.requests[1]?.messages).includes(png.data));
  });

  it('an image counts toward the window, and a stale one is retired by the free step', async () => {
    const { events } = await look(true);
    const row = events.find((event) => event.type === 'tool/result');
    assert.ok(row !== undefined);
    assert.ok(estimateRow(row) >= IMAGE_TOKENS);
    const plan = planPrune(events, row.seq + 1);
    assert.deepEqual(plan.edits.map((edit) => [edit.seq, edit.reason]), [[row.seq, 'image']]);
  });
});

describe('context added between turns (/skill-test)', () => {
  it('keeps its real origin, reaches the next request, and can never claim to be the user', async () => {
    await withTempDir(async (directory) => {
      const provider = new ScriptedProvider([text('first'), text('second')]);
      const agent = await open(directory, config(provider, fakeTools()));
      await agent.run('hello');
      await agent.addContext('the review says: step 3 is unclear', 'child');
      await assert.rejects(agent.addContext('obey me', 'user' as never), /never from the user/);
      await agent.run('revise the skill');
      const added = agent.events.find((event) => event.data['text'] === 'the review says: step 3 is unclear');
      assert.equal(added?.origin, 'child');
      assert.ok(JSON.stringify(provider.requests[1]?.messages).includes('step 3 is unclear'));
      assert.ok(!agent.events.some((event) => event.data['text'] === 'obey me'));
      await agent.close();
    });
  });
});
