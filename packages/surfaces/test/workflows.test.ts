import assert from 'node:assert/strict';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import type { ApprovalCard } from '@hn/security';
import { extractJson, openSession, shapeAnswer } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const SCRIPT = `
phase('look');
const found = await agent('Where is the parser?', { label: 'find parser' });
const shaped = await agent('Give the parser location as JSON', { schema: { type: 'object', required: ['file'] } });
const missed = await agent('Give the parser location as JSON', { schema: { type: 'object', required: ['line'] } });
const read = await tool('read_file', { path: 'a.txt' });
const bash = await tool('call_tool', { name: 'bash', args: { command: 'echo pwned > out.txt' } });
const nested = await tool('workflow', { script: 'return 1' });
const nestedViaCallTool = await tool('call_tool', { name: 'run_code', args: { code: 'return 1' } });
const delegate = await tool('subagent', { task: 'x' });
return { found, shaped, missed, read: read.ok, bash, nested, nestedViaCallTool, delegate };`;

describe('workflows through the real stack', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const system = String(request.messages[0]?.content ?? '');
      const asked = JSON.stringify(request.messages);
      if (system.includes('You are a scout')) return { text: asked.includes('as JSON') ? '```json\n{"file": "parse.ts"}\n```' : 'The parser is in parse.ts.' };
      if (request.messages.at(-1)?.role === 'tool') return { text: 'The workflow finished.' };
      return { calls: [{ id: 'w1', name: 'call_tool', args: { name: 'workflow', args: { script: SCRIPT } } }] };
    });
  });
  after(async () => {
    await model.close();
  });

  it('every sub-call is a gated call: call_tool is unwrapped before the gate, and nesting is refused', { timeout: 180_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      await writeFile(join(root, 'a.txt'), 'alpha\n');
      const cards: ApprovalCard[] = [];
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession(
          {
            workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: join(root, '.home') }, verify: 'off', unsafeWorkflowsBelowTier3: true,
            approver: async (card) => (cards.push(card), card.tool === 'workflow' ? 'once' : 'deny'),
          },
          KeyStore.capture({}),
        );
        await session.agent.run('Run the workflow.');
        const result = String(session.agent.events.find((event) => event.type === 'tool/result')?.data['content']);
        const parsed = JSON.parse(result.slice(result.indexOf('\n') + 1, result.indexOf('\n</workflow-result>'))) as Record<string, unknown>;
        assert.equal(parsed['found'], 'The parser is in parse.ts.');
        assert.deepEqual(parsed['shaped'], { file: 'parse.ts' });
        assert.equal(parsed['missed'], null, 'a schema miss is a failure');
        assert.equal(parsed['read'], true);
        assert.deepEqual(parsed['bash'], { ok: false, content: 'The user said no. Ask what they want instead.' });
        assert.match(String((parsed['nested'] as { content: string }).content), /workflow cannot be called from a workflow or run_code/);
        assert.match(String((parsed['nestedViaCallTool'] as { content: string }).content), /run_code cannot be called from a workflow/);
        assert.match(String((parsed['delegate'] as { content: string }).content), /subagent cannot be called from a workflow/);
        assert.deepEqual(cards.map((card) => card.tool), ['workflow', 'bash'], 'the person saw the script, then the real bash call');
        assert.match(cards[0]?.summary ?? '', /run this workflow script:\n\nphase\('look'\)/);
        assert.equal(await readFile(join(root, 'out.txt')).then(() => true, () => false), false);
        const decisions = session.agent.events.filter((event) => event.type === 'audit/decision').map((event) => event.data['tool']);
        assert.ok(decisions.includes('bash') && decisions.includes('read_file'), 'each sub-call was a gate decision under its real name');
        const rows = session.agent.events.map((event) => event.type).filter((type) => type.startsWith('workflow/'));
        assert.equal(rows[0], 'workflow/run-start');
        assert.equal(rows.at(-1), 'workflow/run-end');
        assert.equal(rows.filter((type) => type === 'workflow/agent-end').length, 3);
        assert.equal(session.subagents.list().length, 3, 'the agents were real, logged children');
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });

  it('refuses below tier 3 without the test switch', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: join(root, '.home') }, verify: 'off', approver: async () => 'once' }, KeyStore.capture({}));
        await session.agent.run('Run the workflow.');
        const result = String(session.agent.events.find((event) => event.type === 'tool/result')?.data['content']);
        assert.match(result, /workflow refuses below tier 3/);
        assert.equal(session.agent.events.some((event) => event.type === 'workflow/run-start'), false);
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });

  it('reads a JSON answer from plain, fenced or wrapped text', () => {
    assert.deepEqual(extractJson('{"a":1}'), { a: 1 });
    assert.deepEqual(extractJson('Here:\n```json\n{"a":2}\n```'), { a: 2 });
    assert.deepEqual(extractJson('the answer is {"a":3} ok'), { a: 3 });
    assert.equal(extractJson('no json here'), undefined);
    assert.equal(shapeAnswer('[1]', { type: 'object' }), null);
    assert.deepEqual(shapeAnswer('[1]', { type: 'array' }), [1]);
    assert.equal(shapeAnswer('plain', undefined), 'plain');
  });
});
