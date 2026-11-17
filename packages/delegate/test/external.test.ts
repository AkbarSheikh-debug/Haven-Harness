import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { createExternalTool, loadExternalAgents, type ExternalAgent } from '@hn/delegate';
import { localOperations } from '@hn/operations';
import { Gate, Jail, type ApprovalCard } from '@hn/security';
import { createDispatcher } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

async function fixture(dir: string) {
  const root = await realpath(dir);
  const canary = join(root, 'EXTERNAL-CANARY');
  const script = join(root, 'agent.mjs');
  await writeFile(script, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(canary)}, process.argv[2]); console.log('external agent did: ' + process.argv[2]);`);
  const agent: ExternalAgent = { name: 'fake-claude', description: 'a test agent', command: process.execPath, args: [script, '{task}'], timeoutMs: 20_000 };
  return { root, canary, agent };
}

function dispatcherFor(root: string, mode: string, agent: ExternalAgent, approver?: (card: ApprovalCard) => Promise<'once' | 'deny'>, boxed = false) {
  const cards: ApprovalCard[] = [];
  const gate = new Gate({
    mode,
    workdir: root,
    jail: new Jail({ root, realpath: (path) => realpath(path) }),
    audit: () => undefined,
    tier: mode === 'yolo' ? 3 : 2,
    ...(mode === 'dont-ask' ? { allow: ['external_agent'] } : {}),
    ...(approver === undefined ? {} : { approver: async (card) => (cards.push(card), approver(card)) }),
  });
  const tool = createExternalTool({ agents: [agent], workdir: root, mode: () => gate.mode, boxed })!;
  const dispatcher = createDispatcher({ gate, ops: localOperations(join(root, 'spill')), workdir: root, extraTools: [tool] });
  return { dispatcher, cards };
}

const call = { id: 'x1', name: 'external_agent', args: { agent: 'fake-claude', task: 'refactor everything' } };
const exists = (path: string) => readFile(path).then(() => true, () => false);

describe('external providers', () => {
  it('attack: external_provider_refused_in_yolo (refused before any card, and the program never runs)', async () => {
    await withTempDir(async (dir) => {
      const { root, canary, agent } = await fixture(dir);
      const { dispatcher, cards } = dispatcherFor(root, 'yolo', agent, async () => 'once');
      const result = await dispatcher.run(call, new AbortController().signal);
      assert.equal(result.isError, true);
      assert.match(result.content, /refused in yolo mode: an external agent runs on the host outside the box/);
      assert.equal(cards.length, 0, 'nobody was even asked');
      assert.equal(await exists(canary), false);
    });
  });

  it('runs only after a person says yes, on a card that names the command and says it is outside the gate', async () => {
    await withTempDir(async (dir) => {
      const { root, canary, agent } = await fixture(dir);
      const yes = dispatcherFor(root, 'safe', agent, async () => 'once');
      const result = await yes.dispatcher.run(call, new AbortController().signal);
      assert.equal(result.origin, 'child');
      assert.match(result.content, /<external-report agent="fake-claude" end="exit code 0">\nexternal agent did: refactor everything/);
      assert.match(yes.cards[0]?.target ?? '', /agent\.mjs \{task\} \(runs on your machine, outside hn's gate and sandbox\)/);
      assert.equal(await readFile(canary, 'utf8'), 'refactor everything', 'the task is one argument, no shell');

      for (const [mode, approver] of [['safe', async () => 'deny' as const], ['safe', undefined], ['dont-ask', undefined], ['accept-edits', undefined]] as const) {
        await writeFile(canary, 'untouched');
        const { dispatcher } = dispatcherFor(root, mode, agent, approver);
        const refused = await dispatcher.run(call, new AbortController().signal);
        assert.equal(refused.isError, true, `${mode} with ${approver === undefined ? 'nobody' : 'a no'}`);
        assert.equal(await readFile(canary, 'utf8'), 'untouched');
      }
      const boxed = dispatcherFor(root, 'safe', agent, async () => 'once', true);
      assert.match((await boxed.dispatcher.run(call, new AbortController().signal)).content, /refused in a sandboxed session/);
    });
  });

  it('loads only well-formed agents from the user config: absolute commands, {task} in the arguments', async () => {
    await withTempDir(async (dir) => {
      await mkdir(join(dir, 'agents'));
      await writeFile(join(dir, 'agents', 'external.json'), JSON.stringify([
        { name: 'good', command: process.execPath, args: ['-e', '0', '{task}'] },
        { name: 'bare', command: 'claude', args: ['{task}'] },
        { name: 'notask', command: process.execPath, args: ['-p'] },
        { name: 'Bad Name', command: process.execPath },
      ]));
      const loaded = await loadExternalAgents(dir);
      assert.deepEqual(loaded.agents.map((agent) => agent.name), ['good']);
      assert.equal(loaded.notes.length, 3);
      assert.deepEqual(await loadExternalAgents(join(dir, 'nowhere')), { agents: [], notes: [] });
      assert.equal(createExternalTool({ agents: [], workdir: dir, mode: () => 'safe', boxed: false }), null, 'no agents, no tool');
    });
  });
});
