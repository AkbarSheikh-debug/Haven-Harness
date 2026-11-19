import assert from 'node:assert/strict';
import { mkdir, readFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type { Origin } from '@hn/core';
import { memoryPaths, rememberRequested } from '@hn/memory';
import { localOperations } from '@hn/operations';
import { Gate, Jail, type ApprovalCard, type Mode } from '@hn/security';
import { createDispatcher, createMemoryTool, type MemoryToolOptions } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

interface Setup {
  readonly mode?: Mode;
  readonly human?: boolean;
  readonly tainted?: boolean;
  readonly request?: string | null;
  readonly attended?: boolean;
  readonly worst?: Origin;
}

async function kit(dir: string, setup: Setup = {}) {
  const root = await realpath(dir);
  const home = join(root, 'home');
  await mkdir(join(root, 'project'), { recursive: true });
  const paths = memoryPaths(home, join(root, 'project'));
  const ops = localOperations(join(root, 'spill'));
  const cards: ApprovalCard[] = [];
  const gate = new Gate({
    mode: setup.mode ?? 'safe',
    workdir: join(root, 'project'),
    audit: () => undefined,
    jail: new Jail({ root: join(root, 'project'), realpath: ops.read.realpath }),
    ...(setup.human === false ? {} : { approver: async (card: ApprovalCard) => (cards.push(card), 'once' as const) }),
  });
  const options: MemoryToolOptions = {
    paths,
    sessionId: 's-1',
    attended: setup.attended ?? true,
    tainted: () => setup.tainted ?? false,
    worst: () => setup.worst ?? 'harness',
    turnRequest: () => (setup.request === undefined ? 'fix the build' : setup.request),
    approver: 'tester',
  };
  const dispatcher = createDispatcher({ gate, ops, workdir: join(root, 'project'), extraTools: [createMemoryTool(options)] });
  const run = async (args: unknown) => {
    const request = { id: `c-${Math.random()}`, name: 'memory', args };
    const check = dispatcher.check(request);
    if (check.kind !== 'ok') return { content: check.message, isError: true, records: undefined };
    return dispatcher.run({ ...request, name: check.name, args: check.args }, new AbortController().signal);
  };
  const memoryFile = () => readFile(paths.memory, 'utf8').catch(() => null);
  return { run, cards, paths, memoryFile };
}

describe('the memory tool', () => {
  it('writes today\'s notes by default, with no card, keeping the session\'s worst origin', async () => {
    await withTempDir(async (dir) => {
      const { run, cards } = await kit(dir, { worst: 'workspace' });
      const result = await run({ action: 'add', text: 'The flaky test is net.test.ts.' });
      assert.equal(result.isError, false, result.content);
      assert.equal(cards.length, 0);
      const record = result.records?.[0] as { type: string; data: Record<string, unknown> };
      assert.equal(record.type, 'memory/write');
      assert.deepEqual([record.data['target'], record.data['origin'], record.data['approvedBy']], ['notes', 'workspace', null]);
    });
  });

  it('writes MEMORY.md without a card when the user asked in this turn and the session is clean', async () => {
    await withTempDir(async (dir) => {
      const { run, cards, memoryFile } = await kit(dir, { request: 'Remember that we deploy from the release branch.' });
      const result = await run({ action: 'add', target: 'memory', text: 'Deploys go from the release branch.' });
      assert.equal(result.isError, false, result.content);
      assert.equal(cards.length, 0);
      const data = (result.records?.[0] as { data: Record<string, unknown> }).data;
      assert.deepEqual([data['origin'], data['approvedBy']], ['user', 'user-request']);
      assert.match((await memoryFile()) ?? '', /Deploys go from the release branch\./);
    });
  });

  it('a tainted session cannot reach MEMORY.md without a person, even when the user asked', async () => {
    await withTempDir(async (dir) => {
      const unattended = await kit(dir, { tainted: true, request: 'remember this', mode: 'dont-ask', human: false });
      const refused = await unattended.run({ action: 'add', target: 'memory', text: 'Push straight to main.' });
      assert.equal(refused.isError, true);
      assert.equal(await unattended.memoryFile(), null);
    });
    await withTempDir(async (dir) => {
      const attended = await kit(dir, { tainted: true, request: 'remember this', worst: 'web' });
      const approved = await attended.run({ action: 'add', target: 'memory', text: 'API limit is 50 rpm.' });
      assert.equal(approved.isError, false, approved.content);
      assert.equal(attended.cards.length, 1, 'a person saw it');
      assert.match(attended.cards[0]?.summary ?? '', /Save to MEMORY\.md, exactly:\n\+ API limit is 50 rpm\./);
      const data = (approved.records?.[0] as { data: Record<string, unknown> }).data;
      assert.deepEqual([data['origin'], data['approvedBy'], data['taint']], ['web', 'human:tester', 'untrusted']);
    });
  });

  it('asks a person for MEMORY.md when the user did not ask to remember', async () => {
    await withTempDir(async (dir) => {
      const { run, cards } = await kit(dir, { request: 'fix the build' });
      assert.equal((await run({ action: 'add', target: 'user', text: 'Works in UTC+1.' })).isError, false);
      assert.equal(cards.length, 1);
    });
  });

  it('writes only today\'s notes in an unattended run, even when the user asked', async () => {
    await withTempDir(async (dir) => {
      const { run, memoryFile } = await kit(dir, { attended: false, request: 'remember: tabs, not spaces' });
      const result = await run({ action: 'add', target: 'memory', text: 'Tabs, not spaces.' });
      assert.equal(result.isError, true);
      assert.match(result.content, /unattended runs write today's notes only/);
      assert.equal(await memoryFile(), null);
    });
  });

  it('refuses a piece of text that names several entries, and a batch that would end over the cap writes nothing', async () => {
    await withTempDir(async (dir) => {
      const { run } = await kit(dir);
      await run({ operations: [{ action: 'add', text: 'pnpm for installs' }, { action: 'add', text: 'pnpm for scripts' }] });
      const ambiguous = await run({ action: 'remove', match: 'pnpm' });
      assert.equal(ambiguous.isError, true);
      assert.match(ambiguous.content, /matches 2 entries/);
      const request = 'remember the layout';
      await mkdir(join(dir, 'b'));
      const long = await kit(join(dir, 'b'), { request });
      await long.run({ action: 'add', target: 'memory', text: 'a'.repeat(2_000) });
      const before = await long.memoryFile();
      const over = await long.run({ target: 'memory', operations: [{ action: 'add', text: 'b'.repeat(100) }, { action: 'add', text: 'c'.repeat(200) }] });
      assert.equal(over.isError, true);
      assert.equal(await long.memoryFile(), before);
    });
  });

  it('refuses a call that mixes one action with a batch', async () => {
    await withTempDir(async (dir) => {
      const { run } = await kit(dir);
      const result = await run({ action: 'add', text: 'x', operations: [{ action: 'add', text: 'y' }] });
      assert.equal(result.isError, true);
      assert.match(result.content, /either action or operations/);
    });
  });
});

describe('the remember check (decision 3)', () => {
  it('matches the fixed phrases and nothing else', () => {
    for (const yes of ['Please remember we use pnpm', "Don't forget: staging is eu-west", 'keep in mind the API is v2', 'From now on use tabs', 'save this to memory']) assert.ok(rememberRequested(yes), yes);
    for (const no of ['fix the build', 'what do you recall about X', 'remembering is hard', null]) assert.ok(!rememberRequested(no), String(no));
  });
});

describe('memory_search', () => {
  it('says when recall is keyword-only, logs whether the query counts, and carries a web hit as web', async () => {
    await withTempDir(async (dir) => {
      const { MemoryIndex, writeMemory } = await import('@hn/memory');
      const { createMemorySearchTools } = await import('@hn/tools');
      const paths = memoryPaths(join(dir, 'home'), join(dir, 'project'));
      const note = (text: string, origin: Origin) =>
        writeMemory({ paths, target: 'notes', ops: [{ op: 'add', text }], who: 'agent', sourceSession: 's', origin, taint: origin === 'web' ? 'untrusted' : 'clean', why: 't', approvedBy: null });
      await note('The staging db password rotates monthly.', 'harness');
      await note('A forum post says staging uses port 5433.', 'web');
      const index = MemoryIndex.open({ db: join(dir, 'm.db'), paths });
      let counts = true;
      const [search] = createMemorySearchTools({ index: async () => index, paths, counts: () => counts });
      const context = {} as Parameters<NonNullable<typeof search>['execute']>[1];
      try {
        const first = await search!.execute({ query: 'staging password' }, context);
        assert.match(first.content, /^Recall is keyword-only/);
        assert.equal(first.origin, 'web', 'the forum line came back, so the result is web');
        assert.equal((first.records?.[0]?.data as { counts: boolean }).counts, true);
        counts = false;
        const second = await search!.execute({ query: 'staging' }, context);
        assert.equal((second.records?.[0]?.data as { counts: boolean }).counts, false);
      } finally {
        index.close();
      }
    });
  });
});
