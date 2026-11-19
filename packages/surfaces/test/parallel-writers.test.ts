import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { git } from '@hn/operations';
import { KeyStore } from '@hn/provider';
import type { ApprovalCard } from '@hn/security';
import { openSession } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

describe('parallel writers through the real stack (decision 3)', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const system = String(request.messages[0]?.content ?? '');
      const last = request.messages.at(-1);
      if (system.includes('You are a worker')) {
        if (last?.role === 'tool') return { text: 'Wrote the file.' };
        const brief = lastContent(request, 'user');
        const file = /into (\w+\.txt)/.exec(brief)?.[1] ?? 'x.txt';
        return { calls: [{ id: `w-${file}`, name: 'write_file', args: { path: file, content: `written by the ${file} worker\n` } }] };
      }
      if (last?.role === 'tool') return { text: 'Both workers reported.' };
      return { calls: [{ id: 'p1', name: 'subagent', args: { tasks: [{ agent: 'worker', task: 'Write into a.txt' }, { agent: 'worker', task: 'Write into b.txt' }] } }] };
    });
  });
  after(async () => {
    await model.close();
  });

  async function run(root: string, approve: (card: ApprovalCard) => 'once' | 'deny') {
    const before = process.env['HN_PARENT_SESSION'];
    const cards: ApprovalCard[] = [];
    try {
      const session = await openSession(
        { workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: join(root, '..', 'home') }, verify: 'off', approver: async (card) => (cards.push(card), approve(card)) },
        KeyStore.capture({}),
      );
      await session.agent.run('Have two workers write a.txt and b.txt.');
      const result = String(session.agent.events.find((event) => event.type === 'tool/result')?.data['content']);
      await session.agent.close();
      await session.close();
      return { result, cards };
    } finally {
      if (before === undefined) delete process.env['HN_PARENT_SESSION'];
      else process.env['HN_PARENT_SESSION'] = before;
    }
  }

  it('two safe workers each write in a private clone, the parent person approves each edit, and both land in the project', { timeout: 180_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = join(await realpath(dir), 'project');
      await mkdir(root);
      await writeFile(join(root, 'README.md'), 'hi\n');
      await git(['init', '--quiet', '-b', 'main'], { cwd: root });
      await git(['add', '-A'], { cwd: root });
      await git(['commit', '--quiet', '-m', 'start'], { cwd: root });
      const head = (await git(['rev-parse', 'HEAD'], { cwd: root })).stdout.trim();
      const { result, cards } = await run(root, () => 'once');
      assert.equal(cards.length, 2, 'one routed card per worker edit');
      assert.ok(cards.every((card) => /^child worker [0-9a-f]{8} asks:/.test(card.summary)));
      assert.match(result, /## Task 1 of 2 \(worker\)[\s\S]*applied to the project: a\.txt[\s\S]*## Task 2 of 2 \(worker\)[\s\S]*applied to the project: b\.txt/);
      assert.equal(await readFile(join(root, 'a.txt'), 'utf8'), 'written by the a.txt worker\n');
      assert.equal(await readFile(join(root, 'b.txt'), 'utf8'), 'written by the b.txt worker\n');
      assert.equal((await git(['rev-parse', 'HEAD'], { cwd: root })).stdout.trim(), head, 'the branch did not move; the files changed in the tree');
    });
  });

  it('refuses parallel writers in a project that is not a git repository, and starts nothing', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = join(await realpath(dir), 'project');
      await mkdir(root);
      const { result, cards } = await run(root, () => 'once');
      assert.match(result, /each need a private clone, and the project is not a git repository\. Nothing was started/);
      assert.equal(cards.length, 0);
    });
  });
});
