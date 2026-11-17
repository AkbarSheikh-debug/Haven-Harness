import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { projectKey } from '@hn/config';
import { git } from '@hn/operations';
import { LEAD } from '@hn/orchestrate';
import { KeyStore } from '@hn/provider';
import type { ApprovalCard } from '@hn/security';
import { loadOrCreateLogKey, parseLog } from '@hn/session';
import { openSession } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const MEMBERS = Array.from({ length: 16 }, (_, i) => `m${i + 1}`);
/** m13 to m16 all edit the same line of shared.txt: three of them must conflict. */
const shared = (name: string) => Number(name.slice(1)) > 12;

let inboxHeld: (() => void) | null = null;

describe('agent teams through the real stack', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI(async (request) => {
      const system = String(request.messages[0]?.content ?? '');
      if (!system.includes('You are a worker')) return { text: 'lead' };
      const brief = String(request.messages.find((message) => message.role === 'user' && String(message.content).includes('You are member'))?.content ?? '');
      const name = /You are member (\w+)/.exec(brief)?.[1] ?? 'm0';
      const id = /task (t\d+)/.exec(brief)?.[1] ?? 't0';
      const tools = request.messages.filter((message) => message.role === 'tool').length;
      if (name === 'inbox') {
        if (tools === 0) return { calls: [{ id: 'c', name: 'team_task', args: { action: 'claim', id, revision: 1 } }] };
        if (tools === 1) {
          if (!JSON.stringify(request.messages).includes('MAGIC-INBOX')) await new Promise<void>((resolve) => (inboxHeld = resolve));
          return { text: 'waiting' };
        }
        return { text: 'done' };
      }
      const file = shared(name) ? 'shared.txt' : `${name}.txt`;
      const steps = shared(name)
        ? [{ name: 'team_task', args: { action: 'claim', id, revision: 1 } }, { name: 'read_file', args: { path: 'shared.txt' } }, { name: 'write_file', args: { path: file, content: `line one\n${name} was here\n` } }, { name: 'team_task', args: { action: 'complete', id, revision: 2 } }]
        : [{ name: 'team_task', args: { action: 'claim', id, revision: 1 } }, { name: 'write_file', args: { path: file, content: `work of ${name}\n` } }, { name: 'team_task', args: { action: 'complete', id, revision: 2 } }];
      const step = steps[tools];
      return step === undefined ? { text: `${name} finished` } : { calls: [{ id: `${name}-${tools}`, ...step }] };
    });
  });
  after(async () => {
    inboxHeld?.();
    await model.close();
  });

  async function project(dir: string): Promise<string> {
    const root = join(await realpath(dir), 'project');
    await mkdir(root);
    await writeFile(join(root, 'shared.txt'), 'line one\nline two\n');
    await git(['init', '--quiet', '-b', 'main'], { cwd: root });
    await git(['add', '-A'], { cwd: root });
    await git(['commit', '--quiet', '-m', 'start'], { cwd: root });
    return root;
  }

  it('16 members on one repo without lost work: 13 merged, 3 conflicts held as tasks with their refs', { timeout: 600_000 }, async (t) => {
    await withTempDir(async (dir) => {
      const root = await project(dir);
      const cards: ApprovalCard[] = [];
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: join(dir, 'home') }, verify: 'off', teams: true, approver: async (card) => (cards.push(card), 'once') }, KeyStore.capture({}));
        const team = session.team;
        assert.ok(team !== null, '--teams gives the root session a team');
        for (const name of MEMBERS) team.apply(LEAD, { kind: 'create', title: `work for ${name}` }, 'model-derived');
        const began = Date.now();
        for (const [index, name] of MEMBERS.entries()) await team.addMember(name, `You are member ${name}. Claim task t${index + 1}, do its work in your folder, then complete it.`);
        assert.equal(await team.idle(540_000), true);
        t.diagnostic(`16 members ran and merged in ${Math.round((Date.now() - began) / 1000)} s`);
        const merges = session.agent.events.filter((event) => event.type === 'team/merge' && event.data['kind'] !== 'start');
        const merged = merges.filter((event) => event.data['kind'] === 'merged').map((event) => String(event.data['member']));
        const conflicts = merges.filter((event) => event.data['kind'] === 'conflict').map((event) => String(event.data['member']));
        const failedMembers = session.agent.events.filter((event) => event.type === 'team/member' && event.data['state'] === 'failed').map((event) => `${String(event.data['name'])} failed: ${String(event.data['why'])}`);
        assert.equal(merged.length, 13, [merges.map((event) => `${String(event.data['kind'])}:${String(event.data['member'])}`).join(' '), ...failedMembers].join('\n'));
        assert.equal(conflicts.length, 3);
        assert.ok(conflicts.every(shared), 'only the members that edited the same line conflicted');
        // Without lost work: every member's change is on main, or held at the ref its conflict task names.
        for (const name of MEMBERS) {
          if (merged.includes(name)) {
            const content = (await git(['show', `HEAD:${shared(name) ? 'shared.txt' : `${name}.txt`}`], { cwd: root })).stdout;
            assert.ok(content.includes(shared(name) ? `${name} was here` : `work of ${name}`), `${name} is on main`);
          } else {
            const task = team.snapshot.tasks.find((candidate) => candidate.title.startsWith('Resolve merge conflict') && candidate.detail.includes(` by ${name} `));
            assert.ok(task?.ref !== undefined, `${name}'s conflict became a task`);
            assert.ok((await git(['show', `${task.ref}:shared.txt`], { cwd: root })).stdout.includes(`${name} was here`), `${name}'s work is at ${task.ref}`);
          }
        }
        assert.equal(team.snapshot.tasks.slice(0, 16).filter((task) => task.status === 'done').length, 16);
        assert.equal(cards.length, 16, 'each member write was approved by the lead person through routing');
        const roster = [...team.roster.values()];
        assert.equal(roster.length, 16);
        assert.ok(roster.every((member) => member.state === 'stopped'));
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });

  it('delivers a lead message to a running member at its next step, carrying its origin', { timeout: 180_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await project(dir);
      const home = join(dir, 'home');
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: home }, verify: 'off', teams: true, approver: async () => 'once' }, KeyStore.capture({}));
        const team = session.team;
        assert.ok(team !== null);
        team.apply(LEAD, { kind: 'create', title: 'inbox' }, 'model-derived');
        inboxHeld = null;
        await team.addMember('inbox', 'You are member inbox. Claim task t1, then wait for a message.');
        for (let i = 0; i < 300 && inboxHeld === null; i += 1) await new Promise((resolve) => setTimeout(resolve, 100));
        assert.ok(inboxHeld !== null, 'the member reached its second model call');
        assert.match(team.message(LEAD, 'inbox', 'MAGIC-INBOX: use the blue config', 'model-derived'), /Delivered to inbox's inbox/);
        await new Promise((resolve) => setTimeout(resolve, 300));
        (inboxHeld as unknown as () => void)();
        assert.equal(await team.idle(120_000), true);
        const key = await loadOrCreateLogKey(join(home, 'log.key'));
        const folder = join(home, 'sessions', projectKey(root), `${session.sessionId}.children`);
        const [child] = await readdir(folder);
        const log = parseLog(await readFile(join(folder, child!)), key);
        const notice = log.events.find((event) => event.type === 'user/message' && event.data['notice'] === true);
        assert.match(String(notice?.data['text']), /Message from lead:[\s\S]*MAGIC-INBOX/);
        assert.equal(notice?.origin, 'model-derived', 'the inbox row keeps the origin of whoever wrote it');
        assert.equal(team.snapshot.tasks[0]?.status, 'open', 'it never completed, so its claim was released when it stopped');
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });
});

describe('a member inbox line', () => {
  it('is never logged as a person, whatever origin the pipe claims', async () => {
    const { inboxOrigin } = await import('@hn/surfaces');
    assert.equal(inboxOrigin('user'), 'child');
    assert.equal(inboxOrigin('human-selected'), 'child');
    assert.equal(inboxOrigin('harness'), 'child');
    assert.equal(inboxOrigin('nonsense'), 'child');
    assert.equal(inboxOrigin('web'), 'web');
    assert.equal(inboxOrigin('model-derived'), 'model-derived');
  });
});
