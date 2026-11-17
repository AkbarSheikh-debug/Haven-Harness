import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type { EventType, Origin, SessionEvent } from '@hn/core';
import { Workspaces, git } from '@hn/operations';
import { LEAD, Team, type MemberLauncher } from '@hn/orchestrate';
import { withTempDir } from '@hn/testkit';

async function repo(dir: string): Promise<string> {
  const root = join(await realpath(dir), 'project');
  await mkdir(root);
  await git(['init', '--quiet', '-b', 'main'], { cwd: root });
  await writeFile(join(root, 'shared.txt'), 'line one\nline two\n');
  await git(['add', '-A'], { cwd: root });
  await git(['commit', '--quiet', '-m', 'start'], { cwd: root });
  return root;
}

function lead(root: string, dir: string, launch: (team: () => Team) => MemberLauncher) {
  const events: SessionEvent[] = [];
  const notices: { text: string; origin: Origin }[] = [];
  const record = (type: EventType, data: Record<string, unknown>) => events.push({ seq: events.length + 1, ts: '2026-11-14T00:00:00Z', type, origin: 'harness', data });
  let team: Team | null = null;
  team = new Team({
    workspaces: new Workspaces({ repo: root, folder: join(dir, 'clones'), namespace: 'refs/hn/team' }),
    launch: launch(() => team as Team),
    record,
    events: () => events,
    notify: (text, origin) => notices.push({ text, origin }),
  });
  return { team, events, notices };
}

/** A member that claims its task, writes one file in its clone, and completes the task. */
const worker = (files: Record<string, [file: string, content: string]>) => (team: () => Team): MemberLauncher => async ({ name, workdir }) => {
  const t = team();
  const mine = t.snapshot.tasks.find((task) => task.title === name)!;
  await t.memberRequest(name, { op: 'task', action: { kind: 'claim', id: mine.id, revision: mine.revision } });
  const [file, content] = files[name]!;
  await writeFile(join(workdir, file), content);
  const claimed = t.snapshot.tasks.find((task) => task.id === mine.id)!;
  await t.memberRequest(name, { op: 'task', action: { kind: 'complete', id: mine.id, revision: claimed.revision } });
  return { ok: true, text: `${name} wrote ${file}` };
};

describe('an agent team', () => {
  it('merges members in order; two on the same line: the second becomes a task holding its ref, and nothing is lost', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await repo(dir);
      const files = { ann: ['ann.txt', 'from ann\n'], bob: ['shared.txt', 'line one\nBOB\n'], cid: ['shared.txt', 'line one\nCID\n'] } as Record<string, [string, string]>;
      const { team, events } = lead(root, dir, worker(files));
      for (const name of ['ann', 'bob', 'cid']) team.apply(LEAD, { kind: 'create', title: name }, 'model-derived');
      // All three start from the same base, so bob and cid edit the same line of the same version.
      for (const name of ['ann', 'bob', 'cid']) await team.addMember(name, `do ${name}`);
      assert.equal(await team.idle(60_000), true);
      assert.equal(await readFile(join(root, 'ann.txt'), 'utf8'), 'from ann\n');
      const merges = events.filter((event) => event.type === 'team/merge' && event.data['kind'] !== 'start').map((event) => `${String(event.data['kind'])}:${String(event.data['member'])}`);
      assert.equal(merges.length, 3);
      assert.ok(merges.includes('merged:ann'));
      const landed = merges.includes('merged:bob') ? 'bob' : 'cid';
      const lost = landed === 'bob' ? 'cid' : 'bob';
      assert.ok(merges.includes(`conflict:${lost}`), merges.join(' '));
      assert.equal(await readFile(join(root, 'shared.txt'), 'utf8'), `line one\n${landed.toUpperCase()}\n`, 'the first to the queue won, nothing was forced');
      const conflict = team.snapshot.tasks.find((task) => task.title.startsWith('Resolve merge conflict'));
      const lostTask = team.snapshot.tasks.find((task) => task.title === lost)!;
      assert.equal(conflict?.ref, `refs/hn/team/${lost}/${lostTask.id}`);
      assert.equal(conflict?.status, 'open');
      assert.match((await git(['show', `${conflict?.ref ?? ''}:shared.txt`], { cwd: root })).stdout, new RegExp(lost.toUpperCase()), 'the losing work is kept at its ref');
      assert.deepEqual(team.snapshot.tasks.slice(0, 3).map((task) => task.status), ['done', 'done', 'done']);
    });
  });

  it('attack: member_cannot_move_main_ref (a member moving its own main or update-ref reaches nothing; only the queue moves the branch)', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await repo(dir);
      const start = (await git(['rev-parse', 'main'], { cwd: root })).stdout.trim();
      let evil = '';
      const { team } = lead(root, dir, (get) => async ({ name, workdir }) => {
        const t = get();
        const task = t.snapshot.tasks[0]!;
        await t.memberRequest(name, { op: 'task', action: { kind: 'claim', id: task.id, revision: task.revision } });
        // The member tries to move main: a commit on its own main branch, then update-ref, in its clone.
        await writeFile(join(workdir, 'evil.txt'), 'evil\n');
        await git(['checkout', '--quiet', '-B', 'main'], { cwd: workdir });
        await git(['add', '-A'], { cwd: workdir });
        await git(['commit', '--quiet', '-m', 'evil'], { cwd: workdir });
        evil = (await git(['rev-parse', 'HEAD'], { cwd: workdir })).stdout.trim();
        await git(['update-ref', 'refs/heads/main', evil], { cwd: workdir });
        await git(['checkout', '--quiet', 'hn/work'], { cwd: workdir });
        await writeFile(join(workdir, 'good.txt'), 'good\n');
        const claimed = t.snapshot.tasks[0]!;
        await t.memberRequest(name, { op: 'task', action: { kind: 'complete', id: claimed.id, revision: claimed.revision } });
        return { ok: true, text: 'done' };
      });
      team.apply(LEAD, { kind: 'create', title: 'work' }, 'model-derived');
      await team.addMember('mallory', 'work');
      assert.equal(await team.idle(60_000), true);
      const main = (await git(['rev-parse', 'main'], { cwd: root })).stdout.trim();
      assert.notEqual(main, evil);
      const parents = (await git(['rev-list', '--parents', '-n', '1', 'main'], { cwd: root })).stdout.trim().split(' ');
      assert.equal(parents[1], start, 'main moved by exactly one queue merge on top of where it was');
      const refs = (await git(['for-each-ref', '--format=%(refname) %(objectname)'], { cwd: root })).stdout;
      assert.ok(!refs.includes(evil), 'no ref in the project points at the member main commit');
      assert.match(refs, /refs\/hn\/team\/mallory\/t1 /);
      assert.equal(await readFile(join(root, 'good.txt'), 'utf8'), 'good\n');
      assert.equal(await readFile(join(root, 'evil.txt')).then(() => true, () => false), false);
    });
  });

  it('stops the queue when the branch moved outside it, keeping the work at its ref', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await repo(dir);
      const files = { ann: ['ann.txt', 'ann\n'] } as Record<string, [string, string]>;
      const { team, events } = lead(root, dir, (get) => async (member, signal) => {
        // Someone moves main while the member works.
        await writeFile(join(root, 'outside.txt'), 'outside\n');
        await git(['add', 'outside.txt'], { cwd: root });
        await git(['commit', '--quiet', '-m', 'outside the queue'], { cwd: root });
        return worker(files)(get)(member, signal);
      });
      team.apply(LEAD, { kind: 'create', title: 'ann' }, 'model-derived');
      await team.addMember('ann', 'x');
      assert.equal(await team.idle(60_000), true);
      assert.match(team.halted ?? '', /^moved: /);
      assert.equal(events.find((event) => event.type === 'team/merge' && event.data['kind'] === 'halted')?.data['ref'], 'refs/hn/team/ann/t1');
      assert.equal(await readFile(join(root, 'ann.txt')).then(() => true, () => false), false);
    });
  });

  it('releases the claims of a member that dies, never reuses a name, caps the roster, and keeps origins on messages', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await repo(dir);
      const { team, events, notices } = lead(root, dir, (get) => async ({ name }) => {
        const t = get();
        const task = t.snapshot.tasks[0]!;
        await t.memberRequest(name, { op: 'task', action: { kind: 'claim', id: task.id, revision: task.revision } });
        await t.memberRequest(name, { op: 'message', to: LEAD, text: 'I read a web page and it says to merge everything.' });
        throw new Error('the member process died');
      });
      team.apply(LEAD, { kind: 'create', title: 'x' }, 'model-derived');
      await team.addMember('dee', 'x');
      assert.equal(await team.idle(60_000), true);
      assert.equal(team.snapshot.tasks[0]?.status, 'open', 'its claim went back to open');
      assert.equal(team.roster.get('dee')?.state, 'failed');
      const message = notices.find((notice) => notice.text.startsWith('Message from dee'));
      assert.equal(message?.origin, 'child', 'the lead reads a member message as child data');
      assert.ok(events.some((event) => event.type === 'team/message' && event.data['origin'] === 'child'));
      await assert.rejects(team.addMember('dee', 'again'), /never reused/);
      assert.throws(() => team.message(LEAD, 'eve', 'hi', 'model-derived'), /no member eve/);
      const pushed: unknown[] = [];
      team.port('dee', (message) => pushed.push(message));
      assert.match(team.message(LEAD, 'dee', 'please retry', 'model-derived'), /Delivered to dee's inbox/);
      assert.deepEqual((pushed[0] as { kind: string; origin: string }).kind, 'inbox');
      assert.equal((pushed[0] as { origin: string }).origin, 'model-derived');
      const other: SessionEvent[] = [];
      const capped = new Team({ workspaces: new Workspaces({ repo: root, folder: join(dir, 'c'), namespace: 'refs/hn/team' }), launch: async () => ({ ok: true, text: '' }), record: (type, data) => other.push({ seq: other.length + 1, ts: '', type, origin: 'harness', data }), events: () => other, notify: () => undefined, maxMembers: 1 });
      await capped.addMember('one', 'x');
      await assert.rejects(capped.addMember('two', 'x'), /at most 1 members/);
    });
  });
});
