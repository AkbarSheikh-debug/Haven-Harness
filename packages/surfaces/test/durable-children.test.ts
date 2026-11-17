import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { projectKey } from '@hn/config';
import type { SessionEvent } from '@hn/core';
import { BUILT_IN_ROLES, SubagentManager, type ChildRun, type LaunchSpec, type ManagerOptions } from '@hn/delegate';
import { KeyStore, resolveCaps } from '@hn/provider';
import type { Mode } from '@hn/security';
import { loadOrCreateLogKey, parseLog } from '@hn/session';
import { openSession } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const caps = resolveCaps('fake', { window: 64_000, maxOutput: 8_000 });
const line = (text: string, end = 'done') => `${JSON.stringify({ sessionId: 'c', end, text, usage: { input: 50, output: 5, cacheRead: 0, cacheWrite: 0 }, steps: 1 })}\n`;
const ok = (text: string): ChildRun => ({ code: 0, stdout: line(text), stderr: '', timedOut: false, cancelled: false, logPath: 'l' });
const ev = (seq: number, type: SessionEvent['type'], data: Record<string, unknown>): SessionEvent => ({ seq, ts: new Date().toISOString(), type, origin: 'harness', data });

function setup(over: Partial<ManagerOptions> = {}) {
  const events: SessionEvent[] = [];
  const notices: string[] = [];
  const specs: LaunchSpec[] = [];
  const m = new SubagentManager({
    parentId: 'p',
    nested: false,
    roles: BUILT_IN_ROLES,
    parentMode: () => 'safe' as Mode,
    parentAllow: [],
    parentTools: () => ['read_file', 'edit_file'],
    tier: 2,
    resolveModel: () => ({ model: 'm', caps }),
    launch: async (spec) => (specs.push(spec), ok(`report ${spec.brief}`)),
    record: (type, data) => events.push(ev(events.length + 1, type, data)),
    events: () => events,
    contextTokens: () => 100,
    tainted: () => false,
    notify: (text) => notices.push(text),
    ...over,
  });
  return { m, events, notices, specs };
}

describe('durable children', () => {
  it('a background child returns at once, holds its slot, and its report arrives as a notice', async () => {
    let release: () => void = () => undefined;
    const { m, notices } = setup({ launch: async (spec) => (await new Promise<void>((resolve) => (release = resolve)), ok(`late ${spec.brief}`)) });
    const id = m.background({ agent: 'scout', task: 'look around' }, { start: 'spawn' });
    assert.match(id, /^[0-9a-f-]{36}$/);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(m.activeCount, 1, 'it still holds a slot');
    assert.equal(m.list()[0]?.status, 'running');
    release();
    assert.equal(await m.drain(5_000), true);
    assert.match(notices[0] ?? '', /A background child settled \(scout [0-9a-f-]+\)\.\n<child-report[\s\S]*late look around/);
    assert.equal(m.list()[0]?.status, 'done');
    assert.equal(m.activeCount, 0);
  });

  it('lists children with status and spend, and stops a running one on request', async () => {
    const { m } = setup({
      launch: async (spec) =>
        new Promise<ChildRun>((resolve) => spec.signal.addEventListener('abort', () => resolve({ code: null, stdout: '', stderr: '', timedOut: false, cancelled: true, logPath: 'l' }))),
    });
    const running = m.single({ agent: 'worker', task: 'long job' }, { start: 'spawn' }, new AbortController().signal);
    await new Promise((resolve) => setTimeout(resolve, 10));
    const id = m.list()[0]!.id;
    assert.match(m.describe(), new RegExp(`${id} worker running: long job`));
    assert.equal(m.interrupt(id.slice(0, 8)), true);
    const result = await running;
    assert.equal(result.cancelled, true);
    assert.equal(m.list()[0]?.status, 'cancelled');
    assert.equal(m.interrupt(id), false, 'a stopped child is not running');
  });

  it('send_message wakes the same child on its own log, refuses a running one, and refuses a changed role', async () => {
    const { m, specs } = setup();
    const first = await m.single({ agent: 'scout', task: 'first question' }, { start: 'spawn' }, new AbortController().signal);
    const again = await m.sendMessage(first.childId.slice(0, 10), 'second question', new AbortController().signal);
    assert.equal(typeof again === 'string' ? '' : again.childId, first.childId);
    assert.equal(specs[1]?.resume, true);
    assert.equal(specs[1]?.childId, first.childId);
    assert.equal(specs[1]?.brief, 'second question');
    assert.deepEqual(m.list().map((child) => child.status), ['done']);
    const changed = setup({ roles: BUILT_IN_ROLES.map((role) => (role.name === 'scout' ? { ...role, hash: 'different' } : role)) });
    changed.events.push(ev(1, 'subagent/catalog', { kind: 'spawned', child: first.childId, role: 'scout', roleHash: BUILT_IN_ROLES[0]!.hash, brief: 'x' }));
    changed.events.push(ev(2, 'subagent/catalog', { kind: 'settled', child: first.childId, role: 'scout', end: 'done' }));
    await assert.rejects(changed.m.sendMessage(first.childId, 'hi', new AbortController().signal), /role has changed/);
    await assert.rejects(m.sendMessage('nope', 'hi', new AbortController().signal), /no child "nope"/);
  });

  it('after a parent restart, settles each unsettled child from its own log: done and charged, or lost', async () => {
    const childEvents = [ev(1, 'turn/start', {}), ev(2, 'assistant/attempt', { model: 'm', usage: { input: 70, output: 7, cacheRead: 0, cacheWrite: 0 } }), ev(3, 'assistant/message', { text: 'FOUND IT' }), ev(4, 'turn/end', { reason: 'done' })];
    const { m, events } = setup({ childLog: async (id) => (id === 'finished' ? childEvents : null) });
    events.push(ev(1, 'subagent/catalog', { kind: 'spawned', child: 'finished', role: 'scout', roleHash: 'h', brief: 'a', callId: 'call-1' }));
    events.push(ev(2, 'subagent/catalog', { kind: 'spawned', child: 'crashed', role: 'worker', roleHash: 'h', brief: 'b', callId: 'call-2' }));
    const repaired = await m.repairResult('call-1', events);
    assert.equal(repaired?.origin, 'child');
    assert.match(repaired?.content ?? '', /From the child's own log:\n<child-report session="finished" role="scout" end="done">\nFOUND IT/);
    const lost = await m.repairResult('call-2', events);
    assert.equal(lost?.isError, true);
    assert.match(lost?.content ?? '', /Child crashed \(worker\) did not finish .* wake it with send_message/);
    assert.equal(await m.repairResult('other', events), null, 'a call that started no child gets the plain unknown');
    assert.equal(await m.recover(), 2);
    assert.deepEqual(m.list().map((child) => `${child.id}:${child.status}`), ['finished:done', 'crashed:lost']);
    assert.ok(events.some((event) => event.type === 'budget/charge' && event.data['child'] === 'finished'), 'what the finished child spent is charged');
  });
});

describe('killing and resuming through real processes', () => {
  let model: FakeOpenAI;
  let holding: (() => void) | null = null;
  let hold = false;
  let onChildRequest: ((count: number) => void) | null = null;
  let childRequests = 0;
  before(async () => {
    model = await startFakeOpenAI(async (request) => {
      const system = String(request.messages[0]?.content ?? '');
      const last = request.messages.at(-1);
      if (system.includes('You are a scout')) {
        childRequests += 1;
        onChildRequest?.(childRequests);
        if (hold) await new Promise<void>((resolve) => (holding = resolve));
        if (last?.role === 'tool') return { text: `SCOUT: read ${String(last.content).length} chars` };
        if (lastContent(request, 'user').includes('carry on')) return { text: 'SCOUT: resumed and finished' };
        return { calls: [{ id: `r${childRequests}`, name: 'read_file', args: { path: 'a.txt' } }] };
      }
      if (last?.role === 'tool') return { text: 'parent done' };
      const user = lastContent(request, 'user');
      if (user.startsWith('wake ')) return { calls: [{ id: 'w1', name: 'call_tool', args: { name: 'send_message', args: { agent: user.slice(5), message: 'carry on' } } }] };
      return { calls: [{ id: 's1', name: 'subagent', args: { agent: 'scout', task: 'Read a.txt and report.' } }] };
    });
  });
  after(async () => {
    hold = false;
    holding?.();
    await model.close();
  });

  it('a child killed mid-run is resumed with send_message: its log is closed honestly and it finishes', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      await writeFile(join(root, 'a.txt'), 'hello');
      const home = join(root, '.home');
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: home }, verify: 'off' }, KeyStore.capture({}));
        childRequests = 0;
        // Hold the child at its second model call, after its read, then kill its process.
        onChildRequest = (count) => {
          if (count !== 2) return;
          hold = true;
          setTimeout(() => {
            const child = session.subagents.list()[0];
            if (child !== undefined) session.subagents.interrupt(child.id);
          }, 300);
        };
        await session.agent.run('Find out what a.txt says.');
        onChildRequest = null;
        hold = false;
        holding?.();
        const child = session.subagents.list()[0]!;
        assert.equal(child.status, 'cancelled');
        const killed = session.agent.events.find((event) => event.type === 'tool/result');
        assert.match(String(killed?.data['content']), /did not finish: it was stopped/);

        await session.agent.run(`wake ${child.id}`);
        assert.equal(session.subagents.list()[0]?.status, 'done');
        const woke = session.agent.events.filter((event) => event.type === 'tool/result').at(-1);
        assert.match(String(woke?.data['content']), /SCOUT: resumed and finished/);

        const key = await loadOrCreateLogKey(join(home, 'log.key'));
        const childLog = parseLog(await readFile(join(home, 'sessions', projectKey(root), `${session.sessionId}.children`, child.id)), key);
        assert.equal(childLog.trust, 'verified');
        const ends = childLog.events.filter((event) => event.type === 'turn/end').map((event) => event.data['reason']);
        assert.equal(ends.length, 2, 'the killed turn was closed on resume, then the new turn ran');
        assert.notEqual(ends[0], 'done');
        assert.equal(ends[1], 'done');
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });

  it('a parent killed while its child works is repaired from the child log, not with "unknown"', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      await writeFile(join(root, 'a.txt'), 'hello');
      const home = join(root, '.home');
      childRequests = 0;
      const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => name !== 'HN_PARENT_SESSION'));
      const parent = spawn(process.execPath, ['--disable-proto=throw', main, '-p', 'Find out what a.txt says.', '--json', '--model', 'fake', '--base-url', model.url, '--window', '64000', '--verify', 'off'], {
        cwd: root,
        env: { ...env, HN_HOME: home },
        stdio: 'ignore',
      });
      // The child's first model call means the parent is waiting on it: kill the parent alone, not its tree.
      await new Promise<void>((resolve) => {
        onChildRequest = (count) => {
          if (count === 1) {
            parent.kill('SIGKILL');
            resolve();
          }
        };
      });
      onChildRequest = null;
      await new Promise((resolve) => parent.once('exit', resolve));
      const folder = join(home, 'sessions', projectKey(root));
      const sessionId = (await readdir(folder)).find((name) => !name.includes('.'))!;
      const key = await loadOrCreateLogKey(join(home, 'log.key'));
      const childFolder = join(folder, `${sessionId}.children`);
      let finished = false;
      for (let i = 0; i < 200 && !finished; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        for (const name of await readdir(childFolder).catch(() => [] as string[])) {
          const log = parseLog(await readFile(join(childFolder, name)), key);
          if (log.events.some((event) => event.type === 'turn/end' && event.data['reason'] === 'done')) finished = true;
        }
      }
      assert.ok(finished, 'the child finished after its parent died');
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: home }, verify: 'off', sessionId }, KeyStore.capture({}));
        const result = session.agent.events.find((event) => event.type === 'tool/result');
        assert.equal(result?.data['outcome'], 'recovered');
        assert.equal(result?.origin, 'child');
        assert.match(String(result?.data['content']), /From the child's own log:\n<child-report[^>]*role="scout" end="done">\nSCOUT: read/);
        assert.equal(session.subagents.list()[0]?.status, 'done', 'the catalog was settled from the child log too');
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });
});

describe('a headless run with a background child', () => {
  it('waits for the child, then gives the model one more turn to use its report', { timeout: 120_000 }, async () => {
    const model = await startFakeOpenAI((request) => {
      const system = String(request.messages[0]?.content ?? '');
      if (system.includes('You are a scout')) return { text: 'BACKGROUND-SCOUT-REPORT' };
      const all = JSON.stringify(request.messages);
      if (all.includes('Background children have settled')) return { text: all.includes('BACKGROUND-SCOUT-REPORT') ? 'FINAL: used the report' : 'FINAL: no report' };
      if (request.messages.at(-1)?.role === 'tool') return { text: 'Started it; ending my turn.' };
      return { calls: [{ id: 'b1', name: 'subagent', args: { agent: 'scout', task: 'Look around.', background: true } }] };
    });
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const out: string[] = [];
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const { runPrint } = await import('@hn/surfaces');
        const code = await runPrint({ workdir: root, mode: 'read-only', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: join(root, '.home') }, verify: 'off', prompt: 'Start a background scout.', json: true }, KeyStore.capture({}), (text) => (out.push(text), true));
        assert.equal(code, 0);
        const report = JSON.parse(out.join('').trim().split('\n').at(-1) ?? '{}') as { text: string };
        assert.equal(report.text, 'FINAL: used the report');
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
        await model.close();
      }
    });
  });
});
