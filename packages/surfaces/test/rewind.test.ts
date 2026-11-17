import assert from 'node:assert/strict';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import type { SessionEvent } from '@hn/core';
import { KeyStore } from '@hn/provider';
import { openSession, planRewind, rewindPoints, runRewind, type CliOptions } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

describe('the rewind plan', () => {
  it('trusts a checkpoint only when no other change came before it after the rewind point', () => {
    let seq = 0;
    const row = (type: SessionEvent['type'], data: Record<string, unknown>, origin: SessionEvent['origin'] = 'harness'): SessionEvent => ({ seq: (seq += 1), ts: '2026-11-14T00:00:00Z', type, origin, data });
    const base = (): SessionEvent[] => {
      seq = 0;
      return [row('turn/start', {}), row('user/message', { text: 'first' }, 'user'), row('turn/end', { reason: 'done' }), row('turn/start', {}), row('user/message', { text: 'second' }, 'user')];
    };
    const change = (tool: string) => row('audit/decision', { tool, decision: 'allowed-once', effect: 'reversible' });
    const exactOne = [...base(), change('write_file'), row('checkpoint/create', { seq: 4 }), row('turn/end', { reason: 'done' })];
    const planned = planRewind(exactOne, 2);
    assert.ok(typeof planned !== 'string');
    assert.equal(planned.exact, true);
    assert.equal(planned.checkpoint, 4);
    const lateCheckpoint = [...base(), change('write_file'), change('edit_file'), row('checkpoint/create', { seq: 5 }), row('turn/end', { reason: 'done' })];
    const late = planRewind(lateCheckpoint, 2);
    assert.ok(typeof late !== 'string');
    assert.equal(late.exact, false, 'a change before the first checkpoint means the checkpoint is not the state at the rewind point');
  });
});

describe('/rewind', () => {
  let model: FakeOpenAI;
  before(async () => {
    // Each turn reads a.txt, writes the version the user names, and turn 1 also writes a memory note.
    model = await startFakeOpenAI((request) => {
      const asked = request.messages.filter((message) => message.role === 'user').map((message) => String(message.content)).reverse().find((text) => /write (v\d)/.test(text)) ?? '';
      const version = /write (v\d)/.exec(asked)?.[1] ?? 'v?';
      const sinceUser = request.messages.slice(request.messages.findLastIndex((message) => message.role === 'user' && /write v\d/.test(String(message.content))) + 1);
      const tools = sinceUser.filter((message) => message.role === 'tool').length;
      if (tools === 0) return { calls: [{ id: `r-${version}`, name: 'read_file', args: { path: 'a.txt' } }] };
      if (tools === 1) return { calls: [{ id: `w-${version}`, name: 'write_file', args: { path: 'a.txt', content: `${version}\n` } }] };
      if (tools === 2 && version === 'v1') return { calls: [{ id: 'm1', name: 'memory', args: { action: 'add', text: 'We are writing versions of a.txt.' } }] };
      return { text: `wrote ${version}` };
    });
  });
  after(async () => {
    await model.close();
  });

  async function twoTurns(root: string) {
    await writeFile(join(root, 'a.txt'), 'v0\n');
    await writeFile(join(root, 'b.txt'), 'b original\n');
    const options: CliOptions = { workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: join(root, '.home') }, verify: 'off', approver: async () => 'once' };
    const session = await openSession(options, KeyStore.capture({}));
    await session.agent.run('Please write v1 into a.txt.');
    await session.agent.run('Now write v2 into a.txt.');
    assert.equal(await readFile(join(root, 'a.txt'), 'utf8'), 'v2\n');
    // The person edits another file by hand.
    await writeFile(join(root, 'b.txt'), 'b edited by the person\n');
    return { session, options };
  }

  it('lists turns, refuses an inexact checkpoint, and rewinds to before turn 1: files back, hand edits kept, old session kept, memory listed as not undone', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const { session, options } = await twoTurns(root);
        assert.deepEqual(rewindPoints(session.agent.events).map((point) => point.text), ['Please write v1 into a.txt.', 'Now write v2 into a.txt.']);
        const second = planRewind(session.agent.events, 2);
        assert.ok(typeof second !== 'string');
        assert.equal(second.exact, false, 'turn 2 wrote in a folder that already had a checkpoint, so none sits exactly before it');
        assert.equal(planRewind(session.agent.events, 9), 'There is no turn 9 to go back to.');

        const out: string[] = [];
        const next = await runRewind(session, options, KeyStore.capture({}), { out: (text) => out.push(text) }, 1, false);
        assert.ok(next !== null);
        const said = out.join('');
        assert.match(said, /Restored 1 file\(s\)/);
        assert.match(said, /your own edits are kept/);
        assert.match(said, /Not undone, because a rewind cannot take them back:\n  - a memory write to notes/);
        assert.equal(await readFile(join(root, 'a.txt'), 'utf8'), 'v0\n');
        assert.equal(await readFile(join(root, 'b.txt'), 'utf8'), 'b edited by the person\n');
        assert.equal(next.agent.events.filter((event) => event.type === 'turn/start').length, 0, 'the fork ends before turn 1');
        assert.equal(next.agent.events.find((event) => event.type === 'session/link')?.data['kind'], 'rewind');
        assert.equal(next.agent.events.find((event) => event.type === 'session/link')?.data['parent'], session.sessionId);
        await next.agent.close();
        await next.close();
        const old = await openSession({ ...options, sessionId: session.sessionId }, KeyStore.capture({}));
        assert.equal(old.agent.events.filter((event) => event.type === 'turn/start').length, 2, 'the old session is whole');
        assert.ok(old.agent.events.some((event) => event.type === 'session/link' && event.data['kind'] === 'rewound-to'));
        await old.agent.close();
        await old.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });

  it('with --all restores the person edits too, and says files were not restored when no exact checkpoint exists', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const first = await twoTurns(root);
        const out: string[] = [];
        const inexact = await runRewind(first.session, first.options, KeyStore.capture({}), { out: (text) => out.push(text) }, 2, false);
        assert.ok(inexact !== null);
        assert.match(out.join(''), /files were NOT restored/);
        assert.equal(await readFile(join(root, 'a.txt'), 'utf8'), 'v2\n', 'nothing was guessed');
        await inexact.agent.close();
        await inexact.close();

        const again = await openSession({ ...first.options, sessionId: first.session.sessionId }, KeyStore.capture({}));
        const all = await runRewind(again, first.options, KeyStore.capture({}), { out: () => undefined }, 1, true);
        assert.ok(all !== null);
        assert.equal(await readFile(join(root, 'a.txt'), 'utf8'), 'v0\n');
        assert.equal(await readFile(join(root, 'b.txt'), 'utf8'), 'b original\n', '--all restores everything the checkpoint holds');
        await all.agent.close();
        await all.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });
});
