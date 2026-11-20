import assert from 'node:assert/strict';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { projectKey } from '@hn/config';
import { parseLog, type LoadedLog } from '@hn/session';
import { MAX_DETAIL, MAX_STEPS, SESSION_ID, buildReplay, listSessions, loadReplay, type Replay, type ReplayStep } from '@hn/surfaces';
import { withTempDir, type FakeOpenAI } from '@hn/testkit';
import { forgedFrame, frameRanges, readKey, recordSession, startScriptedModel, wrongKey, type Recorded } from './replay-fixture.ts';

const find = (replay: Replay, pattern: RegExp): ReplayStep => {
  const step = replay.steps.find((candidate) => pattern.test(candidate.title));
  assert.ok(step !== undefined, `no step matches ${pattern}`);
  return step;
};

describe('the replay of a session', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startScriptedModel();
  });
  after(async () => {
    await model.close();
  });

  /** Records a real session in a fresh folder, and runs `body` with it. */
  const withSession = async (body: (recorded: Recorded, replay: Replay) => Promise<void>): Promise<void> =>
    withTempDir(async (dir) => {
      const recorded = await recordSession(await realpath(dir), model);
      const loaded = await loadReplay(recorded.sessionId, recorded.project, { HN_HOME: recorded.home });
      assert.equal(loaded.kind, 'replay');
      await body(recorded, (loaded as { replay: Replay }).replay);
    });

  it('walks a real session: every turn, the gate\'s decisions, each approval and who answered, the taint change, the files, in order', { timeout: 120_000 }, async () => {
    await withSession(async (_recorded, replay) => {
      assert.equal(replay.trust, 'verified');
      assert.equal(replay.crashed, false);
      assert.equal(replay.truncated, false);
      assert.ok(replay.steps.length > 20);
      assert.deepEqual(
        replay.steps.map((step) => step.index),
        replay.steps.map((_, index) => index),
      );
      for (let i = 1; i < replay.steps.length; i += 1) assert.ok((replay.steps[i] as ReplayStep).seq > (replay.steps[i - 1] as ReplayStep).seq, 'steps are not in log order');
      assert.match(find(replay, /^Where it runs/).title, /no box \(local, tier 2\): the permission gate was the boundary/);
      assert.equal(find(replay, /^The user said/).detail, 'do the work');
      // The gate allowed the write, and a person allowed it first.
      assert.ok(replay.steps.some((step) => step.kind === 'gate' && step.tone === 'ok' && step.title.startsWith('Gate allowed write_file')));
      assert.ok(replay.steps.some((step) => step.kind === 'approval' && step.tone === 'ok' && step.title === 'Allowed once by human'));
      // The jail refused one call, and the person refused another: two refusals, each with its reason.
      const refusals = replay.steps.filter((step) => step.kind === 'gate' && step.tone === 'refused');
      assert.equal(refusals.length, 2);
      assert.match(refusals[0]?.title ?? '', /REFUSED read_file at the path-jail step/);
      assert.match(refusals[0]?.detail ?? '', /outside the project/);
      assert.match(refusals[1]?.title ?? '', /REFUSED bash at the guardian-or-human step/);
      assert.match(refusals[1]?.detail ?? '', /The user said no/);
      assert.ok(replay.steps.some((step) => step.kind === 'approval' && step.tone === 'refused' && step.title === 'Denied by human'));
      // Untrusted input entered once, after the first command's output came back.
      const taint = find(replay, /^Untrusted input entered/);
      assert.match(taint.detail ?? '', /an untrusted tool-output row entered/);
      assert.equal(replay.totals.untrustedAt, taint.index);
      assert.equal(replay.totals.untrustedAt !== null && (replay.steps[replay.totals.untrustedAt - 1] as ReplayStep).state.untrusted, false, 'the state before the taint step already said untrusted');
      assert.equal(taint.state.untrusted, true);
      assert.equal(replay.totals.calls, 6);
      assert.equal(replay.totals.refused, 2);
      assert.equal(replay.totals.approvalsAsked, 5);
      assert.equal(replay.totals.approvalsDenied, 1);
      assert.deepEqual(replay.totals.files, ['new.txt']);
    });
  });

  it('shows a file change as a diff of what the model asked for, and counts it only when it was applied', { timeout: 120_000 }, async () => {
    await withSession(async (_recorded, replay) => {
      const write = replay.steps.find((step) => step.kind === 'call' && step.diff?.kind === 'write');
      assert.deepEqual(write?.diff, { path: 'new.txt', kind: 'write', before: null, after: 'hello\n', cut: false });
      const edit = replay.steps.find((step) => step.kind === 'call' && step.diff?.kind === 'edit');
      assert.deepEqual(edit?.diff, { path: 'new.txt', kind: 'edit', before: 'hello', after: 'hello world', cut: false });
      // The count of files changed moves at the result, not at the request.
      assert.equal((write as ReplayStep).state.filesChanged, 0);
      const wrote = replay.steps.find((step) => step.kind === 'result' && step.callId === 'w1');
      assert.equal(wrote?.state.filesChanged, 1);
      assert.equal(replay.steps.at(-1)?.state.filesChanged, 2, 'the edit was not counted');
      // A refused read is not a file change and carries no diff.
      assert.equal(replay.steps.find((step) => step.callId === 'r1' && step.kind === 'call')?.diff, undefined);
    });
  });

  it('carries the running state to each step: mode, box, calls, refusals and approvals so far', { timeout: 120_000 }, async () => {
    await withSession(async (_recorded, replay) => {
      const last = replay.steps.at(-1) as ReplayStep;
      assert.equal(last.state.calls, 6);
      assert.equal(last.state.refused, 2);
      assert.equal(last.state.approvalsAsked, 5);
      assert.equal(last.state.approvalsDenied, 1);
      assert.equal(last.state.untrusted, true);
      assert.match(last.state.box ?? '', /^no box \(local, tier 2\)/);
      const first = replay.steps[0] as ReplayStep;
      assert.equal(first.state.calls, 0);
      assert.equal(first.state.untrusted, false);
      // The state only ever moves forward for the counts.
      for (let i = 1; i < replay.steps.length; i += 1) {
        const a = (replay.steps[i - 1] as ReplayStep).state;
        const b = (replay.steps[i] as ReplayStep).state;
        assert.ok(b.calls >= a.calls && b.refused >= a.refused && b.approvalsAsked >= a.approvalsAsked && b.filesChanged >= a.filesChanged);
      }
    });
  });

  it('writes hidden characters out where a person judges a command, instead of stripping them, and never carries a raw escape or direction mark', { timeout: 120_000 }, async () => {
    await withSession(async (_recorded, replay) => {
      const call = replay.steps.find((step) => step.kind === 'call' && step.callId === 'b4');
      assert.ok(call !== undefined);
      assert.match(call.detail ?? '', /\\u\{202e\}evil\\u\{200b\}\\u\{1b\}\]52;c;AAAA\\u\{7\}/);
      assert.match(call.detail ?? '', /<img src=x onerror=alert\(1\)><script>alert\(2\)<\/script>/, 'the text itself is kept, as text');
      for (const step of replay.steps) {
        const everything = JSON.stringify([step.title, step.detail, step.diff]);
        assert.doesNotMatch(everything, /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f‪-‮⁦-⁩​-‏]/, `step ${step.index} carries a hidden character`);
      }
    });
  });

  it('attack: forged_log_replay_refused - refuses a log with one byte changed, and shows nothing at all of what it held', { timeout: 120_000 }, async () => {
    await withSession(async (recorded) => {
      const bytes = await readFile(recorded.file);
      const ranges = frameRanges(bytes);
      assert.ok(ranges.length >= 3, 'the log needs several frames for the tests below');
      const key = await readKey(recorded.home);
      const refusal = (replay: Replay, why: string): void => {
        assert.equal(replay.trust, 'refused', why);
        assert.deepEqual(replay.steps, [], `${why}: steps were shown from a log that does not verify`);
        assert.equal(replay.events, 0, why);
        assert.deepEqual(replay.totals.files, [], why);
        assert.match(replay.reason ?? '', /does not verify/, why);
        assert.doesNotMatch(JSON.stringify(replay), /new\.txt|node --version|do the work/, `${why}: the refusal leaks what the log held`);
      };
      const open = (changed: Buffer, useKey = key): Replay => buildReplay(parseLog(changed, useKey), 'x');

      // One byte flipped in the middle of a frame's payload, and one in a MAC.
      const flipped = Buffer.from(bytes);
      const mid = Math.floor(((ranges[1] as { start: number }).start + (ranges[1] as { end: number }).end) / 2);
      flipped.writeUInt8(flipped.readUInt8(mid) ^ 0xff, mid);
      refusal(open(flipped), 'a changed byte');
      const mac = Buffer.from(bytes);
      mac.writeUInt8(mac.readUInt8((ranges[0] as { start: number }).start + 20) ^ 0x01, (ranges[0] as { start: number }).start + 20);
      refusal(open(mac), 'a changed MAC');

      // A whole frame taken out of the middle (the chain breaks), two frames swapped, and one repeated.
      const piece = (index: number): Buffer => bytes.subarray((ranges[index] as { start: number }).start, (ranges[index] as { end: number }).end);
      const without = Buffer.concat(ranges.flatMap((_, index) => (index === 1 ? [] : [piece(index)])));
      refusal(open(without), 'a removed frame');
      const swapped = Buffer.concat(ranges.map((_, index) => piece(index === 1 ? 2 : index === 2 ? 1 : index)));
      refusal(open(swapped), 'two frames swapped');
      const repeated = Buffer.concat([...ranges.map((_, index) => piece(index)), piece(1)]);
      refusal(open(repeated), 'a repeated frame');

      // A frame added at the end by someone without the key, however well it is formed.
      refusal(open(Buffer.concat([bytes, forgedFrame(Buffer.from('{"seq":999}\n'))])), 'a frame with a made-up MAC');
      // Not a log at all, an empty file's opposite: noise.
      refusal(open(Buffer.from('this is not a log')), 'noise');
      // The right bytes, the wrong key.
      refusal(open(bytes, wrongKey(key)), 'the wrong key');
      // The unchanged log still opens, so the refusals above are about the changes.
      assert.equal(open(bytes).trust, 'verified');
    });
  });

  it('shows a log that ends part-way through a record as what it is, a crash, and still shows only what verified', { timeout: 120_000 }, async () => {
    await withSession(async (recorded) => {
      const bytes = await readFile(recorded.file);
      const ranges = frameRanges(bytes);
      const cutAt = (ranges.at(-1) as { end: number }).end - 5;
      const replay = buildReplay(parseLog(bytes.subarray(0, cutAt), await readKey(recorded.home)), 'x');
      assert.equal(replay.trust, 'verified');
      assert.equal(replay.crashed, true);
      assert.ok(replay.steps.length > 0);
    });
  });

  it('opens a session by id from the project\'s own folder only: an id that is not a session id, or a path, finds nothing', { timeout: 120_000 }, async () => {
    await withSession(async (recorded) => {
      const env = { HN_HOME: recorded.home };
      assert.equal((await loadReplay(recorded.sessionId, recorded.project, env)).kind, 'replay');
      for (const id of ['../log.key', '..', '.', 'a/b', 'a\\b', `${recorded.sessionId}/../${recorded.sessionId}`, 'x'.repeat(65), '', 'no such session', '%2e%2e', 'C:evil']) {
        assert.equal((await loadReplay(id, recorded.project, env)).kind, 'missing', JSON.stringify(id));
      }
      assert.equal((await loadReplay(recorded.sessionId, join(recorded.project, 'other'), env)).kind, 'missing', 'a session opened from another project');
      const listed = await listSessions(recorded.project, env);
      assert.deepEqual(
        listed.map((entry) => entry.id),
        [recorded.sessionId],
      );
      assert.deepEqual(await listSessions(join(recorded.project, 'other'), env), []);
      for (const entry of listed) assert.match(entry.id, SESSION_ID);
    });
  });

  it('says a missing log key is missing, never a verified replay', { timeout: 120_000 }, async () => {
    await withSession(async (recorded) => {
      await writeFile(join(recorded.home, 'log.key'), 'x');
      const loaded = await loadReplay(recorded.sessionId, recorded.project, { HN_HOME: recorded.home });
      assert.ok(loaded.kind === 'replay' && loaded.replay.trust === 'refused', 'a log was trusted with a key that is not the one that wrote it');
    });
  });
});

describe('the replay of a very large or odd log', () => {
  const header = { format: 'hn-log' as const, version: 1, sessionId: 's', createdAt: '2026-01-01T00:00:00.000Z' };
  const verified = (events: LoadedLog['events']): LoadedLog => ({ header, events, trust: 'verified', validEnd: 0, lastMac: Buffer.alloc(32), tailDropped: false });
  const event = (seq: number, type: string, data: Record<string, unknown>, origin = 'harness') => ({ seq, ts: '2026-01-01T00:00:00.000Z', type, origin, data }) as LoadedLog['events'][number];

  it('stops at the step limit and says so, rather than building an unbounded answer', () => {
    const events = Array.from({ length: MAX_STEPS + 50 }, (_, index) => event(index + 1, 'turn/start', { turnId: String(index) }));
    const replay = buildReplay(verified(events), 's');
    assert.equal(replay.steps.length, MAX_STEPS);
    assert.equal(replay.truncated, true);
    assert.equal(replay.events, MAX_STEPS + 50);
  });

  it('cuts a huge command, a huge result and a huge diff, and says each was cut', () => {
    const big = 'x'.repeat(MAX_DETAIL * 4);
    const replay = buildReplay(
      verified([
        event(1, 'assistant/message', { text: '', toolCalls: [{ id: 'c1', name: 'bash', args: { command: big } }, { id: 'c2', name: 'write_file', args: { path: 'a.txt', content: big } }] }, 'model-derived'),
        event(2, 'tool/result', { callId: 'c1', content: big, isError: false }),
      ]),
      's',
    );
    for (const step of replay.steps) {
      assert.ok((step.detail?.length ?? 0) <= MAX_DETAIL + 3, `step ${step.index} detail is ${step.detail?.length} long`);
      assert.ok(step.title.length <= 210);
      if ((step.detail?.length ?? 0) > 100) assert.equal(step.detailCut, true, `step ${step.index} was not marked cut`);
    }
    const diff = replay.steps.find((step) => step.diff !== undefined)?.diff;
    assert.ok(diff !== undefined && diff.cut && diff.after.length <= 3_003);
  });

  it('survives events with the wrong shapes, with nothing thrown and nothing invented', () => {
    const replay = buildReplay(
      verified([
        event(1, 'assistant/message', { text: 5, toolCalls: 'no' }, 'model-derived'),
        event(2, 'assistant/message', { text: '', toolCalls: [null, 7, { id: 1 }, { id: 'a', name: 'bash', args: 'nope' }] }, 'model-derived'),
        event(3, 'audit/decision', { callId: 9, tool: {}, decision: 'rejected' }),
        event(4, 'approval/decided', { answer: {}, by: [] }),
        event(5, 'tool/result', { callId: 'nothing', content: 3, isError: 'yes' }),
        event(6, 'taint/change', { untrusted: 'true' }),
      ]),
      's',
    );
    assert.equal(replay.trust, 'verified');
    assert.ok(replay.steps.every((step) => typeof step.title === 'string'));
    assert.deepEqual(replay.totals.files, []);
  });

  it('counts a file change only when the write went through: a refused or failed write, and a result with no request, change nothing', () => {
    const write = (id: string): LoadedLog['events'][number] => event(1, 'assistant/message', { text: '', toolCalls: [{ id, name: 'write_file', args: { path: id + '.txt', content: 'x' } }] }, 'model-derived');
    const replay = buildReplay(
      verified([
        write('failed'),
        event(2, 'tool/result', { callId: 'failed', content: 'disk full', isError: true }),
        write('refused'),
        event(3, 'audit/decision', { callId: 'refused', tool: 'write_file', decision: 'rejected', step: 'path-jail', reason: 'no' }),
        event(4, 'tool/result', { callId: 'refused', content: 'no', isError: false }),
        write('fine'),
        event(5, 'audit/decision', { callId: 'fine', tool: 'write_file', decision: 'allowed-once', step: 'allowed', effect: 'reversible' }),
        event(6, 'tool/result', { callId: 'fine', content: 'Created fine.txt.', isError: false }),
        event(7, 'tool/result', { callId: 'never-asked-for', content: 'x', isError: false }),
      ]),
      's',
    );
    assert.deepEqual(replay.totals.files, ['fine.txt']);
    assert.equal(replay.steps.at(-1)?.state.filesChanged, 1);
  });

  it('does not show a log that has no header, or one that is not verified, whatever its events say', () => {
    const forged: LoadedLog = { header, events: [event(1, 'user/message', { text: 'SECRET' }, 'user')], trust: 'unverified', validEnd: 0, lastMac: Buffer.alloc(32), tailDropped: false };
    assert.deepEqual(buildReplay(forged, 's').steps, []);
    assert.deepEqual(buildReplay({ ...verified([event(1, 'user/message', { text: 'SECRET' }, 'user')]), header: null }, 's').steps, []);
    assert.equal(projectKey('/a') === projectKey('/b'), false);
  });
});
