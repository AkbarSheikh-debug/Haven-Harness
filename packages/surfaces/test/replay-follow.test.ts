import assert from 'node:assert/strict';
import { request } from 'node:http';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { after, before, describe, it } from 'node:test';
import { MAX_FOLLOW_BYTES, followReplay, loadReplay, prefixOf, startReplayServe, type Replay, type ReplayStep, type Served } from '@hn/surfaces';
import { withTempDir, type FakeOpenAI } from '@hn/testkit';
import { forgedFrame, frameRanges, recordSession, startScriptedModel, type Recorded } from './replay-fixture.ts';

interface Reply {
  readonly status: number;
  readonly body: string;
}

function call(port: number, path: string, headers: Record<string, string> = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method: 'GET', path, headers: { host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      let text = '';
      res.setEncoding('utf8').on('data', (chunk: string) => (text += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: text }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function login(served: Served): Promise<string> {
  const origin = `http://127.0.0.1:${served.port}`;
  const body = `token=${served.token}`;
  const reply = await new Promise<{ cookie: string }>((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: served.port, method: 'POST', path: '/login', headers: { host: `127.0.0.1:${served.port}`, origin, 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(Buffer.byteLength(body)) } }, (res) => {
      res.resume();
      res.on('end', () => resolve({ cookie: /hn_session=[0-9a-f]{64}/.exec(String(res.headers['set-cookie']))?.[0] ?? '' }));
    });
    req.on('error', reject);
    req.end(body);
  });
  assert.notEqual(reply.cookie, '');
  return reply.cookie;
}

type Followed = Replay & { follow: { size: number; prefix: string; since: number } | null; unchanged?: boolean };

describe('following a session log as it grows', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startScriptedModel();
  });
  after(async () => {
    await model.close();
  });

  /** A recorded session whose log file is cut back to its first frames, as a live session's log is part-way through. */
  const withGrowingLog = async (body: (context: { recorded: Recorded; whole: Buffer; ends: number[]; served: Served; get: (path: string) => Promise<Reply>; open: () => Promise<Followed>; poll: (from: Followed) => Promise<Followed>; full: Replay }) => Promise<void>): Promise<void> =>
    withTempDir(async (dir) => {
      const recorded = await recordSession(await realpath(dir), model);
      const whole = await readFile(recorded.file);
      const ends = frameRanges(whole).map((range) => range.end);
      assert.ok(ends.length >= 12, `the recorded session is too short to cut: ${ends.length} frames`);
      const fullLoaded = await loadReplay(recorded.sessionId, recorded.project, { HN_HOME: recorded.home });
      assert.equal(fullLoaded.kind, 'replay');
      const served = await startReplayServe({ cwd: recorded.project, env: { HN_HOME: recorded.home } });
      try {
        const cookie = await login(served);
        const get = (path: string): Promise<Reply> => call(served.port, path, { cookie });
        const base = `/replay/api/session/${recorded.sessionId}`;
        await body({
          recorded,
          whole,
          ends,
          served,
          get,
          full: (fullLoaded as { replay: Replay }).replay,
          open: async () => JSON.parse((await get(base)).body) as Followed,
          poll: async (from) => JSON.parse((await get(`${base}?since=${from.follow?.since}&size=${from.follow?.size}&prefix=${from.follow?.prefix}`)).body) as Followed,
        });
      } finally {
        await served.close();
      }
    });

  it('sends only the steps that are new, and together they are exactly the whole replay', { timeout: 180_000 }, async () => {
    await withGrowingLog(async ({ recorded, whole, ends, open, poll, full }) => {
      await writeFile(recorded.file, whole.subarray(0, ends[5]));
      const first = await open();
      assert.equal(first.trust, 'verified');
      assert.ok(first.follow !== null && first.follow.since === first.steps.length && first.follow.size === ends[5]);

      // Nothing was written: a cheap answer, nothing re-sent.
      assert.deepEqual(await poll(first), { unchanged: true });

      await writeFile(recorded.file, whole.subarray(0, ends[10]));
      const second = await poll(first);
      assert.equal(second.trust, 'verified');
      assert.equal(second.steps[0]?.index, first.steps.length, 'the new steps carry on from the old ones');
      const merged: ReplayStep[] = [...first.steps, ...second.steps];
      assert.deepEqual(merged.map((step) => step.index), merged.map((_, index) => index));

      await writeFile(recorded.file, whole);
      const third = await poll(second);
      merged.push(...third.steps);
      assert.deepEqual(merged, full.steps, 'what a follower puts together is exactly what opening the finished log shows');
      assert.deepEqual(third.totals, full.totals);
      assert.equal(third.follow?.prefix, prefixOf(full.steps));
    });
  });

  it('waits for a record that is still being written, and does not call it forged', { timeout: 180_000 }, async () => {
    await withGrowingLog(async ({ recorded, whole, ends, open, poll }) => {
      await writeFile(recorded.file, whole.subarray(0, ends[5]));
      const first = await open();
      // Half of the next record is on disk.
      const half = (ends[5] as number) + Math.floor(((ends[6] as number) - (ends[5] as number)) / 2);
      await writeFile(recorded.file, whole.subarray(0, half));
      const during = await poll(first);
      assert.equal(during.trust, 'verified');
      assert.equal(during.crashed, true, 'the page can say the last record is still being written');
      assert.deepEqual(during.steps, [], 'nothing of the unfinished record is shown');
      // The rest arrives.
      await writeFile(recorded.file, whole.subarray(0, ends[7]));
      const after = await poll(during.follow === null ? first : { ...first, follow: during.follow });
      assert.equal(after.trust, 'verified');
      assert.equal(after.crashed, false);
      assert.ok(after.steps.length >= 1);
    });
  });

  it('attack: followed_log_forged - a forged record appended while following turns the screen to refused, and none of its content is sent', { timeout: 180_000 }, async () => {
    await withGrowingLog(async ({ recorded, whole, ends, open, poll }) => {
      await writeFile(recorded.file, whole.subarray(0, ends[5]));
      const first = await open();
      const payload = Buffer.from(JSON.stringify({ type: 'user/message', origin: 'user', data: { text: 'FORGED-LINE-DO-NOT-SHOW' } }));
      await writeFile(recorded.file, Buffer.concat([whole.subarray(0, ends[5]), forgedFrame(payload)]));
      const forged = await poll(first);
      assert.equal(forged.trust, 'refused');
      assert.deepEqual(forged.steps, []);
      assert.equal(forged.follow, null, 'there is nothing to follow from');
      assert.doesNotMatch(JSON.stringify(forged), /FORGED-LINE-DO-NOT-SHOW/);
      assert.match(forged.reason ?? '', /failed its integrity check/);
      // The same with a byte changed inside a record the follower was already shown.
      const edited = Buffer.from(whole.subarray(0, ends[10]));
      edited[(ends[3] as number) - 3] = (edited[(ends[3] as number) - 3] as number) ^ 0xff;
      await writeFile(recorded.file, edited);
      assert.equal((await poll(first)).trust, 'refused');
    });
  });

  it('attack: followed_log_shortened_or_rewritten - refuses a log that got shorter, or whose shown part no longer matches what the follower holds', { timeout: 180_000 }, async () => {
    await withGrowingLog(async ({ recorded, whole, ends, open, poll }) => {
      await writeFile(recorded.file, whole.subarray(0, ends[10]));
      const long = await open();
      // Cut back, to a prefix that still verifies: it is shorter than what was shown.
      await writeFile(recorded.file, whole.subarray(0, ends[5]));
      const shorter = await poll(long);
      assert.equal(shorter.trust, 'refused');
      assert.match(shorter.reason ?? '', /shorter/);
      // The follower holds a fingerprint of different steps: whatever it was shown is not what this log says.
      await writeFile(recorded.file, whole);
      const other = await open();
      const claimed = { ...other, follow: { size: 1, since: 10, prefix: 'a'.repeat(64) } } as Followed;
      const changed = await poll(claimed);
      assert.equal(changed.trust, 'refused');
      assert.match(changed.reason ?? '', /already shown has changed/);
    });
  });

  it('refuses malformed follow parameters and a log too large to follow, and answers for a missing one', { timeout: 180_000 }, async () => {
    await withGrowingLog(async ({ recorded, whole, get }) => {
      const base = `/replay/api/session/${recorded.sessionId}`;
      const prefix = 'a'.repeat(64);
      for (const bad of ['since=x&size=1&prefix=' + prefix, 'since=1&size=-1&prefix=' + prefix, 'since=1&size=1&prefix=zz', 'since=1&size=1', 'since=99999999999&size=1&prefix=' + prefix]) assert.equal((await get(`${base}?${bad}`)).status, 400, bad);
      assert.equal((await get(`/replay/api/session/nothing-here?since=0&size=1&prefix=${prefix}`)).status, 404);
      assert.equal((await get(`/replay/api/session/..%2Fx?since=0&size=1&prefix=${prefix}`)).status, 400);
      await writeFile(recorded.file, Buffer.concat([whole, Buffer.alloc(MAX_FOLLOW_BYTES)]));
      assert.equal((await get(`${base}?since=0&size=1&prefix=${prefix}`)).status, 413);
      const loaded = await followReplay(recorded.sessionId, recorded.project, { HN_HOME: recorded.home }, { since: 0, size: 1, prefix });
      assert.equal(loaded.kind, 'too-large');
    });
  });

  it('opens with "Follow live" on and the newest session chosen when started with follow', { timeout: 180_000 }, async () => {
    await withTempDir(async (dir) => {
      const recorded = await recordSession(await realpath(dir), model);
      const served = await startReplayServe({ cwd: recorded.project, env: { HN_HOME: recorded.home }, follow: true });
      const plain = await startReplayServe({ cwd: recorded.project, env: { HN_HOME: recorded.home } });
      try {
        assert.match((await call(served.port, '/replay', { cookie: await login(served) })).body, /<body data-follow="1">/);
        assert.doesNotMatch((await call(plain.port, '/replay', { cookie: await login(plain) })).body, /data-follow/);
      } finally {
        await served.close();
        await plain.close();
      }
    });
  });
});
