import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { get as httpGet } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { MAX_TAIL_SUBSCRIBERS, openBrokerAudit } from '@hn/broker';
import { signCheckpoint, verifyBundle, type AuditEntry, type AuditExport, type Checkpoint } from '@hn/security';
import { baseTree, startTeam, type Person, type Team, type TeamOptions } from './fixture.ts';

const AUDITOR = { email: 'sam@example.com', department: 'eng', groups: ['auditor'] };
const ANA = { email: 'ana@example.com', department: 'eng', groups: [] };

const tree = baseTree({ org: { version: 1, name: 'org', models: { allow: ['team-*'] }, approvers: { roles: ['lead'] }, audit: { readers: { roles: ['auditor'] } } } });

interface Setup {
  readonly team: Team;
  readonly sam: Person;
  /** A request as the auditor, with their login token. */
  readonly ask: (path: string) => Promise<Response>;
  /** Writes a row the way the broker does, and waits until it is on disk and in the index. */
  readonly write: (type: string, data: Record<string, unknown>) => Promise<void>;
}

async function withAudit(run: (setup: Setup) => Promise<void>, options: TeamOptions = {}): Promise<void> {
  const team = await startTeam({ tree, ...options });
  try {
    const sam = await team.login(AUDITOR);
    await run({
      team,
      sam,
      ask: (path) => team.raw(path, { token: sam.loginToken, session: sam.sid }),
      write: async (type, data) => {
        team.broker.context.audit(type, data);
        await team.broker.audit.settle();
      },
    });
  } finally {
    await team.close();
  }
}

const json = async <T>(response: Response): Promise<T> => (await response.json()) as T;

describe('reading the broker audit', () => {
  it('lets a named reader search by person, session, type and time, in pages', async () => {
    await withAudit(async ({ team, ask, write }) => {
      const ana = await team.login(ANA);
      await ana.session('s-1');
      await ana.session('s-2');
      await new Promise((resolve) => setTimeout(resolve, 20));
      const middle = new Date().toISOString();
      await new Promise((resolve) => setTimeout(resolve, 20));
      await write('broker/model', { user: 'ana@example.com', session: 's-1', model: 'team-large', usd: 0.5, tokens: 100 });
      await write('broker/model', { user: 'bo@example.com', session: 's-9', model: 'team-small', usd: 0.1, tokens: 10 });
      const all = await json<{ rows: AuditEntry[]; head: { n: number } }>(await ask('/v1/audit/rows'));
      assert.ok(all.rows.length >= 5);
      assert.equal(all.head.n, all.rows[all.rows.length - 1]?.n);
      const byUser = await json<{ rows: AuditEntry[] }>(await ask('/v1/audit/rows?user=ana%40example.com'));
      assert.ok(byUser.rows.length >= 3 && byUser.rows.every((row) => JSON.stringify(row.data).includes('ana@example.com')));
      const bySession = await json<{ rows: AuditEntry[] }>(await ask('/v1/audit/rows?session=s-9'));
      assert.deepEqual(bySession.rows.map((row) => row.type), ['broker/model']);
      const byType = await json<{ rows: AuditEntry[] }>(await ask('/v1/audit/rows?type=broker/model'));
      assert.deepEqual([...new Set(byType.rows.map((row) => row.type))], ['broker/model']);
      const late = await json<{ rows: AuditEntry[] }>(await ask(`/v1/audit/rows?since=${encodeURIComponent(middle)}&type=broker/model`));
      assert.equal(late.rows.length, 2);
      const early = await json<{ rows: AuditEntry[] }>(await ask(`/v1/audit/rows?until=${encodeURIComponent(middle)}`));
      assert.ok(early.rows.length >= 3 && early.rows.every((row) => row.type !== 'broker/model'));
      // Pages: two at a time, following `next`, give every row once and in order.
      const seen: number[] = [];
      let after = 0;
      for (let pages = 0; pages < 50; pages += 1) {
        const page = await json<{ rows: AuditEntry[]; next: number | null }>(await ask(`/v1/audit/rows?limit=2&after=${after}&type=broker/`));
        seen.push(...page.rows.map((row) => row.n));
        if (page.next === null) break;
        after = page.next;
      }
      assert.deepEqual(seen, [...seen].sort((a, b) => a - b));
      assert.equal(new Set(seen).size, seen.length);
      assert.ok(seen.length >= 5);
    });
  });

  it('attack: audit_filter_injection - refuses a filter that is not plain, and unknown or repeated parameters, without trying to interpret it', async () => {
    await withAudit(async ({ ask }) => {
      for (const bad of ['type=.*', 'type=broker/(', 'type=%00', 'session=../x', 'session=a%20b', 'limit=501', 'limit=0', 'limit=-1', 'limit=x', 'since=yesterday', 'after=1.5', 'frm=1', 'user=a&user=b', `user=${'x'.repeat(201)}`]) {
        assert.equal((await ask(`/v1/audit/rows?${bad}`)).status, 400, bad);
      }
      // A user filter is only ever compared, so a pattern finds nothing and breaks nothing.
      const none = await json<{ rows: unknown[] }>(await ask('/v1/audit/rows?user=.*'));
      assert.deepEqual(none.rows, []);
    });
  });

  it('attack: audit_read_by_non_reader audit_read_by_session_token - refuses everyone who is not a named reader, a session token, no token and an expired login, and records the refusals', async () => {
    let clock = Date.now();
    await withAudit(async ({ team, sam, ask }) => {
      const ana = await team.login(ANA);
      for (const path of ['/v1/audit/rows', '/v1/audit/approvals', '/v1/audit/sessions', '/v1/audit/anchors', '/v1/audit/checkpoints', '/v1/audit/export', '/v1/audit/tail']) {
        assert.equal((await team.raw(path, { token: ana.loginToken, session: ana.sid })).status, 403, `${path} for someone who is not a reader`);
        assert.equal((await team.raw(path, { token: await sam.session('agent-1'), session: 'agent-1' })).status, 401, `${path} with a session token, which a model-driven session holds`);
        assert.equal((await team.raw(path, {})).status, 401, `${path} with no token`);
      }
      assert.ok(team.audit.filter((row) => row.type === 'broker/audit-read-refused' && row.data['user'] === 'ana@example.com').length >= 7);
      assert.equal((await ask('/v1/audit/rows')).status, 200);
      clock += 9 * 3_600_000;
      assert.equal((await ask('/v1/audit/rows')).status, 401, 'the login has expired');
    }, { now: () => clock });
  });

  it('attack: audit_reader_access_ends_with_policy - stops being a reader the moment the policy stops naming them', async () => {
    await withAudit(async ({ team, ask }) => {
      assert.equal((await ask('/v1/audit/rows')).status, 200);
      await team.setPolicy({ ...tree, serial: 2, org: { version: 1, name: 'org', models: { allow: ['team-*'] } } });
      assert.equal((await ask('/v1/audit/rows')).status, 403);
    });
  });

  it('records who looked, and what they asked for', async () => {
    await withAudit(async ({ team, ask }) => {
      await ask('/v1/audit/rows?user=ana%40example.com&type=broker/model');
      await ask('/v1/audit/approvals?state=pending');
      const reads = team.audit.filter((row) => row.type === 'broker/audit-read');
      assert.equal(reads.length, 2);
      assert.deepEqual(reads[0]?.data['filter'], { user: 'ana@example.com', type: 'broker/model' });
      assert.equal(reads[0]?.data['user'], 'sam@example.com');
      assert.equal(reads[1]?.data['what'], 'approvals');
      // And the row is in the chain itself, where a reader can see it on the next search.
      const mine = await json<{ rows: AuditEntry[] }>(await ask('/v1/audit/rows?type=broker/audit-read'));
      assert.ok(mine.rows.length >= 2);
    });
  });

  it('shows each approval as one record: asked, decided by whom, used, denied, refused, or still waiting', async () => {
    await withAudit(async ({ ask, write }) => {
      await write('broker/approval-requested', { id: 'a1', user: 'ana@example.com', action: 'push main abc' });
      await write('broker/approval-refused', { id: 'a1', approver: 'ana@example.com', reason: 'The person who asked cannot approve their own request.' });
      await write('broker/approval-decided', { id: 'a1', approver: 'cy@example.com', requester: 'ana@example.com', action: 'push main abc', decision: 'approve' });
      await write('broker/approval-used', { id: 'a1', user: 'ana@example.com', action: 'push main abc', decidedBy: 'cy@example.com' });
      await write('broker/approval-requested', { id: 'a2', user: 'bo@example.com', action: 'push main def' });
      await write('broker/approval-decided', { id: 'a2', approver: 'cy@example.com', requester: 'bo@example.com', action: 'push main def', decision: 'deny' });
      await write('broker/approval-requested', { id: 'a3', user: 'ana@example.com', action: 'push main ghi' });
      const { approvals } = await json<{ approvals: { id: string; requester: string; state: string; decidedBy: string | null; refused: { approver: string }[]; rows: number[] }[] }>(await ask('/v1/audit/approvals'));
      const byId = new Map(approvals.map((item) => [item.id, item]));
      assert.equal(byId.get('a1')?.state, 'used');
      assert.equal(byId.get('a1')?.decidedBy, 'cy@example.com');
      assert.equal(byId.get('a1')?.requester, 'ana@example.com');
      assert.equal(byId.get('a1')?.refused[0]?.approver, 'ana@example.com');
      assert.equal(byId.get('a1')?.rows.length, 4, 'every line names its rows, so it can be checked against the chain');
      assert.equal(byId.get('a2')?.state, 'denied');
      assert.equal(byId.get('a3')?.state, 'pending');
      const only = async (query: string): Promise<string[]> => (await json<{ approvals: { id: string }[] }>(await ask(`/v1/audit/approvals?${query}`))).approvals.map((item) => item.id);
      assert.deepEqual(await only('state=pending'), ['a3']);
      assert.deepEqual(await only('state=denied'), ['a2']);
      assert.deepEqual(await only('state=refused'), ['a1']);
      assert.deepEqual((await only('user=bo%40example.com')), ['a2']);
      assert.deepEqual(await only('user=cy%40example.com'), ['a1', 'a2'], 'the approver is found too');
      assert.equal((await ask('/v1/audit/approvals?state=bogus')).status, 400);
    });
  });

  it('lists sessions with their model calls and the head each one anchored', async () => {
    await withAudit(async ({ team, ask, write }) => {
      const ana = await team.login(ANA);
      const token = await ana.session('s-a');
      const mac = 'a'.repeat(64);
      assert.equal((await team.raw('/v1/audit/anchor', { token, session: 's-a', body: { n: 4, mac } })).status, 200);
      await write('broker/model', { user: 'ana@example.com', session: 's-a', model: 'team-large', usd: 0.25, tokens: 40 });
      await write('broker/model', { user: 'ana@example.com', session: 's-a', model: 'team-large', usd: 0.25, tokens: 60 });
      const { sessions } = await json<{ sessions: { user: string; session: string; modelCalls: number; usd: number; tokens: number; anchor: { n: number; mac: string } | null }[] }>(await ask('/v1/audit/sessions?user=ana%40example.com'));
      const found = sessions.find((item) => item.session === 's-a');
      assert.equal(found?.modelCalls, 2);
      assert.equal(found?.usd, 0.5);
      assert.equal(found?.tokens, 100);
      assert.deepEqual(found?.anchor, { n: 4, mac });
      const anchors = await json<{ anchors: { user: string; session: string; n: number }[] }>(await ask('/v1/audit/anchors?user=ana%40example.com&session=s-a'));
      assert.deepEqual(anchors.anchors.map((item) => [item.user, item.session, item.n]), [['ana@example.com', 's-a', 4]]);
    });
  });
});

describe('the broker audit checkpoints', () => {
  const rowsIn = async (state: string): Promise<string> => readFile(join(state, 'audit.jsonl'), 'utf8');

  it('attack: audit_checkpoint_file_edited - signs the head, keeps its key and its checkpoints across a restart, and refuses a checkpoint file that was edited', async () => {
    const state = await mkdtemp(join(tmpdir(), 'hn-cp-'));
    try {
      const first = await openBrokerAudit(state, undefined, { checkpointEvery: 0, checkpointMs: 3_600_000 });
      assert.equal(await first.checkpoint(), null, 'nothing to sign yet');
      first.record('broker/login', { user: 'a' });
      first.record('broker/login', { user: 'b' });
      await first.settle();
      const signed = (await first.checkpoint()) as Checkpoint;
      assert.equal(signed.n, 2);
      assert.equal((await first.checkpoint())?.sig, signed.sig, 'the same head is signed once');
      const publicPem = first.checkpoints.publicPem;
      first.close();
      const second = await openBrokerAudit(state, undefined, { checkpointEvery: 0, checkpointMs: 3_600_000 });
      assert.equal(second.checkpoints.publicPem, publicPem, 'the key is kept');
      assert.deepEqual(second.checkpoints.list().map((item) => item.n), [2]);
      second.close();

      // Someone edits a checkpoint to cover a different row.
      const text = await readFile(join(state, 'checkpoints.jsonl'), 'utf8');
      await writeFile(join(state, 'checkpoints.jsonl'), text.replace('"n":2', '"n":1'));
      await assert.rejects(openBrokerAudit(state), /not signed by this broker|not in the audit chain/);
      // Put it back, and cut the chain's tail instead: the checkpoint names a row that is gone.
      await writeFile(join(state, 'checkpoints.jsonl'), text);
      const chain = (await rowsIn(state)).split('\n').filter((line) => line !== '');
      await writeFile(join(state, 'audit.jsonl'), `${chain[0]}\n`);
      await assert.rejects(openBrokerAudit(state), /not in the audit chain/);
    } finally {
      await rm(state, { recursive: true, force: true });
    }
  });

  it('refuses, at start, a checkpoint for the real head that another key signed', async () => {
    const state = await mkdtemp(join(tmpdir(), 'hn-cp-'));
    try {
      const first = await openBrokerAudit(state, undefined, { checkpointEvery: 0 });
      first.record('broker/login', { user: 'a' });
      await first.settle();
      const real = (await first.checkpoint()) as Checkpoint;
      first.close();
      const forged = signCheckpoint({ n: real.n, mac: real.mac }, real.ts, generateKeyPairSync('ed25519').privateKey);
      await writeFile(join(state, 'checkpoints.jsonl'), JSON.stringify(forged) + String.fromCharCode(10));
      await assert.rejects(openBrokerAudit(state), /not signed by this broker/);
    } finally {
      await rm(state, { recursive: true, force: true });
    }
  });

  it('drops a checkpoint that was half written when the process died, and goes on writing', async () => {
    const state = await mkdtemp(join(tmpdir(), 'hn-cp-'));
    try {
      const first = await openBrokerAudit(state, undefined, { checkpointEvery: 0 });
      first.record('broker/login', { user: 'a' });
      await first.settle();
      await first.checkpoint();
      first.record('broker/login', { user: 'b' });
      await first.settle();
      first.close();
      const path = join(state, 'checkpoints.jsonl');
      await writeFile(path, `${await readFile(path, 'utf8')}{"n":2,"mac":"`);
      const second = await openBrokerAudit(state, undefined, { checkpointEvery: 0 });
      assert.deepEqual(second.checkpoints.list().map((item) => item.n), [1]);
      assert.equal((await second.checkpoint())?.n, 2);
      second.close();
      const third = await openBrokerAudit(state);
      assert.deepEqual(third.checkpoints.list().map((item) => item.n), [1, 2]);
      third.close();
    } finally {
      await rm(state, { recursive: true, force: true });
    }
  });

  it('signs by itself every so many rows', async () => {
    const state = await mkdtemp(join(tmpdir(), 'hn-cp-'));
    try {
      const sink = await openBrokerAudit(state, undefined, { checkpointEvery: 3, checkpointMs: 3_600_000 });
      for (let i = 0; i < 7; i += 1) sink.record('broker/login', { user: `u${i}` });
      await sink.settle();
      await sink.checkpoint().then(() => undefined);
      assert.deepEqual(sink.checkpoints.list().map((item) => item.n).sort((a, b) => a - b), [3, 6, 7]);
      sink.close();
    } finally {
      await rm(state, { recursive: true, force: true });
    }
  });
});

describe('exporting the broker audit', () => {
  it('gives a bundle that verifies offline with the audit key and the pinned public key, and not with others', async () => {
    await withAudit(async ({ team, ask, write }) => {
      const ana = await team.login(ANA);
      await ana.session('s-1');
      await write('broker/model', { user: 'ana@example.com', session: 's-1', model: 'team-large', usd: 1, tokens: 5 });
      const bundle = await json<AuditExport>(await ask('/v1/audit/export'));
      assert.equal(bundle.kind, 'export');
      assert.equal(bundle.from, 1);
      assert.equal(bundle.exportedBy, 'sam@example.com');
      const { publicKey } = team.broker.audit.checkpoints;
      const result = verifyBundle(bundle, { hmacKey: team.broker.audit.key, publicKey });
      assert.equal(result.ok, true, result.reason ?? '');
      assert.equal(result.rows, bundle.count);
      assert.equal(verifyBundle(bundle, { hmacKey: randomBytes(32), publicKey }).ok, false);
      assert.equal(verifyBundle({ ...bundle, rows: bundle.rows.map((row, index) => (index === 1 ? { ...row, data: { ...row.data, user: 'mallory' } } : row)) }, { hmacKey: team.broker.audit.key, publicKey }).ok, false);
      // A range from the middle to an earlier row is covered by a checkpoint the broker signs for it.
      const middle = await json<AuditExport>(await ask('/v1/audit/export?from=2&to=3'));
      assert.equal(middle.count, 2);
      assert.equal(verifyBundle(middle, { hmacKey: team.broker.audit.key, publicKey }).ok, true);
    });
  });

  it('refuses a range past the end, backwards, or malformed', async () => {
    await withAudit(async ({ ask }) => {
      assert.equal((await ask('/v1/audit/export?to=999999')).status, 416);
      assert.equal((await ask('/v1/audit/export?from=3&to=2')).status, 400);
      assert.equal((await ask('/v1/audit/export?from=0')).status, 400);
      assert.equal((await ask('/v1/audit/export?from=a')).status, 400);
    });
  });

  it('hands out the public key and the checkpoints, with a fresh one at the head', async () => {
    await withAudit(async ({ team, ask }) => {
      const listed = await json<{ keyId: string; publicKey: string; checkpoints: Checkpoint[] }>(await ask('/v1/audit/checkpoints'));
      assert.equal(listed.publicKey, team.broker.audit.checkpoints.publicPem);
      // The broker signs the head, then records this read as one more row; wait for that row, so the head is not a race.
      await team.broker.audit.settle();
      const head = team.broker.audit.store.head.n;
      const [last] = await team.broker.audit.store.read(head, head);
      assert.equal(last?.type, 'broker/audit-read');
      assert.equal(listed.checkpoints[listed.checkpoints.length - 1]?.n, team.broker.audit.store.head.n - 1);
      assert.equal(listed.checkpoints[0]?.keyId, listed.keyId);
    });
  });
});

async function readLines(response: Response, count: number, timeoutMs = 5_000): Promise<Record<string, any>[]> {
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  const decoder = new TextDecoder();
  const lines: Record<string, any>[] = [];
  let pending = '';
  const deadline = Date.now() + timeoutMs;
  while (lines.length < count && Date.now() < deadline) {
    const chunk = await Promise.race([reader.read(), new Promise<{ done: true; value: undefined }>((resolve) => setTimeout(() => resolve({ done: true, value: undefined }), Math.max(1, deadline - Date.now())))]);
    if (chunk.done) break;
    pending += decoder.decode(chunk.value, { stream: true });
    let at = pending.indexOf('\n');
    while (at !== -1) {
      lines.push(JSON.parse(pending.slice(0, at)) as Record<string, any>);
      pending = pending.slice(at + 1);
      at = pending.indexOf('\n');
    }
  }
  reader.releaseLock();
  return lines;
}

describe('following the broker audit live', () => {
  it('attack: audit_tail_gap_or_repeat - streams new rows in order as they are written, and resumes from a row number with no gap or repeat', async () => {
    await withAudit(async ({ team, ask, write }) => {
      await team.broker.audit.settle();
      const head = team.broker.audit.store.head.n;
      const live = await ask('/v1/audit/tail');
      assert.equal(live.status, 200);
      // The read of the tail is itself a row, written before the stream starts, so it is before the first one streamed.
      await write('broker/login', { user: 'x1' });
      await write('broker/login', { user: 'x2' });
      // The first row is the tail's own entry in the record of who looked.
      const streamed = (await readLines(live, 3)).filter((line) => line['type'] === 'row').map((line) => line['row'] as AuditEntry);
      assert.deepEqual(streamed.map((row) => row.type === 'broker/audit-read' ? 'read' : row.data['user']), ['read', 'x1', 'x2']);
      assert.equal(streamed[0]?.n, head + 1);
      assert.deepEqual(streamed.map((row) => row.n), [head + 1, head + 2, head + 3]);
      await live.body?.cancel();

      const got = streamed.slice(1);
      const from = got[0]?.n ?? 0;
      await write('broker/login', { user: 'x3' });
      const resumed = await ask(`/v1/audit/tail?from=${from}`);
      const rows = (await readLines(resumed, 4)).filter((line) => line['type'] === 'row').map((line) => (line['row'] as AuditEntry).n);
      assert.equal(rows[0], from + 1, 'starts right after the row it was given');
      assert.ok(rows.length >= 3);
      assert.deepEqual(rows, rows.map((_, index) => from + 1 + index), 'no gap and no repeat');
      await resumed.body?.cancel();
    });
  });

  it('attack: audit_tail_outlives_login - sends a heartbeat, and ends the stream when the login has expired', async () => {
    let clock = Date.now();
    await withAudit(async ({ ask }) => {
      const live = await ask('/v1/audit/tail');
      const beat = await readLines(live, 2);
      assert.ok(beat.some((line) => line['type'] === 'heartbeat'), JSON.stringify(beat));
      clock += 9 * 3_600_000;
      const closing = await readLines(live, 3, 3_000);
      assert.ok(closing.some((line) => line['type'] === 'closed'), JSON.stringify(closing));
    }, { now: () => clock, auditOptions: { heartbeatMs: 40 } });
  });

  it(`attack: audit_tail_follower_cap - refuses the ${MAX_TAIL_SUBSCRIBERS + 1}th follower, and lets another in when one leaves`, async () => {
    await withAudit(async ({ team, sam, ask }) => {
      const open: Response[] = [];
      for (let i = 0; i < MAX_TAIL_SUBSCRIBERS; i += 1) {
        const response = await ask('/v1/audit/tail');
        assert.equal(response.status, 200);
        open.push(response);
      }
      assert.equal((await ask('/v1/audit/tail')).status, 429);
      await open[0]?.body?.cancel();
      let admitted = false;
      for (let tries = 0; tries < 50 && !admitted; tries += 1) {
        const again = await team.raw('/v1/audit/tail', { token: sam.loginToken, session: sam.sid });
        admitted = again.status === 200;
        if (admitted) await again.body?.cancel();
        else await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.equal(admitted, true);
      for (const response of open.slice(1)) await response.body?.cancel();
    }, { auditOptions: { heartbeatMs: 3_600_000 } });
  });

  it('attack: audit_tail_slow_reader_dropped - drops a follower that does not read, instead of buffering without bound', { timeout: 40_000 }, async () => {
    await withAudit(async ({ team, sam, write }) => {
      const url = new URL(`${team.broker.url}/v1/audit/tail?from=0`);
      const stalled = await new Promise<{ end: Promise<string>; destroy(): void }>((resolve) => {
        const request = httpGet({ host: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, headers: { authorization: `Bearer ${sam.loginToken}`, 'x-hn-session': sam.sid } }, (response) => {
          response.pause();
          // Reading starts only after the broker has had its say.
          resolve({ end: new Promise((done) => { let text = ''; response.on('data', (chunk: Buffer) => (text = (text + chunk.toString('utf8')).slice(-2000))); response.on('end', () => done(text)); response.on('error', () => done(text)); }), destroy: () => request.destroy() });
          setTimeout(() => response.resume(), 3_000).unref();
        });
        request.on('error', () => undefined);
      });
      const pad = 'x'.repeat(200_000);
      for (let i = 0; i < 80; i += 1) await write('broker/login', { user: 'pad', pad });
      // Bounded, and the stalled connection is always torn down, so a broker that never drops it fails this test instead of hanging the run.
      const limit = new Promise<string>((resolve) => setTimeout(() => resolve('no end: the broker kept buffering'), 15_000).unref());
      const tail = await Promise.race([stalled.end, limit]).finally(() => stalled.destroy());
      assert.match(tail, /"type":"dropped"/);
      assert.equal(team.broker.audit.store.head.n >= 80, true, 'the broker itself was not slowed down');
    }, { auditOptions: { tailBufferBytes: 512 * 1024, heartbeatMs: 3_600_000 } });
  });
});
