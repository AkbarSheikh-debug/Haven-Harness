import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ForkBoundaryError, SessionAlreadyOwnedError, toolCallsOf, type SessionEvent } from '@hn/core';
import {
  UNKNOWN_OUTCOME_MESSAGE,
  acquireSessionLock,
  closingRecords,
  deriveSurface,
  forkSession,
  lastForkBoundary,
  openToolCalls,
  parseLog,
  repairSession,
  SessionWriter,
} from '@hn/session';
import { FakeModel, assertGolden, withTempDir } from '@hn/testkit';

const key = randomBytes(32);
const fixedNow = (): string => '2026-11-02T00:00:00.000Z';
const golden = (name: string): string =>
  fileURLToPath(new URL(`./golden/${name}.json`, import.meta.url));

async function reload(path: string): Promise<ReturnType<typeof parseLog>> {
  return parseLog(await readFile(path), key);
}

/** One finished step, then a second step that crashed while its tool was running. */
async function crashedSession(path: string): Promise<void> {
  const writer = await SessionWriter.open({ path, sessionId: 'source', key, now: fixedNow });
  writer.append('turn/start', { turnId: 't1' });
  writer.append('user/message', { text: 'fix the bug' }, 'user');
  writer.append('step/start', { stepId: '1' });
  writer.append('assistant/message', {
    text: 'reading',
    toolCalls: [{ id: 'c1', name: 'read_file', args: { path: 'a.ts' } }],
  });
  writer.append('tool/result', { callId: 'c1', content: 'source' }, 'workspace');
  writer.append('step/end', { stepId: '1' });
  writer.append('step/start', { stepId: '2' });
  writer.append('assistant/message', {
    text: 'editing',
    toolCalls: [
      { id: 'c2', name: 'edit_file', args: {} },
      { id: 'c3', name: 'bash', args: {} },
    ],
  });
  writer.append('job/registered', { jobId: 'j1' });
  writer.append('compaction/start', { compactionId: 'k1' });
  await writer.close();
}

describe('the unredeemed ticket', () => {
  it('gives every open call exactly one honest result, closing inner records first', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log');
      await crashedSession(path);
      const log = await reload(path);
      assert.deepEqual(
        openToolCalls(log.events).map((call) => call.id),
        ['c2', 'c3'],
      );

      const records = closingRecords(log.events);
      assert.deepEqual(
        records.map((record) => record.type),
        ['tool/result', 'tool/result', 'job/settled', 'compaction/end', 'step/end', 'turn/end'],
      );
      assert.equal(records[0]?.data['content'], UNKNOWN_OUTCOME_MESSAGE);
      assert.equal(records[3]?.data['aborted'], true);
      assert.equal(records[2]?.data['status'], 'lost');
    });
  });

  it('repairs the record on disk, and a second repair does nothing', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log');
      await crashedSession(path);

      const writer = await SessionWriter.open({ path, sessionId: 'source', key, now: fixedNow });
      assert.equal(await repairSession(writer, (await reload(path)).events), 6);
      assert.equal(await repairSession(writer, (await reload(path)).events), 0);
      await writer.close();

      const log = await reload(path);
      assert.deepEqual(openToolCalls(log.events), []);
      assert.deepEqual(closingRecords(log.events), []);
      assertEveryCallHasOneResult(log.events);
    });
  });
});

describe('projection', () => {
  it('folds a compaction by replacing rows, and never rewrites the log', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log');
      const writer = await SessionWriter.open({ path, sessionId: 's', key, now: fixedNow });
      const first = writer.append('user/message', { text: 'one' }, 'user');
      const second = writer.append('assistant/message', { text: 'two' });
      const third = writer.append('user/message', { text: 'three' }, 'user');
      writer.append('compaction/start', { compactionId: 'k' });
      const summary = writer.append('user/message', {
        text: '[CONTEXT COMPACTION — REFERENCE ONLY]',
        surfaceOp: { op: 'replace', startSeq: first.seq, endSeq: second.seq, shadowedSeqs: [first.seq, second.seq] },
      });
      writer.append('compaction/end', { compactionId: 'k' });
      await writer.close();

      const log = await reload(path);
      assert.equal(log.events.length, 6, 'the original rows stay in the log');
      assert.deepEqual(
        deriveSurface(log.events).map((row) => row.seq),
        [summary.seq, third.seq],
      );
    });
  });

  it('matches the reviewed golden projection of a repaired session', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log');
      await crashedSession(path);
      const writer = await SessionWriter.open({ path, sessionId: 'source', key, now: fixedNow });
      await repairSession(writer, (await reload(path)).events);
      await writer.close();
      await assertGolden(golden('repaired-surface'), deriveSurface((await reload(path)).events));
    });
  });
});

describe('fork', () => {
  it('forks at the last closed step, closes the turn, and leaves the source alone', async () => {
    await withTempDir(async (directory) => {
      const sourcePath = join(directory, 'source');
      await crashedSession(sourcePath);
      const before = await readFile(sourcePath);
      const source = parseLog(before, key);
      assert.equal(lastForkBoundary(source.events), 6);

      const writer = await forkSession({
        source,
        path: join(directory, 'fork'),
        sessionId: 'fork',
        key,
      });
      writer.append('user/message', { text: 'try another way' }, 'user');
      await writer.close();

      const fork = await reload(join(directory, 'fork'));
      assert.equal(fork.trust, 'verified');
      assert.deepEqual(fork.header?.seed, { sourceSessionId: 'source', inheritedEventCount: 6 });
      assert.deepEqual(
        fork.events.slice(6, 8).map((event) => event.type),
        ['turn/end', 'session/end-seed'],
      );
      assert.deepEqual(closingRecords(fork.events), []);
      assert.deepEqual(fork.events.slice(0, 6), source.events.slice(0, 6), 'history is copied exactly');
      assert.deepEqual(await readFile(sourcePath), before);
    });
  });

  it('refuses to land on a file that already exists', async () => {
    await withTempDir(async (directory) => {
      const sourcePath = join(directory, 'source');
      await crashedSession(sourcePath);
      await assert.rejects(
        forkSession({ source: await reload(sourcePath), path: sourcePath, sessionId: 'fork', key }),
        { code: 'EEXIST' },
      );
    });
  });

  it('refuses a boundary inside an unfinished step', async () => {
    await withTempDir(async (directory) => {
      const sourcePath = join(directory, 'source');
      await crashedSession(sourcePath);
      await assert.rejects(
        forkSession({
          source: await reload(sourcePath),
          path: join(directory, 'fork'),
          sessionId: 'fork',
          key,
          boundarySeq: 4,
        }),
        ForkBoundaryError,
      );
    });
  });

  it('does not let a stale compaction in the seed block the fork', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log');
      const writer = await SessionWriter.open({ path, sessionId: 's', key, now: fixedNow });
      writer.append('compaction/start', { compactionId: 'stale' });
      writer.append('session/end-seed', { inherited: true });
      await writer.close();
      assert.deepEqual(closingRecords((await reload(path)).events), []);
    });
  });
});

describe('one writer', () => {
  it('refuses a second writer in the same process, then frees the lock on release', async () => {
    await withTempDir(async (directory) => {
      const options = { sessionId: 's', lockDir: directory };
      const lock = await acquireSessionLock(options);
      await assert.rejects(acquireSessionLock(options), SessionAlreadyOwnedError);
      await lock.release();
      const again = await acquireSessionLock(options);
      await again.release();
    });
  });

  it('keeps sessions and lock directories independent', async () => {
    await withTempDir(async (directory) => {
      const a = await acquireSessionLock({ sessionId: 'a', lockDir: directory });
      const b = await acquireSessionLock({ sessionId: 'b', lockDir: directory });
      await a.release();
      await b.release();
    });
  });
});

describe('fake model', () => {
  it('plays back its script and fails loudly on an extra call', async () => {
    const model = new FakeModel([{ text: 'one' }, { error: new Error('503') }]);
    assert.equal((await model.complete('first')).text, 'one');
    await assert.rejects(model.complete('second'), /503/);
    await assert.rejects(model.complete('third'), /script ran out/);
    assert.deepEqual(model.requests, ['first', 'second', 'third']);
  });
});

function assertEveryCallHasOneResult(events: readonly SessionEvent[]): void {
  const results = new Map<string, number>();
  for (const event of events) {
    if (event.type === 'tool/result') {
      const id = event.data['callId'] as string;
      results.set(id, (results.get(id) ?? 0) + 1);
    }
  }
  for (const event of events) {
    for (const call of toolCallsOf(event)) assert.equal(results.get(call.id), 1, call.id);
  }
}
