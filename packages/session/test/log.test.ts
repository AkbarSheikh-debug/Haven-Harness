import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import zlib, { zstdCompressSync } from 'node:zlib';
import { FlushFailedError, parseEvent } from '@hn/core';
import {
  FRAME_HEADER_BYTES,
  FRAME_MAGIC,
  GENESIS_MAC,
  LIVE_WRITE_BATCH_MAX_DELAY_MS,
  MAX_FRAME_RAW_BYTES,
  encodeFrame,
  parseLog,
  SessionWriter,
  type ScheduleBatch,
} from '@hn/session';
import { withTempDir } from '@hn/testkit';

const key = randomBytes(32);

function rawFrame(payload: Buffer, claimedRawLength: number): Buffer {
  const lengths = Buffer.alloc(8);
  lengths.writeUInt32LE(payload.length, 0);
  lengths.writeUInt32LE(claimedRawLength, 4);
  return Buffer.concat([FRAME_MAGIC, lengths, Buffer.alloc(32), payload]);
}

describe('writing', () => {
  it('round-trips events through disk with sequence numbers from 1', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'nested', 'log');
      const writer = await SessionWriter.open({ path, sessionId: 's', key });
      const first = writer.append('user/message', { text: 'hi' }, 'user');
      const second = writer.append('assistant/message', { text: 'hello' }, 'model-derived');
      await writer.close();

      const log = parseLog(await readFile(path), key);
      assert.equal(log.header?.sessionId, 's');
      assert.deepEqual(log.events, [first, second]);
      assert.deepEqual([first.seq, second.seq], [1, 2]);
    });
  });

  it('continues the sequence and the MAC chain after reopening', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log');
      const first = await SessionWriter.open({ path, sessionId: 's', key });
      first.append('turn/start', { turnId: 'a' });
      await first.close();

      const second = await SessionWriter.open({ path, sessionId: 's', key });
      assert.equal(second.append('turn/end', { turnId: 'a' }).seq, 2);
      await second.close();

      const log = parseLog(await readFile(path), key);
      assert.equal(log.trust, 'verified');
      assert.equal(log.events.length, 2);
    });
  });

  it('opens one batch window that later events do not extend', async () => {
    await withTempDir(async (directory) => {
      const scheduled: { fire: () => void; delayMs: number }[] = [];
      const schedule: ScheduleBatch = (fire, delayMs) => {
        scheduled.push({ fire, delayMs });
        return { cancel: () => undefined };
      };
      const path = join(directory, 'log');
      const writer = await SessionWriter.open({ path, sessionId: 's', key, schedule });

      writer.append('turn/start', { turnId: 'a' });
      writer.append('step/start', { stepId: '1' });
      writer.append('step/end', { stepId: '1' });
      assert.equal(scheduled.length, 1);
      assert.equal(scheduled[0]?.delayMs, LIVE_WRITE_BATCH_MAX_DELAY_MS);
      assert.equal(LIVE_WRITE_BATCH_MAX_DELAY_MS, 200);
      assert.equal(parseLog(await readFile(path), key).events.length, 0, 'nothing durable yet');

      await writer.flush();
      assert.equal(writer.pendingCount, 0);
      assert.equal(parseLog(await readFile(path), key).events.length, 3);
      await writer.close();
    });
  });

  it('fails closed on a full disk, keeps the events, and recovers without duplicates', async () => {
    await withTempDir(async (directory) => {
      let diskFull = false;
      const path = join(directory, 'log');
      const writer = await SessionWriter.open({
        path,
        sessionId: 's',
        key,
        beforeWrite: () => {
          if (diskFull) throw new Error('ENOSPC');
        },
      });
      writer.append('turn/start', { turnId: 'a' });
      await writer.flush();

      diskFull = true;
      const event = writer.append('assistant/message', { toolCalls: [] });
      await assert.rejects(writer.flush(), FlushFailedError);
      assert.equal(writer.pendingCount, 1, 'the event must not be lost');
      assert.equal(parseLog(await readFile(path), key).events.length, 1, 'and must not be durable');

      diskFull = false;
      await writer.flush();
      await writer.close();
      const log = parseLog(await readFile(path), key);
      assert.equal(log.trust, 'verified');
      assert.deepEqual(log.events.at(-1), event);
      assert.equal(log.events.length, 2);
    });
  });
});

describe('durability', () => {
  it('awaits one fsync per frame before a flush reports success', async () => {
    await withTempDir(async (directory) => {
      let syncs = 0;
      const writer = await SessionWriter.open({
        path: join(directory, 'log'),
        sessionId: 's',
        key,
        sync: async (handle) => {
          await handle.sync();
          syncs += 1;
        },
      });
      assert.equal(syncs, 1, 'the header frame');

      writer.append('turn/start', { turnId: 'a' });
      await writer.flush();
      assert.equal(syncs, 2);

      await writer.flush();
      assert.equal(syncs, 2, 'nothing queued, nothing to sync');
      await writer.close();
    });
  });

  it('treats a failed fsync as a failed flush and rewrites the frame', async () => {
    await withTempDir(async (directory) => {
      let failNext = false;
      const path = join(directory, 'log');
      const writer = await SessionWriter.open({
        path,
        sessionId: 's',
        key,
        sync: async (handle) => {
          if (failNext) {
            failNext = false;
            throw new Error('EIO');
          }
          await handle.sync();
        },
      });
      failNext = true;
      const event = writer.append('turn/start', { turnId: 'a' });
      await assert.rejects(writer.flush(), FlushFailedError);
      assert.equal(writer.pendingCount, 1);

      await writer.close();
      const log = parseLog(await readFile(path), key);
      assert.equal(log.trust, 'verified');
      assert.deepEqual(log.events, [event]);
    });
  });
});

describe('hostile files', () => {
  it('attack: zstd_bomb_rejected. stops a decompression bomb at the size the frame declared', async (t) => {
    const inflate = t.mock.method(zlib, 'zstdDecompressSync');
    const bomb = zstdCompressSync(Buffer.alloc(32 * 1024 * 1024));
    const log = parseLog(rawFrame(bomb, 16), key);
    assert.equal(log.trust, 'unverified');
    assert.deepEqual(log.events, []);
    const options = inflate.mock.calls.at(0)?.arguments[1] as { maxOutputLength: number };
    assert.equal(options.maxOutputLength, 16, 'the cap must stop inflation, not check it afterwards');
  });

  it('rejects duplicate or skipped sequence numbers even under a valid MAC', () => {
    const header = JSON.stringify({ format: 'hn-log', version: 1, sessionId: 's', createdAt: 'now' });
    const row = (seq: number): string =>
      JSON.stringify({ seq, ts: '2026-11-02T00:00:00.000Z', type: 'turn/end', origin: 'harness', data: {} });
    const load = (...rows: string[]): ReturnType<typeof parseLog> =>
      parseLog(encodeFrame(`${[header, ...rows].join('\n')}\n`, key, GENESIS_MAC).bytes, key);

    const duplicated = load(row(1), row(1), row(2));
    assert.equal(duplicated.trust, 'unverified');
    assert.deepEqual(duplicated.events.map((event) => event.seq), [1, 2], 'the duplicate is dropped');
    assert.equal(load(row(1), row(3)).trust, 'unverified');
    assert.equal(load(row(1), row(2)).trust, 'verified');
  });

  it('rejects frames that declare an absurd size without reading them', () => {
    const log = parseLog(rawFrame(Buffer.alloc(8), MAX_FRAME_RAW_BYTES + 1), key);
    assert.equal(log.trust, 'unverified');
  });

  it('treats an absurd frame length as forgery, not as a crash tail it may cut off', () => {
    const frame = rawFrame(Buffer.alloc(8), 8);
    frame.writeUInt32LE(0xffffffff, 4);
    const log = parseLog(frame, key);
    assert.equal(log.trust, 'unverified');
    assert.equal(log.tailDropped, false);
  });

  it('rejects a frame with a wrong magic number even when its MAC is fine', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log');
      const writer = await SessionWriter.open({ path, sessionId: 's', key });
      await writer.close();
      const bytes = await readFile(path);
      bytes[0] = 0x58;
      assert.equal(parseLog(bytes, key).trust, 'unverified');
    });
  });

  it('chains frames, so a frame from another session under the same key cannot be spliced in', async () => {
    await withTempDir(async (directory) => {
      const write = async (name: string, text: string): Promise<{ bytes: Buffer; split: number }> => {
        const path = join(directory, name);
        const writer = await SessionWriter.open({ path, sessionId: 's', key });
        await writer.flush();
        const split = (await readFile(path)).length;
        writer.append('user/message', { text }, 'user');
        await writer.close();
        return { bytes: await readFile(path), split };
      };
      const victim = await write('victim', 'mine');
      const donor = await write('donor', 'rm -rf everything');

      const spliced = Buffer.concat([victim.bytes.subarray(0, victim.split), donor.bytes.subarray(donor.split)]);
      assert.equal(parseLog(spliced, key).trust, 'unverified');
    });
  });

  it('rejects a file that is not a log at all', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'log');
      await writeFile(path, Buffer.alloc(FRAME_HEADER_BYTES * 2, 0x41));
      assert.equal(parseLog(await readFile(path), key).trust, 'unverified');
    });
  });

  it('accepts only exact event shapes', () => {
    const good = { seq: 1, ts: '2026-11-02T00:00:00.000Z', type: 'turn/end', origin: 'harness', data: {} };
    assert.notEqual(parseEvent(good), null);
    assert.equal(parseEvent({ ...good, extra: 1 }), null);
    assert.equal(parseEvent({ ...good, seq: 0 }), null);
    assert.equal(parseEvent({ ...good, seq: 1.5 }), null);
    assert.equal(parseEvent({ ...good, type: 'nope' }), null);
    assert.equal(parseEvent({ ...good, origin: 'root' }), null);
    assert.equal(parseEvent({ ...good, data: [] }), null);
    assert.equal(parseEvent({ ...good, ts: 'yesterday' }), null);
    assert.equal(parseEvent(JSON.parse('{"__proto__":{"seq":1}}')), null);
  });

  it('runs with Object.prototype.__proto__ disabled', () => {
    const probe: Record<string, unknown> = {};
    assert.throws(() => probe['__proto__'], { code: 'ERR_PROTO_ACCESS' });
  });
});
