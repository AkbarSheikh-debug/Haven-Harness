import { mkdir, open, writeFile, type FileHandle } from 'node:fs/promises';
import { dirname } from 'node:path';
import {
  FlushFailedError,
  LOG_FORMAT_VERSION,
  SessionUnverifiedError,
  type EventType,
  type Origin,
  type SessionEvent,
} from '@hn/core';
import {
  GENESIS_MAC,
  MAX_FRAME_RAW_BYTES,
  encodeFrame,
  parseLog,
  type LoadedLog,
  type LogHeader,
  type LogSeed,
} from './frames.ts';

/** The first pending event opens this window. Later events do not extend it. */
export const LIVE_WRITE_BATCH_MAX_DELAY_MS = 200;

export interface BatchTimer {
  cancel(): void;
}

export type ScheduleBatch = (fire: () => void, delayMs: number) => BatchTimer;

export interface WriterOptions {
  readonly path: string;
  readonly sessionId: string;
  readonly key: Buffer;
  readonly seed?: LogSeed;
  /** Applied to each row before it reaches the disk, so no secret is ever written. */
  readonly redact?: (row: string) => string;
  /** Fail if the file already exists, so a fork can never land on another session. */
  readonly mustCreate?: boolean;
  readonly now?: () => string;
  /** Replaces the real timer in tests. */
  readonly schedule?: ScheduleBatch;
  /** Runs before each write, so tests can simulate a full disk. */
  readonly beforeWrite?: () => void | Promise<void>;
  /** Replaces the fsync in tests. A missing fsync is invisible until a power cut. */
  readonly sync?: (handle: FileHandle) => Promise<void>;
}

const realSchedule: ScheduleBatch = (fire, delayMs) => {
  const timer = setTimeout(fire, delayMs);
  timer.unref();
  return { cancel: () => clearTimeout(timer) };
};

async function syncParentDirectory(path: string): Promise<void> {
  // Windows cannot fsync a directory, and NTFS journals the create itself.
  if (process.platform === 'win32') return;
  const directory = await open(dirname(path), 'r');
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function openOrCreate(path: string, mustCreate: boolean): Promise<FileHandle> {
  if (mustCreate) return open(path, 'wx+');
  try {
    return await open(path, 'r+');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    return open(path, 'wx+');
  }
}

/**
 * The only way to write a session log. Events are batched for speed, and `flush`
 * is the promise that they survive: callers await it before any model call or
 * tool body, so a failed flush stops the effect from happening.
 */
export class SessionWriter {
  readonly path: string;
  readonly sessionId: string;
  #key: Buffer;
  #handle: FileHandle;
  #offset: number;
  #lastMac: Buffer;
  #nextSeq: number;
  #pending: SessionEvent[] = [];
  #timer: BatchTimer | null = null;
  #paused = false;
  #queue: Promise<void> = Promise.resolve();
  #closed = false;
  #now: () => string;
  #schedule: ScheduleBatch;
  #beforeWrite: (() => void | Promise<void>) | undefined;
  #sync: (handle: FileHandle) => Promise<void>;
  #redact: (row: string) => string;

  private constructor(options: WriterOptions, handle: FileHandle, log: LoadedLog, offset: number) {
    this.path = options.path;
    this.sessionId = options.sessionId;
    this.#key = options.key;
    this.#handle = handle;
    this.#offset = offset;
    this.#lastMac = log.lastMac;
    this.#nextSeq = (log.events.at(-1)?.seq ?? 0) + 1;
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#schedule = options.schedule ?? realSchedule;
    this.#beforeWrite = options.beforeWrite;
    this.#sync = options.sync ?? ((target) => target.sync());
    this.#redact = options.redact ?? ((row) => row);
  }

  /**
   * Opens a log for writing, creating it when absent. A crash-torn tail is moved
   * to a sidecar and cut off. A log that fails verification is refused and left
   * exactly as it was found.
   */
  static async open(options: WriterOptions): Promise<SessionWriter> {
    await mkdir(dirname(options.path), { recursive: true });
    const handle = await openOrCreate(options.path, options.mustCreate ?? false);
    try {
      const bytes = await handle.readFile();
      const log = parseLog(bytes, options.key);
      if (log.trust !== 'verified') throw new SessionUnverifiedError(options.path);
      if (log.header !== null && log.header.sessionId !== options.sessionId) {
        throw new SessionUnverifiedError(options.path);
      }

      if (log.validEnd < bytes.length) {
        await writeFile(`${options.path}.torn-${log.validEnd}`, bytes.subarray(log.validEnd));
        await handle.truncate(log.validEnd);
        await handle.sync();
      }

      const writer = new SessionWriter(options, handle, log, log.validEnd);
      if (log.header === null) await writer.#writeHeader(options);
      await syncParentDirectory(options.path);
      return writer;
    } catch (error) {
      await handle.close();
      throw error;
    }
  }

  get pendingCount(): number {
    return this.#pending.length;
  }

  /**
   * Queues an event and returns it with its sequence number. It is not durable until
   * `flush`. `ts` is only for copying history, where the original time must survive.
   */
  append(
    type: EventType,
    data: Record<string, unknown>,
    origin: Origin = 'harness',
    ts: string = this.#now(),
  ): SessionEvent {
    if (this.#closed) throw new Error('The session writer is closed.');
    const event: SessionEvent = { seq: this.#nextSeq, ts, type, origin, data };
    this.#nextSeq += 1;
    this.#pending.push(event);
    if (this.#timer === null && !this.#paused) {
      this.#timer = this.#schedule(() => {
        this.#timer = null;
        this.flush().catch(() => {
          // The events stay queued and the batch window stays closed. The next
          // awaited flush retries and reports the failure to its caller.
        });
      }, LIVE_WRITE_BATCH_MAX_DELAY_MS);
    }
    return event;
  }

  /** Writes and fsyncs everything queued. Rejects with `FlushFailedError`, keeping the events. */
  flush(): Promise<void> {
    const drained = this.#queue.catch(() => undefined).then(() => this.#drain());
    this.#queue = drained;
    return drained;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    try {
      await this.flush();
    } finally {
      this.#closed = true;
      this.#timer?.cancel();
      this.#timer = null;
      await this.#handle.close();
    }
  }

  async #drain(): Promise<void> {
    this.#timer?.cancel();
    this.#timer = null;
    this.#paused = false;
    while (this.#pending.length > 0) {
      const { text, count } = this.#nextBatch();
      try {
        await this.#writeFrame(text);
      } catch (error) {
        this.#paused = true;
        throw new FlushFailedError(error);
      }
      this.#pending.splice(0, count);
    }
  }

  #nextBatch(): { text: string; count: number } {
    let text = '';
    let bytes = 0;
    let count = 0;
    for (const event of this.#pending) {
      const row = `${this.#redact(JSON.stringify(event))}\n`;
      const rowBytes = Buffer.byteLength(row);
      if (count > 0 && bytes + rowBytes > MAX_FRAME_RAW_BYTES) break;
      text += row;
      bytes += rowBytes;
      count += 1;
    }
    return { text, count };
  }

  async #writeFrame(text: string): Promise<void> {
    const { bytes, mac } = encodeFrame(text, this.#key, this.#lastMac);
    await this.#beforeWrite?.();
    try {
      await this.#handle.write(bytes, 0, bytes.length, this.#offset);
      await this.#sync(this.#handle);
    } catch (error) {
      await this.#handle.truncate(this.#offset).catch(() => undefined);
      throw error;
    }
    this.#offset += bytes.length;
    this.#lastMac = mac;
  }

  async #writeHeader(options: WriterOptions): Promise<void> {
    const header: LogHeader = {
      format: 'hn-log',
      version: LOG_FORMAT_VERSION,
      sessionId: options.sessionId,
      createdAt: this.#now(),
      ...(options.seed === undefined ? {} : { seed: options.seed }),
    };
    this.#lastMac = GENESIS_MAC;
    await this.#writeFrame(`${JSON.stringify(header)}\n`);
  }
}
