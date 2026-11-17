import { createHmac, timingSafeEqual } from 'node:crypto';
import zlib from 'node:zlib';
import { LOG_FORMAT_VERSION, SessionVersionError, parseEvent, type SessionEvent } from '@hn/core';

export const FRAME_MAGIC = Buffer.from('HNF1', 'latin1');
export const MAC_BYTES = 32;
/** magic (4) + compressed length (4) + raw length (4) + MAC (32). */
export const FRAME_HEADER_BYTES = 12 + MAC_BYTES;
export const MAX_FRAME_RAW_BYTES = 64 * 1024 * 1024;
export const MAX_FRAME_COMPRESSED_BYTES = MAX_FRAME_RAW_BYTES + 1024 * 1024;
export const MAX_LOG_RAW_BYTES = 1024 * 1024 * 1024;
export const GENESIS_MAC = Buffer.alloc(MAC_BYTES);

const MAC_DOMAIN = Buffer.from('hn-frame-v1', 'latin1');

export interface LogSeed {
  readonly sourceSessionId: string;
  readonly inheritedEventCount: number;
}

export interface LogHeader {
  readonly format: 'hn-log';
  readonly version: number;
  readonly sessionId: string;
  readonly createdAt: string;
  readonly seed?: LogSeed;
}

export type LogTrust = 'verified' | 'unverified';

export interface LoadedLog {
  readonly header: LogHeader | null;
  readonly events: readonly SessionEvent[];
  /** `unverified` logs are read-only and carry no rights. */
  readonly trust: LogTrust;
  /** Bytes covered by verified frames. Anything after them is not trusted. */
  readonly validEnd: number;
  /** The last verified frame's MAC, which the next frame chains from. */
  readonly lastMac: Buffer;
  /** True when the file ended part-way through a frame. */
  readonly tailDropped: boolean;
}

function frameMac(key: Buffer, prevMac: Buffer, lengths: Buffer, payload: Buffer): Buffer {
  return createHmac('sha256', key)
    .update(MAC_DOMAIN)
    .update(prevMac)
    .update(lengths)
    .update(payload)
    .digest();
}

export function encodeFrame(text: string, key: Buffer, prevMac: Buffer): { bytes: Buffer; mac: Buffer } {
  const raw = Buffer.from(text, 'utf8');
  if (raw.length > MAX_FRAME_RAW_BYTES) {
    throw new RangeError(`Frame of ${raw.length} bytes exceeds the ${MAX_FRAME_RAW_BYTES} byte limit.`);
  }
  const payload = zlib.zstdCompressSync(raw);
  const lengths = Buffer.alloc(8);
  lengths.writeUInt32LE(payload.length, 0);
  lengths.writeUInt32LE(raw.length, 4);
  const mac = frameMac(key, prevMac, lengths, payload);
  return { bytes: Buffer.concat([FRAME_MAGIC, lengths, mac, payload]), mac };
}

function decompress(payload: Buffer, rawLength: number): string | null {
  try {
    const raw = zlib.zstdDecompressSync(payload, { maxOutputLength: Math.max(rawLength, 1) });
    return raw.length === rawLength ? raw.toString('utf8') : null;
  } catch {
    return null;
  }
}

function parseHeader(row: unknown): LogHeader | null {
  if (typeof row !== 'object' || row === null) return null;
  const { format, version, sessionId, createdAt } = row as Record<string, unknown>;
  if (format !== 'hn-log' || !Number.isSafeInteger(version)) return null;
  if (typeof sessionId !== 'string' || typeof createdAt !== 'string') return null;
  if ((version as number) > LOG_FORMAT_VERSION) {
    throw new SessionVersionError(version as number, LOG_FORMAT_VERSION);
  }
  return row as LogHeader;
}

function parseRow(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch {
    return undefined;
  }
}

/**
 * Reads a log. Never throws on damaged input, only on a newer format.
 *
 * A frame cut off by the end of the file is a crash, so it is dropped. A complete
 * frame with a bad MAC is damage or forgery, so the whole log becomes `unverified`
 * and stays on disk untouched.
 */
export function parseLog(bytes: Buffer, key: Buffer): LoadedLog {
  const events: SessionEvent[] = [];
  let header: LogHeader | null = null;
  let trust: LogTrust = 'verified';
  let tailDropped = false;
  let offset = 0;
  let validEnd = 0;
  let prevMac = GENESIS_MAC;
  let lastMac = GENESIS_MAC;
  let rawTotal = 0;
  let nextSeq = 1;

  const fail = (): void => {
    trust = 'unverified';
  };

  frames: while (offset < bytes.length) {
    if (bytes.length - offset < FRAME_HEADER_BYTES) {
      tailDropped = true;
      break;
    }
    if (!bytes.subarray(offset, offset + 4).equals(FRAME_MAGIC)) {
      fail();
      break;
    }
    const lengths = bytes.subarray(offset + 4, offset + 12);
    const compressedLength = lengths.readUInt32LE(0);
    const rawLength = lengths.readUInt32LE(4);
    if (compressedLength > MAX_FRAME_COMPRESSED_BYTES || rawLength > MAX_FRAME_RAW_BYTES) {
      fail();
      break;
    }
    const end = offset + FRAME_HEADER_BYTES + compressedLength;
    if (end > bytes.length) {
      tailDropped = true;
      break;
    }
    rawTotal += rawLength;
    if (rawTotal > MAX_LOG_RAW_BYTES) {
      fail();
      break;
    }

    const mac = bytes.subarray(offset + 12, offset + FRAME_HEADER_BYTES);
    const payload = bytes.subarray(offset + FRAME_HEADER_BYTES, end);
    if (!timingSafeEqual(mac, frameMac(key, prevMac, lengths, payload))) fail();

    const text = decompress(payload, rawLength);
    if (text === null) {
      fail();
      break;
    }

    for (const line of text.split('\n')) {
      if (line === '') continue;
      const row = parseRow(line);
      if (header === null) {
        header = parseHeader(row);
        if (header === null) {
          fail();
          break frames;
        }
        continue;
      }
      const event = parseEvent(row);
      if (event === null) {
        fail();
        break frames;
      }
      if (event.seq !== nextSeq) {
        fail();
        if (event.seq < nextSeq) continue;
      }
      events.push(event);
      nextSeq = event.seq + 1;
    }

    if (trust === 'verified') {
      validEnd = end;
      lastMac = Buffer.from(mac);
    }
    prevMac = Buffer.from(mac);
    offset = end;
  }

  return { header, events, trust, validEnd, lastMac, tailDropped };
}
