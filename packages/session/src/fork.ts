import { ForkBoundaryError, SessionUnverifiedError, type SessionEvent } from '@hn/core';
import type { LoadedLog } from './frames.ts';
import { openToolCalls } from './project.ts';
import { closingRecords } from './repair.ts';
import { SessionWriter } from './writer.ts';

function isClosedStep(events: readonly SessionEvent[], end: number): boolean {
  const last = events[end];
  if (last?.type !== 'step/end' && last?.type !== 'turn/end') return false;
  const prefix = events.slice(0, end + 1);
  if (openToolCalls(prefix).length > 0) return false;
  return !closingRecords(prefix).some((record) => record.type === 'compaction/end');
}

/** The newest seq at or before `limit` where the history is a closed, balanced step. */
export function lastForkBoundary(events: readonly SessionEvent[], limit = Number.MAX_SAFE_INTEGER): number {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if (event !== undefined && event.seq <= limit && isClosedStep(events, index)) return event.seq;
  }
  return 0;
}

export interface ForkOptions {
  readonly source: LoadedLog;
  readonly path: string;
  readonly sessionId: string;
  readonly key: Buffer;
  /** Must be a closed step. Defaults to the newest one. */
  readonly boundarySeq?: number;
}

/**
 * Copies a verified prefix into a new session. The source is left untouched, so a
 * rewind never destroys the path not taken. Any turn still open at the boundary is
 * closed in the copy, then an end-seed marks where the new session's own life begins.
 */
export async function forkSession(options: ForkOptions): Promise<SessionWriter> {
  const { source, boundarySeq } = options;
  if (source.trust !== 'verified' || source.header === null) {
    throw new SessionUnverifiedError(options.path);
  }

  const boundary = boundarySeq ?? lastForkBoundary(source.events);
  const index = source.events.findIndex((event) => event.seq === boundary);
  const valid = boundary === 0 || (index !== -1 && isClosedStep(source.events, index));
  if (!valid) throw new ForkBoundaryError(boundary);

  const inherited = source.events.slice(0, index + 1);
  const writer = await SessionWriter.open({
    path: options.path,
    sessionId: options.sessionId,
    key: options.key,
    mustCreate: true,
    seed: { sourceSessionId: source.header.sessionId, inheritedEventCount: inherited.length },
  });
  for (const event of inherited) writer.append(event.type, { ...event.data }, event.origin, event.ts);
  for (const record of closingRecords(inherited)) writer.append(record.type, record.data, record.origin);
  writer.append('session/end-seed', { inherited: true, boundarySeq: boundary });
  await writer.flush();
  return writer;
}
