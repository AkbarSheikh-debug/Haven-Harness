import type { EventType, Origin, SessionEvent } from '@hn/core';
import { openToolCalls } from './project.ts';
import type { SessionWriter } from './writer.ts';

export const UNKNOWN_OUTCOME_MESSAGE =
  'Its outcome is unknown. The session stopped before this tool reported back. ' +
  'Retry only if the operation is read-only or idempotent.';

export interface ClosingRecord {
  readonly type: EventType;
  readonly data: Record<string, unknown>;
  readonly origin: Origin;
}

function lastIndexOfType(events: readonly SessionEvent[], type: EventType): number {
  return events.findLastIndex((event) => event.type === type);
}

function openIds(
  events: readonly SessionEvent[],
  startType: EventType,
  endType: EventType,
  idField: string,
): string[] {
  const open = new Set<string>();
  for (const event of events) {
    if (event.type === startType) open.add(event.data[idField] as string);
    if (event.type === endType) open.delete(event.data[idField] as string);
  }
  return [...open];
}

/**
 * The records a crashed session is missing, in the order they must be appended:
 * tools and jobs, then the compaction, then the step, then the turn. The log itself
 * is repaired, so resume never depends on a fix-up made on the way to the provider.
 */
export function closingRecords(events: readonly SessionEvent[]): ClosingRecord[] {
  const records: ClosingRecord[] = [];

  for (const call of openToolCalls(events)) {
    records.push({
      type: 'tool/result',
      origin: 'harness',
      data: { callId: call.id, content: UNKNOWN_OUTCOME_MESSAGE, isError: true, outcome: 'unknown' },
    });
  }
  for (const jobId of openIds(events, 'job/registered', 'job/settled', 'jobId')) {
    records.push({ type: 'job/settled', origin: 'harness', data: { jobId, status: 'lost' } });
  }

  // A fork inherits history, but not any compaction its source had in flight.
  const live = events.slice(lastIndexOfType(events, 'session/end-seed') + 1);
  for (const compactionId of openIds(live, 'compaction/start', 'compaction/end', 'compactionId')) {
    records.push({ type: 'compaction/end', origin: 'harness', data: { compactionId, aborted: true } });
  }
  for (const stepId of openIds(live, 'step/start', 'step/end', 'stepId')) {
    records.push({ type: 'step/end', origin: 'harness', data: { stepId, reason: 'interrupted' } });
  }
  for (const turnId of openIds(live, 'turn/start', 'turn/end', 'turnId')) {
    records.push({ type: 'turn/end', origin: 'harness', data: { turnId, reason: 'interrupted' } });
  }
  return records;
}

/** Appends the closing records and waits until they are durable. Safe to run twice. */
export async function repairSession(writer: SessionWriter, events: readonly SessionEvent[]): Promise<number> {
  const records = closingRecords(events);
  for (const record of records) writer.append(record.type, record.data, record.origin);
  await writer.flush();
  return records.length;
}
