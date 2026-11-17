import { isSurfaceEvent, toolCallsOf, type SessionEvent, type ToolCall } from '@hn/core';
import type { LoadedLog } from './frames.ts';

export interface SurfaceOp {
  readonly op: 'replace';
  readonly startSeq: number;
  readonly endSeq: number;
  /** Surface order is not numeric order, so this list is the authority. */
  readonly shadowedSeqs: readonly number[];
}

export interface Rights {
  readonly readOnly: boolean;
  readonly mode: string | null;
  readonly approvals: readonly SessionEvent[];
  readonly memoryWrites: boolean;
}

function surfaceOpOf(event: SessionEvent): SurfaceOp | null {
  const op = event.data['surfaceOp'] as SurfaceOp | undefined;
  return op?.op === 'replace' && Array.isArray(op.shadowedSeqs) ? op : null;
}

/** The rows the model sees, folded from the log. A fold replaces rows and never rewrites them. */
export function deriveSurface(events: readonly SessionEvent[]): SessionEvent[] {
  const rows: SessionEvent[] = [];
  for (const event of events) {
    if (!isSurfaceEvent(event)) continue;
    const op = surfaceOpOf(event);
    if (op === null) {
      rows.push(event);
      continue;
    }
    const shadowed = new Set(op.shadowedSeqs);
    const at = rows.findIndex((row) => shadowed.has(row.seq));
    const kept = rows.filter((row) => !shadowed.has(row.seq));
    kept.splice(at === -1 ? kept.length : at, 0, event);
    rows.length = 0;
    rows.push(...kept);
  }
  return rows;
}

/** Tool calls that have no result yet: tickets nobody redeemed. */
export function openToolCalls(events: readonly SessionEvent[]): ToolCall[] {
  const open = new Map<string, ToolCall>();
  for (const event of events) {
    for (const call of toolCallsOf(event)) open.set(call.id, call);
    if (event.type === 'tool/result') open.delete(event.data['callId'] as string);
  }
  return [...open.values()];
}

/**
 * What a log may grant when a session resumes. An unverified log grants nothing,
 * however its rows read, because a checksum is not proof of who wrote them.
 */
export function foldRights(log: LoadedLog): Rights {
  if (log.trust !== 'verified') {
    return { readOnly: true, mode: null, approvals: [], memoryWrites: false };
  }
  let mode: string | null = null;
  const approvals: SessionEvent[] = [];
  for (const event of log.events) {
    if (event.type === 'mode/change' && typeof event.data['mode'] === 'string') mode = event.data['mode'];
    if (event.type === 'approval/decided') approvals.push(event);
  }
  return { readOnly: false, mode, approvals, memoryWrites: true };
}
