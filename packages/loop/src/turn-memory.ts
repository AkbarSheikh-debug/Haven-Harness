import type { Origin, SessionEvent } from '@hn/core';
import { deriveSurface } from '@hn/session';
import type { LiveLog, LoopConfig } from './types.ts';

/** A frame the memory layer produced. The loop only places it; memory decides what it says. */
export interface MemoryFrame {
  readonly text: string;
  readonly digest: string;
  readonly origin: Origin;
}

/** What the loop needs from memory. Every hook is optional, so a session without memory runs as before. */
export interface MemoryHooks {
  /** The frozen snapshot for this process. The same frame every time it is asked. */
  snapshot(): Promise<MemoryFrame>;
  /** Relevant recall for one user turn: chunks matching what the user typed, or null. */
  recall?(query: string, visible: readonly SessionEvent[], signal: AbortSignal): Promise<MemoryFrame | null>;
  /** Before a summary fold: append what matters from these rows to the daily note. */
  flush?(rows: readonly SessionEvent[], signal: AbortSignal): Promise<void>;
}

export function isMemoryRow(row: SessionEvent): boolean {
  return row.data['memory'] === true;
}

function currentMemory(events: readonly SessionEvent[]): SessionEvent | undefined {
  return deriveSurface(events).find((row) => isMemoryRow(row) && row.data['pinned'] === true);
}

/**
 * Before the first turn of this process: one pinned memory row, right after the instruction row. On a
 * resume the logged row stays unless memory changed while the session was closed. Within a process it
 * never changes, so writes during the session never move the cached prefix.
 */
export async function ensureMemory(config: LoopConfig, log: LiveLog): Promise<void> {
  if (config.memory === undefined) return;
  const frame = await config.memory.snapshot();
  const existing = currentMemory(log.events);
  if (existing !== undefined && existing.data['digest'] === frame.digest) return;
  const data: Record<string, unknown> = { text: frame.text, memory: true, pinned: true, digest: frame.digest };
  if (existing !== undefined) data['surfaceOp'] = { op: 'replace', startSeq: existing.seq, endSeq: existing.seq, shadowedSeqs: [existing.seq] };
  log.append('user/message', data, frame.origin);
}

/**
 * Relevant recall: once per user turn, the user's own words are the query and what matches
 * arrives as one row right after their message, so the cached prefix never changes. Recall is a
 * help, never a reason for a turn to fail, so any error leaves the turn as it was.
 */
export async function recallForTurn(config: LoopConfig, log: LiveLog, input: string, signal: AbortSignal): Promise<void> {
  const recall = config.memory?.recall;
  if (recall === undefined) return;
  try {
    const frame = await recall(input, deriveSurface(log.events), signal);
    if (frame !== null) log.append('user/message', { text: frame.text, recall: true, digest: frame.digest }, frame.origin);
  } catch {
    // Nothing recalled this turn.
  }
}
