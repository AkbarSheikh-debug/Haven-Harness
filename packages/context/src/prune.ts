import { createHash } from 'node:crypto';
import { toolCallsOf, type Origin, type SessionEvent, type ToolCall } from '@hn/core';
import { isPinned } from './fold-plan.ts';
import { estimateRow } from './tokens.ts';

/** Results at or under this size are cheaper to keep than to replace. */
export const PRUNE_MIN_CHARS = 200;
/** The newest `skill` results keep their bodies: the model is probably still following them. */
const SPARED_SKILL_RESULTS = 3;

export type PruneReason = 'duplicate' | 'stale' | 'image' | 'shrunk';

export interface PruneEdit {
  readonly seq: number;
  readonly reason: PruneReason;
  /** The stub that replaces the row's content. It holds no byte of the original. */
  readonly content: string;
}

export interface PrunePlan {
  readonly edits: readonly PruneEdit[];
  /** Estimated tokens the edits remove. */
  readonly saved: number;
}

/** A record for the log writer: the type, its data and the origin it carries. */
export interface PendingRecord {
  readonly type: 'tool/result' | 'user/message' | 'compaction/prune' | 'compaction/summary';
  readonly data: Record<string, unknown>;
  readonly origin: Origin;
}

function contentOf(row: SessionEvent): string {
  const value = row.type === 'tool/result' ? row.data['content'] : row.data['text'];
  return typeof value === 'string' ? value : '';
}

function hasImages(row: SessionEvent): boolean {
  const images = row.data['images'];
  return Array.isArray(images) && images.length > 0;
}

function digest(text: string): string {
  return createHash('sha256').update(text).digest('hex').slice(0, 12);
}

/** Tool names are model-written, so only a safe slice of one ever reaches a stub. */
function safeName(name: string | undefined): string {
  const cleaned = (name ?? '').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 64);
  return cleaned === '' ? 'tool' : cleaned;
}

/**
 * The tool a call really ran. A deferred tool runs through `call_tool`, and the log keeps the model's own
 * call, so the name inside is the one that matters (for example a `skill` body that must be spared).
 */
export function effectiveCall(call: ToolCall): ToolCall {
  if (call.name !== 'call_tool' || typeof call.args !== 'object' || call.args === null) return call;
  const inner = call.args as { name?: unknown; args?: unknown };
  return typeof inner.name === 'string' ? { id: call.id, name: inner.name, args: inner.args ?? {} } : call;
}

function toolNames(rows: readonly SessionEvent[]): Map<string, string> {
  const names = new Map<string, string>();
  for (const row of rows) for (const call of toolCallsOf(row)) names.set(call.id, effectiveCall(call).name);
  return names;
}

export function stubFor(row: SessionEvent, reason: PruneReason, tool: string): string {
  const text = contentOf(row);
  const size = `${text.length.toLocaleString('en-US')} chars, sha256:${digest(text)}`;
  switch (reason) {
    case 'duplicate':
      return `[Pruned: same output as a later ${tool} result (${size}). See that one.]`;
    case 'image':
      return `[Pruned: an image from an earlier ${tool} result was retired to save context. Run the tool again to see it.]`;
    case 'shrunk':
      if (row.type === 'user/message') {
        return `[Pruned: an earlier user message (${size}) was too large to keep. The summary quotes the original request.]`;
      }
      return `[Pruned to save context: ${tool} result (${size}). Run the tool again if you need it.]`;
    case 'stale':
      return `[Pruned to save context: ${tool} result (${size}). Run the tool again if you need it.]`;
  }
}

function alreadyPruned(row: SessionEvent): boolean {
  return typeof row.data['pruned'] === 'string';
}

/**
 * The free step, before any model call: (1) identical results over 200 chars keep only the newest;
 * (2) outside the tail, results over 200 chars become a one-line stub; (3) images outside the tail retire.
 * Tool-call arguments never change, and the newest `skill` results keep their bodies.
 */
export function planPrune(rows: readonly SessionEvent[], tailStartSeq: number): PrunePlan {
  const names = toolNames(rows);
  const results = rows.filter((row) => row.type === 'tool/result' && !isPinned(row) && !alreadyPruned(row));
  const toolOf = (row: SessionEvent): string => safeName(names.get(String(row.data['callId'])));
  const spared = new Set(
    results
      .filter((row) => names.get(String(row.data['callId'])) === 'skill')
      .slice(-SPARED_SKILL_RESULTS)
      .map((row) => row.seq),
  );
  const edits = new Map<number, PruneEdit>();
  const seen = new Set<string>();
  for (const row of [...results].reverse()) {
    const text = contentOf(row);
    if (text.length <= PRUNE_MIN_CHARS) continue;
    const key = createHash('sha256').update(text).digest('hex');
    if (seen.has(key) && !spared.has(row.seq)) {
      edits.set(row.seq, { seq: row.seq, reason: 'duplicate', content: stubFor(row, 'duplicate', toolOf(row)) });
    }
    seen.add(key);
  }
  for (const row of results) {
    if (row.seq >= tailStartSeq || edits.has(row.seq) || spared.has(row.seq)) continue;
    const reason: PruneReason | null = hasImages(row)
      ? 'image'
      : contentOf(row).length > PRUNE_MIN_CHARS
        ? 'stale'
        : null;
    if (reason !== null) edits.set(row.seq, { seq: row.seq, reason, content: stubFor(row, reason, toolOf(row)) });
  }
  const ordered = [...edits.values()].sort((a, b) => a.seq - b.seq);
  return { edits: ordered, saved: savedBy(rows, ordered) };
}

/** Stubs for rows the fold planner chose to shrink. */
export function shrinkEdits(rows: readonly SessionEvent[], seqs: readonly number[]): PruneEdit[] {
  const names = toolNames(rows);
  const wanted = new Set(seqs);
  return rows
    .filter((row) => wanted.has(row.seq))
    .map((row) => ({
      seq: row.seq,
      reason: 'shrunk' as const,
      content: stubFor(row, 'shrunk', safeName(names.get(String(row.data['callId'])))),
    }));
}

function replacement(row: SessionEvent, edit: PruneEdit): SessionEvent {
  const key = row.type === 'tool/result' ? 'content' : 'text';
  const { images: _images, ...rest } = row.data;
  return { ...row, data: { ...rest, [key]: edit.content, pruned: edit.reason } };
}

export function savedBy(rows: readonly SessionEvent[], edits: readonly PruneEdit[]): number {
  const bySeq = new Map(rows.map((row) => [row.seq, row]));
  let saved = 0;
  for (const edit of edits) {
    const row = bySeq.get(edit.seq);
    if (row !== undefined) saved += Math.max(0, estimateRow(row) - estimateRow(replacement(row, edit)));
  }
  return saved;
}

/**
 * The log records for a set of edits: one `compaction/prune` saying what changed, then one replacement row
 * per edit that shadows the original through a surface replace. The original stays in the log.
 * A tool result keeps its origin, so taint survives; a user-message stub is harness text, so it says so.
 */
export function pruneRecords(rows: readonly SessionEvent[], edits: readonly PruneEdit[]): PendingRecord[] {
  const bySeq = new Map(rows.map((row) => [row.seq, row]));
  const records: PendingRecord[] = [
    {
      type: 'compaction/prune',
      origin: 'harness',
      data: { edits: edits.map((edit) => ({ seq: edit.seq, reason: edit.reason })), saved: savedBy(rows, edits) },
    },
  ];
  for (const edit of edits) {
    const row = bySeq.get(edit.seq);
    if (row === undefined || (row.type !== 'tool/result' && row.type !== 'user/message')) continue;
    const surfaceOp = { op: 'replace', startSeq: row.seq, endSeq: row.seq, shadowedSeqs: [row.seq] };
    const data = { ...replacement(row, edit).data, surfaceOp };
    records.push({ type: row.type, data, origin: row.type === 'user/message' ? 'harness' : row.origin });
  }
  return records;
}
