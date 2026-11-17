import { HnError, toolCallsOf, type SessionEvent } from '@hn/core';
import type { Budget } from './budget.ts';
import { estimateRow } from './tokens.ts';

/** Conversational rows protected at the start, after the pinned prefix (Hermes). */
export const HEAD_ROWS = 3;
/** The most of T the kept tail may take when it grows back to keep a pair whole. */
const TAIL_CAP_RATIO = 0.5;
/** What a shrunk tool result costs: a one-line stub naming what it was. */
export const SHRUNK_ROW_TOKENS = 64;
/** A result larger than this is worth shrinking. */
const SHRINK_WORTH = SHRUNK_ROW_TOKENS * 2;

export class UnbalancedFoldError extends HnError {
  constructor() {
    super('UNBALANCED_FOLD', 'Compaction runs only at a step boundary, when every tool call has its result.');
  }
}

export interface FoldPlanInput {
  /** The surface the model sees now, in order. */
  readonly rows: readonly SessionEvent[];
  readonly budget: Budget;
  /** K after the load check, which may have scaled it down. */
  readonly keep: number;
  /** Tokens for system and tools, which are never folded. */
  readonly fixedTokens: number;
  /** How many folds this session already made. A huge first paste is pruned on the second. */
  readonly priorFolds: number;
  readonly estimate?: (row: SessionEvent) => number;
}

export interface FoldPlan {
  /** Session-prefix rows (instructions, memory snapshot): never counted as head, never folded. */
  readonly pinned: readonly number[];
  readonly head: readonly number[];
  /** Rows the summary replaces. */
  readonly middle: readonly number[];
  readonly tail: readonly number[];
  /**
   * Rows kept in place but cut to a stub: tool results, and on a later fold a huge user paste in the head.
   * Call arguments are never changed.
   */
  readonly shrink: readonly number[];
  /** Estimated context after the fold, with a full-size summary. */
  readonly tokensAfter: number;
}

export function isPinned(row: SessionEvent): boolean {
  return row.data['pinned'] === true;
}

/**
 * `balanced[i]` is true when cutting before row i separates no tool call from its result.
 * A result whose call is not in the list is ignored: it cannot be split from something absent.
 */
export function balancedCuts(rows: readonly SessionEvent[]): boolean[] {
  const open = new Set<string>();
  const balanced: boolean[] = [true];
  for (const row of rows) {
    for (const call of toolCallsOf(row)) open.add(call.id);
    if (row.type === 'tool/result') open.delete(String(row.data['callId']));
    balanced.push(open.size === 0);
  }
  return balanced;
}

/** Row costs, with shrunk results counted at their stub size. */
class Sizer {
  readonly #cost: number[];
  readonly #shrunk = new Set<number>();
  readonly #rows: readonly SessionEvent[];

  constructor(rows: readonly SessionEvent[], estimate: (row: SessionEvent) => number) {
    this.#rows = rows;
    this.#cost = rows.map(estimate);
  }

  cost(index: number): number {
    return this.#shrunk.has(index) ? SHRUNK_ROW_TOKENS : (this.#cost[index] ?? 0);
  }

  sum(from: number, to: number): number {
    let total = 0;
    for (let index = from; index < to; index += 1) total += this.cost(index);
    return total;
  }

  /**
   * Shrinks tool results in [from, to), largest first, until `over()` is false. User text shrinks only when
   * `userText` is set, which is the huge-first-paste case on a later fold.
   */
  shrinkWhile(from: number, to: number, over: () => boolean, userText = false): void {
    const candidates: number[] = [];
    for (let index = from; index < to; index += 1) {
      const row = this.#rows[index];
      const kind = row?.type === 'tool/result' || (userText && row?.type === 'user/message');
      if (kind && !this.#shrunk.has(index) && this.cost(index) > SHRINK_WORTH) {
        candidates.push(index);
      }
    }
    candidates.sort((a, b) => this.cost(b) - this.cost(a));
    for (const index of candidates) {
      if (!over()) return;
      this.#shrunk.add(index);
    }
  }

  get shrunk(): ReadonlySet<number> {
    return this.#shrunk;
  }
}

/** The first three conversational rows, grown forward while they end on an unanswered call. */
function headEnd(balanced: readonly boolean[], length: number): number {
  let end = Math.min(HEAD_ROWS, length);
  while (end < length && !balanced[end]) end += 1;
  return end;
}

/** The newest rows that fit in `keep`, then moved back to a balanced cut. */
function tailStart(sizer: Sizer, balanced: readonly boolean[], from: number, length: number, keep: number): number {
  let start = length;
  let used = 0;
  while (start > from && used + sizer.cost(start - 1) <= keep) {
    start -= 1;
    used += sizer.cost(start);
  }
  // The newest complete step always stays, even when it alone is larger than K: the model just asked for it.
  start = Math.min(start, newestStep(balanced, from, length));
  while (start > from && !balanced[start]) start -= 1;
  return start;
}

/** Where the newest complete step starts: the last balanced cut before the end, never before `from`. */
function newestStep(balanced: readonly boolean[], from: number, length: number): number {
  let index = length - 1;
  while (index > from && !balanced[index]) index -= 1;
  return Math.max(from, index);
}

function nextBalanced(balanced: readonly boolean[], after: number, length: number): number {
  let index = after + 1;
  while (index < length && !balanced[index]) index += 1;
  return Math.min(index, length);
}

/**
 * Plans one fold: which rows stay as head and tail, which the summary replaces, and which results shrink.
 * It never splits a pair, and it never returns a plan that changes nothing.
 */
export function planFold(input: FoldPlanInput): FoldPlan {
  const { budget } = input;
  const pinnedRows = input.rows.filter(isPinned);
  const rows = input.rows.filter((row) => !isPinned(row));
  const estimate = input.estimate ?? estimateRow;
  const balanced = balancedCuts(rows);
  if (!balanced[rows.length]) throw new UnbalancedFoldError();

  const sizer = new Sizer(rows, estimate);
  const fixed = input.fixedTokens + pinnedRows.reduce((sum, row) => sum + estimate(row), 0);
  const tailCap = Math.floor(budget.trigger * TAIL_CAP_RATIO);
  const head = headEnd(balanced, rows.length);
  let tail = tailStart(sizer, balanced, head, rows.length, input.keep);
  // A pair is never split: if keeping it whole overflows the cap, its result bodies shrink instead.
  sizer.shrinkWhile(tail, rows.length, () => sizer.sum(tail, rows.length) > tailCap);

  if (tail <= head) {
    // Head and tail met, so nothing lies between them: prune inside both. Only if that changed nothing is
    // the tail forced forward, because a fold above T must never be a no-op.
    sizer.shrinkWhile(0, rows.length, () => true);
    if (sizer.shrunk.size === 0) tail = nextBalanced(balanced, head, rows.length);
  }
  if (input.priorFolds > 0) {
    for (let index = 0; index < head; index += 1) {
      sizer.shrinkWhile(index, index + 1, () => sizer.cost(index) > budget.summaryCap, true);
    }
  }
  const after = (): number => fixed + sizer.sum(0, head) + budget.summaryCap + sizer.sum(tail, rows.length);
  const over = (): boolean => after() >= budget.trigger;
  sizer.shrinkWhile(0, head, over);
  // Still over: fold older kept turns one balanced step at a time, then shrink what is left of the tail,
  // and fold the newest step only as the last resort.
  const newest = newestStep(balanced, tail, rows.length);
  while (over() && tail < newest) tail = nextBalanced(balanced, tail, rows.length);
  sizer.shrinkWhile(tail, rows.length, over);
  while (over() && tail < rows.length) tail = nextBalanced(balanced, tail, rows.length);

  const seqs = (from: number, to: number): number[] => rows.slice(from, to).map((row) => row.seq);
  return {
    pinned: pinnedRows.map((row) => row.seq),
    head: seqs(0, head),
    middle: seqs(head, tail),
    tail: seqs(tail, rows.length),
    shrink: [...sizer.shrunk].sort((a, b) => a - b).map((index) => (rows[index] as SessionEvent).seq),
    tokensAfter: after(),
  };
}
