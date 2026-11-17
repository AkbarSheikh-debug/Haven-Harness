import { createHash } from 'node:crypto';
import type { SessionEvent } from '@hn/core';
import { contextTokens, type ModelCaps, type Usage } from '@hn/provider';
import type { Budget } from './budget.ts';

/**
 * Ratios chosen to overcount rather than undercount. A fold that runs a little early costs one cache miss;
 * an undercount overflows the window. Four characters per token, used alone, undercounts CJK about fourfold.
 */
/** A short Latin word is one token; longer ones add one per this many characters. */
const LATIN_WORD_CHARS = 5;
const LATIN_EXTRA_CHARS_PER_TOKEN = 4;
const OTHER_LETTERS_PER_TOKEN = 2;
const CJK_TOKENS_PER_CHAR = 1.1;
const PUNCT_TOKENS_PER_CHAR = 1;
const NEWLINE_TOKENS_PER_CHAR = 0.5;
const SYMBOL_TOKENS = 2;
const SPACES_PER_TOKEN = 8;
/** Role markers and separators the provider adds around every row. */
export const ROW_OVERHEAD = 4;
/** An unanchored estimate fires on its own only this close to W - O. */
const UNANCHORED_RATIO = 0.9;

const CJK = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}　-〿＀-￯]/u;
const LETTER = /[\p{L}\p{M}\p{N}]/u;

type CharClass = 'latin' | 'digit' | 'letter' | 'cjk' | 'space' | 'newline' | 'punct' | 'symbol';

function classOf(char: string): CharClass {
  const code = char.codePointAt(0) ?? 0;
  if (code < 0x80) {
    if (char === '\n' || char === '\r') return 'newline';
    if (char === ' ' || char === '\t') return 'space';
    if (char >= '0' && char <= '9') return 'digit';
    if (/[A-Za-z_]/.test(char)) return 'latin';
    return 'punct';
  }
  if (CJK.test(char)) return 'cjk';
  if (LETTER.test(char)) return 'letter';
  return 'symbol';
}

/** The cost of one run of same-class characters. Fractions add up, and the total is rounded up once. */
function runCost(kind: CharClass, length: number): number {
  switch (kind) {
    case 'latin':
      return 1 + Math.max(0, length - LATIN_WORD_CHARS) / LATIN_EXTRA_CHARS_PER_TOKEN;
    case 'digit':
      // Many tokenizers split numbers into single digits.
      return length;
    case 'letter':
      return length / OTHER_LETTERS_PER_TOKEN;
    case 'cjk':
      return length * CJK_TOKENS_PER_CHAR;
    case 'space':
      // One space joins the next word's token; longer runs (indentation) cost their own.
      return length === 1 ? 0 : length / SPACES_PER_TOKEN;
    case 'newline':
      return length * NEWLINE_TOKENS_PER_CHAR;
    case 'punct':
      return length * PUNCT_TOKENS_PER_CHAR;
    case 'symbol':
      return length * SYMBOL_TOKENS;
  }
}

/** A script-aware token estimate for text. It is meant to err high. */
export function estimateText(text: string): number {
  let total = 0;
  let kind: CharClass | null = null;
  let length = 0;
  for (const char of text) {
    const next = classOf(char);
    if (next === kind) {
      length += 1;
      continue;
    }
    if (kind !== null) total += runCost(kind, length);
    kind = next;
    length = 1;
  }
  if (kind !== null) total += runCost(kind, length);
  return Math.ceil(total);
}

/** The parts of a row the model sees: its text, tool results and tool calls. */
export function rowText(event: SessionEvent): string {
  const parts: string[] = [];
  const { data } = event;
  for (const key of ['text', 'content', 'summary'] as const) {
    const value = data[key];
    if (typeof value === 'string') parts.push(value);
  }
  const calls = data['toolCalls'];
  if (Array.isArray(calls)) {
    for (const call of calls) parts.push(JSON.stringify(call));
  }
  return parts.join('\n');
}

/**
 * What one attached image costs. Providers bill by pixels after their own resize; Anthropic tops out near 1,600
 * for a full-size image. Counting every image at the top errs high, as the rest of the estimate does.
 */
export const IMAGE_TOKENS = 1_600;

export function estimateRow(event: SessionEvent): number {
  const images = event.data['images'];
  const pictures = Array.isArray(images) ? images.length * IMAGE_TOKENS : 0;
  return estimateText(rowText(event)) + ROW_OVERHEAD + pictures;
}

/** What makes two requests comparable: the same model, system prompt and tools. */
export function envelopeOf(parts: { readonly model: string; readonly system: string; readonly tools: unknown }): string {
  return createHash('sha256')
    .update(JSON.stringify([parts.model, parts.system, parts.tools]))
    .digest('hex')
    .slice(0, 32);
}

/** The last count a provider reported, valid only for requests with the same envelope. */
export interface UsageAnchor {
  readonly envelope: string;
  /** Context tokens the provider counted for the request, plus the reply it wrote. */
  readonly tokens: number;
  /** The reply's row, so every row after it is new since the count. */
  readonly atSeq: number;
}

export function anchorFrom(usage: Usage, envelope: string, atSeq: number): UsageAnchor {
  return { envelope, tokens: contextTokens(usage) + usage.output, atSeq };
}

export interface ContextEstimate {
  readonly tokens: number;
  /** True when a provider count backs the number and only the newer rows were estimated. */
  readonly anchored: boolean;
}

/**
 * Anchors on the provider's last count and estimates only the delta. Without a valid anchor, every row
 * plus the fixed prefix is estimated.
 */
export function estimateContext(input: {
  readonly rows: readonly SessionEvent[];
  readonly envelope: string;
  readonly prefixTokens: number;
  readonly anchor: UsageAnchor | null;
}): ContextEstimate {
  const { rows, anchor } = input;
  const usable =
    anchor !== null && anchor.envelope === input.envelope && rows.some((row) => row.seq === anchor.atSeq);
  if (usable) {
    const after = anchor.atSeq;
    const delta = rows.filter((row) => row.seq > after).reduce((sum, row) => sum + estimateRow(row), 0);
    return { tokens: anchor.tokens + delta, anchored: true };
  }
  const all = rows.reduce((sum, row) => sum + estimateRow(row), 0);
  return { tokens: input.prefixTokens + all, anchored: false };
}

export interface FoldDecision {
  readonly fold: boolean;
  /** Set when the decision rests on an estimate alone, so the UI can say so. */
  readonly estimated: boolean;
}

/**
 * Anchored counts fold at T. An unanchored estimate does not fire alone unless it is near W - O,
 * except on a model that never reports usage, where the estimate is all there is.
 */
export function shouldFold(estimate: ContextEstimate, budget: Budget, usage: ModelCaps['usage']): FoldDecision {
  if (estimate.anchored) return { fold: estimate.tokens >= budget.trigger, estimated: false };
  if (usage === 'none') return { fold: estimate.tokens >= budget.trigger, estimated: true };
  const near = Math.max(budget.trigger, Math.floor((budget.window - budget.output) * UNANCHORED_RATIO));
  return { fold: estimate.tokens >= near, estimated: true };
}
