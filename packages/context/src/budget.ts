import { HnError } from '@hn/core';

/** Below this a summary, a head and a tail cannot all fit, so the session is refused rather than thrashing. */
export const MIN_WINDOW = 16_000;
export const DEFAULT_MAX_OUTPUT = 32_000;
const DEFAULT_THRESHOLD_RATIO = 0.8;
const DEFAULT_RETAIN_RATIO = 0.16;
const HEADROOM_MIN = 4_096;
const HEADROOM_MAX = 65_536;
/** DSH's headroom, reached for every window with W - O >= 129,536, so large windows match DSH exactly. */
const HEADROOM_OFFSET = 64_000;
const SUMMARY_FLOOR = 2_000;
const SUMMARY_CEILING = 10_000;
const SUMMARY_CONTENT_RATIO = 0.2;
const SLACK_RATIO = 0.1;

export class WindowTooSmallError extends HnError {
  constructor(window: number) {
    super('WINDOW_TOO_SMALL', `A context window of ${window} tokens is under the ${MIN_WINDOW} minimum.`);
  }
}

export class PrefixTooLargeError extends HnError {
  constructor(prefix: number, trigger: number) {
    super(
      'PREFIX_TOO_LARGE',
      `The fixed prefix (${prefix} tokens) leaves no room under the compaction trigger (${trigger} tokens).`,
    );
  }
}

/** Per-model overrides, as DSH has. */
export interface BudgetOverrides {
  readonly thresholdRatio?: number;
  readonly retainRatio?: number;
  readonly headroomTokens?: number;
}

export interface BudgetInput {
  /** W: the model's context window. */
  readonly window: number;
  /** The model's own output ceiling. */
  readonly modelMaxOutput: number;
  /** The configured output request; the advertised maximum is never used on its own. */
  readonly maxOutput?: number;
  readonly overrides?: BudgetOverrides;
}

export interface Budget {
  readonly window: number;
  /** O: the requested `max_tokens`. */
  readonly output: number;
  /** B: headroom kept free under the window. */
  readonly headroom: number;
  /** T: fold when the context reaches this. */
  readonly trigger: number;
  /** K: the newest tokens kept word for word. */
  readonly keep: number;
  /** The largest a summary may be: 0.1T. */
  readonly summaryCap: number;
}

function ratio(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!(value > 0 && value < 1)) throw new RangeError(`${name} must be between 0 and 1, got ${value}.`);
  return value;
}

/** `x = W - O; B = clamp(x - 64,000, 4,096, 65,536)`. Identical to DSH for x >= 129,536. */
export function headroomFor(window: number, output: number): number {
  const x = window - output;
  return Math.min(HEADROOM_MAX, Math.max(HEADROOM_MIN, x - HEADROOM_OFFSET));
}

/** The compaction recipe: WHEN is T, KEEP is K. */
export function computeBudget(input: BudgetInput): Budget {
  const { window } = input;
  if (!Number.isFinite(window) || window < MIN_WINDOW) throw new WindowTooSmallError(window);
  const output = Math.min(input.modelMaxOutput, input.maxOutput ?? DEFAULT_MAX_OUTPUT);
  if (!(output > 0) || output >= window) throw new RangeError(`Output ${output} does not fit window ${window}.`);
  const threshold = ratio(input.overrides?.thresholdRatio, DEFAULT_THRESHOLD_RATIO, 'thresholdRatio');
  const retain = ratio(input.overrides?.retainRatio, DEFAULT_RETAIN_RATIO, 'retainRatio');
  const headroom = input.overrides?.headroomTokens ?? headroomFor(window, output);
  if (!(headroom >= 0)) throw new RangeError(`headroomTokens must not be negative, got ${headroom}.`);
  const trigger = Math.floor(Math.min(window * threshold, window - output - headroom));
  if (trigger <= 0) throw new WindowTooSmallError(window);
  const keep = Math.floor(retain * (window - output));
  return { window, output, headroom, trigger, keep, summaryCap: Math.floor(trigger * SLACK_RATIO) };
}

/** `max(2,000, min(20% of content, 10,000, 0.1T))`, and never over 0.1T. */
export function summaryBudget(budget: Budget, contentTokens: number): number {
  const wanted = Math.max(
    SUMMARY_FLOOR,
    Math.min(Math.floor(contentTokens * SUMMARY_CONTENT_RATIO), SUMMARY_CEILING, budget.summaryCap),
  );
  return Math.min(wanted, budget.summaryCap);
}

export interface LoadParts {
  readonly system: number;
  readonly tools: number;
  /** Pinned session-prefix rows and the first three conversational rows. */
  readonly head: number;
  readonly summary: number;
}

export interface LoadFit {
  readonly keep: number;
  readonly summary: number;
  /** True when keep and summary had to shrink to fit. */
  readonly scaled: boolean;
}

/**
 * The load check run at session start: `system + tools + head + summary + K + 0.1T <= T`.
 * When it fails, K and the summary shrink together; when nothing fits, the session is refused.
 */
export function fitLoad(budget: Budget, parts: LoadParts): LoadFit {
  const fixed = parts.system + parts.tools + parts.head;
  const room = budget.trigger - fixed - budget.summaryCap;
  if (room <= 0) throw new PrefixTooLargeError(fixed, budget.trigger);
  const wanted = budget.keep + parts.summary;
  if (wanted <= room) return { keep: budget.keep, summary: parts.summary, scaled: false };
  const factor = room / wanted;
  return { keep: Math.floor(budget.keep * factor), summary: Math.floor(parts.summary * factor), scaled: true };
}
