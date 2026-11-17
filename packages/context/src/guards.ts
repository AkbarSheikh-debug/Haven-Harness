import type { SessionEvent } from '@hn/core';

const SECOND = 1_000;
/** Failure cooldown ladder on timeouts; any other failure waits a flat 30 s. */
const TIMEOUT_LADDER = [60 * SECOND, 300 * SECOND, 900 * SECOND] as const;
const OTHER_FAILURE_COOLDOWN = 30 * SECOND;
/** A fold that found nothing to change backs off without a strike. */
const NOOP_BACKOFF = 300 * SECOND;
/** Two ineffective folds in a row trip the breaker; one probe is allowed after this. */
const BREAKER_TRIPS_AFTER = 2;
const PROBE_AFTER = 300 * SECOND;
/** Two fallbacks in a row bench the summary model until a probe. */
const BENCH_AFTER = 2;

/** All four guards. Plain data, written into every `compaction/end`, so it survives a resume. */
export interface GuardState {
  readonly cooldownUntil: number;
  readonly timeoutStrikes: number;
  readonly noopUntil: number;
  readonly ineffective: number;
  readonly breakerOpenedAt: number | null;
  readonly fallbackStreak: number;
  readonly benchedAt: number | null;
  /** Set after a fold until the next provider count says whether it worked. */
  readonly awaitingJudgement: boolean;
}

export const FRESH_GUARDS: GuardState = {
  cooldownUntil: 0,
  timeoutStrikes: 0,
  noopUntil: 0,
  ineffective: 0,
  breakerOpenedAt: null,
  fallbackStreak: 0,
  benchedAt: null,
  awaitingJudgement: false,
};

export type GuardDecision =
  | { readonly allowed: true; readonly probe: boolean }
  | { readonly allowed: false; readonly reason: string; readonly until: number };

/** Whether a fold may run now. A manual `/compact` clears the cooldown and the no-op backoff. */
export function mayCompact(state: GuardState, now: number, manual = false): GuardDecision {
  if (state.breakerOpenedAt !== null) {
    const probeAt = state.breakerOpenedAt + PROBE_AFTER;
    if (now < probeAt && !manual) {
      return { allowed: false, reason: 'Compaction stopped helping, so it is paused until one probe.', until: probeAt };
    }
    return { allowed: true, probe: true };
  }
  if (!manual && now < state.cooldownUntil) {
    return { allowed: false, reason: 'Compaction failed recently and is cooling down.', until: state.cooldownUntil };
  }
  if (!manual && now < state.noopUntil) {
    return { allowed: false, reason: 'The last fold found nothing to change.', until: state.noopUntil };
  }
  return { allowed: true, probe: false };
}

export function clearForManual(state: GuardState): GuardState {
  return { ...state, cooldownUntil: 0, noopUntil: 0 };
}

export function onFailure(state: GuardState, now: number, timedOut: boolean): GuardState {
  if (!timedOut) return { ...state, cooldownUntil: now + OTHER_FAILURE_COOLDOWN };
  const step = TIMEOUT_LADDER[Math.min(state.timeoutStrikes, TIMEOUT_LADDER.length - 1)] as number;
  return { ...state, cooldownUntil: now + step, timeoutStrikes: state.timeoutStrikes + 1 };
}

export function onNoop(state: GuardState, now: number): GuardState {
  return { ...state, noopUntil: now + NOOP_BACKOFF };
}

/** A fold landed; whether it helped is judged on the next provider count, not on our estimate. */
export function onFolded(state: GuardState): GuardState {
  return { ...state, cooldownUntil: 0, timeoutStrikes: 0, awaitingJudgement: true };
}

/** The first provider-reported context after a fold. Still at or over T means the fold did not help. */
export function onMeasured(state: GuardState, now: number, reportedTokens: number, trigger: number): GuardState {
  if (!state.awaitingJudgement) return state;
  const judged = { ...state, awaitingJudgement: false };
  if (reportedTokens < trigger) return { ...judged, ineffective: 0, breakerOpenedAt: null };
  const ineffective = state.ineffective + 1;
  const trip = ineffective >= BREAKER_TRIPS_AFTER || state.breakerOpenedAt !== null;
  return { ...judged, ineffective, breakerOpenedAt: trip ? now : state.breakerOpenedAt };
}

export type SummarySource = 'summary' | 'fallback' | 'main' | 'static';

/** Which source wrote the summary. Fallbacks in a row bench the summary model; a clean run unbenches it. */
export function onSummarySource(state: GuardState, now: number, source: SummarySource): GuardState {
  if (source === 'summary') return { ...state, fallbackStreak: 0, benchedAt: null };
  const fallbackStreak = state.fallbackStreak + 1;
  return { ...state, fallbackStreak, benchedAt: fallbackStreak >= BENCH_AFTER ? (state.benchedAt ?? now) : null };
}

/** True while the summary model is benched and no probe is due. */
export function summaryModelBenched(state: GuardState, now: number): boolean {
  return state.benchedAt !== null && now < state.benchedAt + PROBE_AFTER;
}

function isGuardState(value: unknown): value is GuardState {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return (Object.keys(FRESH_GUARDS) as (keyof GuardState)[]).every((key) => {
    const field = record[key];
    if (key === 'awaitingJudgement') return typeof field === 'boolean';
    if (key === 'breakerOpenedAt' || key === 'benchedAt') return field === null || Number.isFinite(field);
    return Number.isFinite(field);
  });
}

/** The guards as the newest `compaction/end` that recorded them left them. A malformed record means fresh guards. */
export function guardsFromLog(events: readonly SessionEvent[]): GuardState {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index] as SessionEvent;
    // An end written by crash repair carries no guards; the one before it still holds the real state.
    if (event.type !== 'compaction/end' || !('guards' in event.data)) continue;
    const guards = event.data['guards'];
    return isGuardState(guards) ? { ...guards } : FRESH_GUARDS;
  }
  return FRESH_GUARDS;
}
