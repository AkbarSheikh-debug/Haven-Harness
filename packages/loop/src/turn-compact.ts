import { randomUUID } from 'node:crypto';
import {
  buildSummaryRequest,
  chooseShape,
  composeSummary,
  envelopeOf,
  estimateContext,
  estimateRow,
  estimateText,
  finishSummary,
  planStateText,
  mayCompact,
  onFailure,
  onFolded,
  onNoop,
  onSummarySource,
  planFold,
  planPrune,
  pruneRecords,
  shouldFold,
  shrinkEdits,
  summarizeWithFallback,
  summaryBudget,
  summaryModelBenched,
  summaryRecords,
  type ContextEstimate,
  type PendingRecord,
  type SummaryAttempt,
  type SummaryShape,
  type UsageAnchor,
} from '@hn/context';
import type { SessionEvent } from '@hn/core';
import { Redactor } from '@hn/security';
import { deriveSurface } from '@hn/session';
import { surfaceMessages } from './messages.ts';
import { reemitSnapshot } from './turn-instructions.ts';
import type { LoopConfig, SummaryRoute, TurnContext } from './types.ts';

const SUMMARY_TIMEOUT_MS = 120_000;
/** Within this fraction of W - O a fold runs even while a guard says wait, using the static summary only. */
const HARD_RATIO = 0.95;
/** Below this many tokens for its own text, no model can write the eleven sections, so none is asked. */
const MIN_MODEL_BUDGET = 200;

export type CompactReason = 'auto' | 'manual' | 'overflow';
export type CompactOutcome = 'folded' | 'pruned' | 'noop' | 'failed' | 'aborted';

/** What a fold needs from a turn. `/compact` builds one outside a turn. */
export type CompactContext = Pick<TurnContext, 'config' | 'log' | 'signal' | 'compaction'>;

interface FoldResult {
  readonly outcome: CompactOutcome;
  readonly detail: Record<string, unknown>;
  /** Set when every model failed and the static summary was used, so the failure cooldown applies. */
  readonly modelsFailed?: { readonly timedOut: boolean };
}

const now = (config: LoopConfig): number => (config.now ?? Date.now)();

export function envelopeFor(config: LoopConfig): string {
  return envelopeOf({ model: config.model, system: config.system, tools: config.tools.specs });
}

function fixedTokens(config: LoopConfig): number {
  return estimateText(config.system) + estimateText(JSON.stringify(config.tools.specs));
}

/**
 * The provider's newest count for this envelope, from the log. A fold after it makes it stale,
 * because the provider counted rows that are no longer there.
 */
export function anchorFromLog(events: readonly SessionEvent[], envelope: string): UsageAnchor | null {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index] as SessionEvent;
    if (event.data['surfaceOp'] !== undefined) return null;
    if (event.type !== 'assistant/attempt') continue;
    const usage = event.data['usage'] as { input: number; output: number; cacheRead: number; cacheWrite: number } | null;
    if (usage === null || usage === undefined || event.data['envelope'] !== envelope) return null;
    const reply = events.slice(index + 1).find((next) => next.type === 'assistant/message');
    if (reply === undefined) return null;
    return { envelope, tokens: usage.input + usage.cacheRead + usage.cacheWrite + usage.output, atSeq: reply.seq };
  }
  return null;
}

const MAX_CALIBRATION = 4;

export function currentEstimate(ctx: CompactContext): ContextEstimate {
  const envelope = envelopeFor(ctx.config);
  const rows = deriveSurface(ctx.log.events);
  const prefixTokens = fixedTokens(ctx.config);
  const anchor = anchorFromLog(ctx.log.events, envelope);
  if (anchor !== null) {
    const position = rows.findIndex((row) => row.seq === anchor.atSeq);
    const ours = prefixTokens + rows.slice(0, position + 1).reduce((sum, row) => sum + estimateRow(row), 0);
    if (position !== -1 && ours > 0) {
      ctx.compaction.calibration = Math.min(MAX_CALIBRATION, Math.max(1, anchor.tokens / ours));
    }
  }
  const estimate = estimateContext({ rows, envelope, prefixTokens, anchor });
  return estimate.anchored ? estimate : { ...estimate, tokens: Math.ceil(estimate.tokens * ctx.compaction.calibration) };
}

/** Our row estimate scaled by the newest calibration, for planning a fold in the provider's units. */
function scaledRow(ctx: CompactContext): (row: SessionEvent) => number {
  const factor = ctx.compaction.calibration;
  return (row) => Math.ceil(estimateRow(row) * factor);
}

function append(ctx: CompactContext, records: readonly PendingRecord[]): void {
  for (const record of records) ctx.log.append(record.type, record.data, record.origin);
}

export function routesOf(config: LoopConfig): readonly SummaryRoute[] {
  return (
    config.compaction?.routes ?? [
      { source: 'main', provider: config.provider, model: config.model, window: config.caps.window },
    ]
  );
}

interface FoldWork {
  readonly surface: readonly SessionEvent[];
  readonly middle: readonly SessionEvent[];
  readonly redactor: Redactor;
  readonly replacedTokens: number;
  readonly shapes: Map<string, SummaryShape>;
}

function attemptFor(ctx: CompactContext, route: SummaryRoute, work: FoldWork): SummaryAttempt {
  const { config, compaction } = ctx;
  const { surface, middle, redactor, replacedTokens } = work;
  // The harness's verbatim quotes count toward the cap, so the model gets what is left.
  const quotes = estimateText(composeSummary('', surface, redactor));
  // What is really left under the cap. Promising more (this used a floor of 500) meant a small window told the
  // model 500 tokens and then rejected anything over its 409 cap: an obedient model could not pass (seen live).
  const budgetTokens = summaryBudget(compaction.budget, replacedTokens) - quotes;
  return {
    source: route.source,
    model: route.model,
    run: async () => {
      if (budgetTokens < MIN_MODEL_BUDGET) {
        const left = Math.max(0, budgetTokens);
        return { ok: false, reason: `Only ${left} tokens are left for a summary under the ${compaction.budget.summaryCap} cap, too few for a model to write one.` };
      }
      const lastMiddle = surface.findIndex((row) => row.seq === middle.at(-1)?.seq);
      const replayRows = surface.slice(0, lastMiddle + 1);
      const replayTokens = fixedTokens(config) + replayRows.reduce((sum, row) => sum + estimateRow(row), 0);
      const sameRoute = route.provider.route === config.provider.route && route.model === config.model;
      // Room for reasoning before the summary (thinking models spend output on it), within what the summary
      // route's window holds after the replay, in the provider's units. Never less than the summary's own budget.
      const room = route.window - Math.ceil(replayTokens * compaction.calibration) - compaction.budget.headroom;
      const outputTokens = Math.max(budgetTokens, Math.min(config.maxOutputTokens, room));
      const shape = chooseShape({ sameRoute, replayTokens, summaryWindow: route.window, budgetTokens: outputTokens });
      work.shapes.set(route.model, shape);
      const request = buildSummaryRequest({
        shape,
        model: route.model,
        budgetTokens,
        outputTokens,
        middle,
        redactor,
        replay: { system: config.system, tools: config.tools.specs, messages: surfaceMessages(replayRows) },
      });
      const timeout = AbortSignal.timeout(config.compaction?.timeoutMs ?? SUMMARY_TIMEOUT_MS);
      const reply = await route.provider.complete({ ...request, signal: AbortSignal.any([ctx.signal, timeout]) });
      return finishSummary({ reply, middle, surface, replacedTokens, maxTokens: compaction.budget.summaryCap, redactor });
    },
  };
}

/** Prunes, plans, shrinks and summarises. The caller writes `compaction/end` and settles the guards. */
async function fold(ctx: CompactContext, reason: CompactReason, staticOnly: boolean): Promise<FoldResult> {
  const { config, log, compaction } = ctx;
  const { budget } = compaction;
  const redactor = config.compaction?.redactor ?? new Redactor();
  const estimate = scaledRow(ctx);
  const fixed = Math.ceil(fixedTokens(config) * compaction.calibration);
  const keep = reason === 'overflow' ? 0 : budget.keep;
  const priorFolds = log.events.filter((event) => event.type === 'compaction/summary').length;
  const plan = (rows: readonly SessionEvent[]) =>
    planFold({ rows, budget, keep, fixedTokens: fixed, priorFolds, estimate });

  let surface = deriveSurface(log.events);
  const prune = planPrune(surface, plan(surface).tail[0] ?? Number.POSITIVE_INFINITY);
  let changed = prune.edits.length > 0;
  if (changed) {
    append(ctx, pruneRecords(surface, prune.edits));
    surface = deriveSurface(log.events);
    const after = fixed + surface.reduce((sum, row) => sum + estimate(row), 0);
    // The free step: under T again means no model call at all.
    if (reason === 'auto' && after < budget.trigger) return { outcome: 'pruned', detail: { saved: prune.saved } };
  }

  const second = plan(surface);
  const middleSeqs = new Set(second.middle);
  // Rows about to be summarised are not worth shrinking first.
  const shrink = second.shrink.filter((seq) => !middleSeqs.has(seq));
  if (shrink.length > 0) {
    append(ctx, pruneRecords(surface, shrinkEdits(surface, shrink)));
    surface = deriveSurface(log.events);
    changed = true;
  }
  const middle = surface.filter((row) => middleSeqs.has(row.seq));
  if (middle.length === 0) return { outcome: changed ? 'pruned' : 'noop', detail: {} };
  // Before these rows go, what matters in them reaches today's note (10.5). Not when a guard forced a fast fold, and a
  // failed flush never stops the fold.
  if (!staticOnly && reason !== 'overflow' && config.memory?.flush !== undefined) await config.memory.flush(middle, ctx.signal).catch(() => undefined);

  const replacedTokens = middle.reduce((sum, row) => sum + estimateRow(row), 0);
  // The summary must shrink what it replaces in our own units; calibration only moves the trigger.
  const benched = summaryModelBenched(compaction.guards, now(config));
  const routes = staticOnly ? [] : routesOf(config).filter((route) => !(benched && route.source === 'summary'));
  const work: FoldWork = { surface, middle, redactor, replacedTokens, shapes: new Map() };
  const chain = await summarizeWithFallback({
    attempts: routes.map((route) => attemptFor(ctx, route, work)),
    middle,
    surface,
    replacedTokens,
    redactor,
  });
  if (ctx.signal.aborted) return { outcome: 'aborted', detail: {} };
  const detail = { source: chain.source, model: chain.model, failures: chain.failures, timedOut: chain.timedOut };
  if (!chain.fits) return { outcome: changed ? 'pruned' : 'noop', detail };
  const shape = chain.source === 'static' ? 'static' : (work.shapes.get(chain.model ?? '') ?? 'flat');
  append(ctx, summaryRecords({ text: chain.text, origin: chain.origin, middle, source: chain.model ?? 'static', shape }));
  compaction.guards = onSummarySource(compaction.guards, now(config), chain.source);
  const modelsFailed = chain.source === 'static' && chain.failures.length > 0;
  return { outcome: 'folded', detail, ...(modelsFailed ? { modelsFailed: { timedOut: chain.timedOut } } : {}) };
}

function settleGuards(ctx: CompactContext, result: FoldResult): void {
  const { compaction } = ctx;
  const at = now(ctx.config);
  if (result.outcome === 'noop') compaction.guards = onNoop(compaction.guards, at);
  if (result.outcome === 'failed') compaction.guards = onFailure(compaction.guards, at, false);
  if (result.outcome === 'folded' || result.outcome === 'pruned') compaction.guards = onFolded(compaction.guards);
  if (result.modelsFailed !== undefined) {
    compaction.guards = onFailure(compaction.guards, at, result.modelsFailed.timedOut);
  }
}

/**
 * One fold, logged as `compaction/start ... compaction/end`. The start is flushed before any work, so a
 * crash leaves an unmatched start that repair closes as aborted. A fold is applied exactly when its
 * replacement rows are durable, whatever the end record says.
 */
export async function runCompaction(ctx: CompactContext, reason: CompactReason, staticOnly = false): Promise<CompactOutcome> {
  const { log, compaction } = ctx;
  const compactionId = randomUUID();
  const before = currentEstimate(ctx).tokens;
  log.append('compaction/start', { compactionId, reason, tokens: before, staticOnly });
  await log.flush();
  let result: FoldResult;
  try {
    result = await fold(ctx, reason, staticOnly);
  } catch (error) {
    result = { outcome: 'failed', detail: { error: error instanceof Error ? error.message : String(error) } };
  }
  settleGuards(ctx, result);
  if (result.outcome === 'folded') {
    await reemitSnapshot(ctx.config, log);
    // The goal and todos were made in turns the summary just replaced, so they are sent again whole.
    const plan = planStateText(log.events);
    if (plan !== null) log.append('user/message', { text: plan, planState: true }, 'model-derived');
  }
  log.append('compaction/end', {
    compactionId,
    outcome: result.outcome,
    ...result.detail,
    tokensBefore: before,
    tokensAfter: currentEstimate(ctx).tokens,
    guards: compaction.guards,
    ...(result.outcome === 'aborted' ? { aborted: true } : {}),
  });
  await log.flush();
  return result.outcome;
}

/**
 * The check at the top of every lap, which is also right after tools. Folds when the count says so and
 * the guards allow; near W - O it folds even against a guard, with the static summary only.
 * Returns `full` when the window is still too full to call the model.
 */
export async function compactIfNeeded(ctx: CompactContext): Promise<'ok' | 'full'> {
  const { config, compaction } = ctx;
  const { budget } = compaction;
  const estimate = currentEstimate(ctx);
  if (!shouldFold(estimate, budget, config.caps.usage).fold) return 'ok';
  const hard = Math.floor((budget.window - budget.output) * HARD_RATIO);
  if (mayCompact(compaction.guards, now(config)).allowed) await runCompaction(ctx, 'auto');
  else if (estimate.tokens >= hard) await runCompaction(ctx, 'auto', true);
  else return 'ok';
  return currentEstimate(ctx).tokens >= budget.window - budget.output ? 'full' : 'ok';
}
