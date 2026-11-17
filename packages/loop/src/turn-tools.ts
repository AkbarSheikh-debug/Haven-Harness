import { FlushFailedError } from '@hn/core';
import type { ModelReply } from '@hn/provider';
import { refreshAfterTools } from './turn-instructions.ts';
import type { Action, ToolCallRequest, ToolOutcome, TurnContext } from './types.ts';

const MAX_STRIKES = 3;

interface PlannedCall {
  readonly call: ToolCallRequest;
  /** Set when the call failed validation and must not run. */
  readonly rejected?: ToolOutcome;
}

const rejection = (content: string): ToolOutcome => ({ content, isError: true, origin: 'harness' });

/** Ordered runs. A call joins a parallel run only if it is safe and overlaps no writer in it. */
export function planSegments(ctx: TurnContext, calls: readonly PlannedCall[]): PlannedCall[][] {
  const { tools } = ctx.config;
  const segments: PlannedCall[][] = [];
  let run: PlannedCall[] = [];
  let reads = new Set<string>();
  let writes = new Set<string>();

  const flushRun = (): void => {
    if (run.length > 0) segments.push(run);
    run = [];
    reads = new Set();
    writes = new Set();
  };

  for (const planned of calls) {
    const { call } = planned;
    if (planned.rejected !== undefined || !tools.isConcurrencySafe(call.name, call.args)) {
      flushRun();
      segments.push([planned]);
      continue;
    }
    const touched = tools.touches(call.name, call.args);
    const overlaps =
      touched.writes.some((path) => reads.has(path) || writes.has(path)) ||
      touched.reads.some((path) => writes.has(path));
    if (overlaps) flushRun();
    run.push(planned);
    touched.reads.forEach((path) => reads.add(path));
    touched.writes.forEach((path) => writes.add(path));
  }
  flushRun();
  return segments;
}

/**
 * A throw from the dispatcher still gives the call its result. Without one the call stays open on the surface:
 * a provider refuses the next request, and no fold can cut past it, so the window only grows.
 */
async function runPlanned(ctx: TurnContext, planned: PlannedCall): Promise<ToolOutcome> {
  if (planned.rejected !== undefined) return planned.rejected;
  try {
    return await ctx.config.tools.run(planned.call, ctx.signal);
  } catch (error) {
    // A log that cannot be written means nothing else may happen.
    if (error instanceof FlushFailedError) throw error;
    return rejection(`${planned.call.name} failed inside the harness: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** A rolling pool. Results are returned in call order, however they finish. */
async function runSegment(ctx: TurnContext, segment: readonly PlannedCall[]): Promise<ToolOutcome[]> {
  const results = new Array<ToolOutcome>(segment.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (let index = next; index < segment.length; index = next) {
      next += 1;
      const planned = segment[index];
      if (planned !== undefined) results[index] = await runPlanned(ctx, planned);
    }
  };
  await Promise.all(Array.from({ length: Math.min(ctx.config.maxParallelToolCalls, segment.length) }, worker));
  return results;
}

function validate(ctx: TurnContext, calls: readonly ToolCallRequest[]): PlannedCall[] {
  const { state, config } = ctx;
  return calls.map((call) => {
    const check = config.tools.check(call);
    if (check.kind === 'ok') return { call: { ...call, name: check.name, args: check.args } };
    if (check.kind === 'unknown') state.unknownStrikes += 1;
    else state.invalidStrikes += 1;
    return { call, rejected: rejection(check.message) };
  });
}

/**
 * Validates, records intent, runs, then records every result. The assistant row was
 * appended before this, and the flush here is the promise that intent is on disk
 * before any tool has an effect.
 */
export async function runToolRound(ctx: TurnContext, reply: ModelReply): Promise<Action> {
  const { log, state } = ctx;
  const calls = reply.parts.flatMap((part) =>
    part.type === 'tool_call' ? [{ id: part.id, name: part.name, args: part.args }] : [],
  );
  const planned = validate(ctx, calls);
  for (const { call } of planned) log.append('tool/call', { callId: call.id, name: call.name });
  await log.flush();
  ctx.config.tools.beginStep?.();

  // Messages for the model (hook output, guardrail warnings) wait until every result of the round is in, so no
  // text ever lands between two results of one round.
  const later: { text: string; origin: ToolOutcome['origin'] }[] = [];
  const hooks = ctx.config.hooks;
  const gated: PlannedCall[] = [];
  for (const entry of planned) {
    if (entry.rejected !== undefined || hooks === undefined) {
      gated.push(entry);
      continue;
    }
    const pre = await hooks.preTool(entry.call, ctx.signal);
    later.push(...pre.messages);
    gated.push(pre.blocked === null ? entry : { call: entry.call, rejected: rejection(`A hook blocked this call: ${pre.blocked}`) });
  }

  let stop: string | null = null;
  for (const segment of planSegments(ctx, gated)) {
    const outcomes = await runSegment(ctx, segment);
    for (const [index, { call }] of segment.entries()) {
      const outcome = outcomes[index] ?? rejection('The tool returned nothing.');
      const images = outcome.isError || outcome.images === undefined || outcome.images.length === 0 ? [] : outcome.images;
      const seen = images.length > 0 && ctx.config.caps.vision;
      const content = images.length > 0 && !seen ? `${outcome.content}\nThis model cannot see images, so only this description was sent.` : outcome.content;
      log.append(
        'tool/result',
        { callId: call.id, content, isError: outcome.isError, ...(seen ? { images } : {}) },
        outcome.origin,
      );
      for (const record of outcome.records ?? []) log.append(record.type, { ...record.data, callId: call.id });
      const verdict = state.guard.observe(call.name, call.args, outcome.content, outcome.isError);
      if (verdict.kind === 'warn') later.push({ text: verdict.message, origin: 'harness' });
      if (verdict.kind === 'stop') stop = verdict.message;
      if (hooks !== undefined && segment[index]?.rejected === undefined) {
        later.push(...(await hooks.postTool(call, outcome, ctx.signal)).messages);
      }
    }
  }
  for (const message of later) log.append('user/message', { text: message.text }, message.origin);

  const ran = planned.filter((p) => p.rejected === undefined).map((p) => p.call);
  await refreshAfterTools(ctx.config, log, ran);
  ctx.config.stopGate?.noteRound(ran.map((call) => call.name));
  for (const message of (await ctx.config.afterToolRound?.(ran.map((call) => call.name), ctx.signal)) ?? []) {
    log.append('user/message', { text: message.text }, message.origin);
  }
  log.append('step/end', { stepId: state.stepId });
  if (state.unknownStrikes >= MAX_STRIKES || state.invalidStrikes >= MAX_STRIKES) {
    return state.finish('invalid_calls', 'The model kept sending calls that cannot run.');
  }
  return stop === null ? 'next_iteration' : state.finish('guardrail', stop);
}
