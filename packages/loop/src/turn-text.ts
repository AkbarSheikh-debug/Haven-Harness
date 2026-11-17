import type { ModelReply } from '@hn/provider';
import type { Action, HookOutcome, TurnContext } from './types.ts';

const MAX_CONTINUATIONS = 4;
const MAX_EMPTY_RETRIES = 2;
const EMPTY_NUDGE = 'Your last reply was empty. Reply to the user, or call a tool.';
const CUT_OFF_NOTICE = 'Your reply was cut off by the output limit. Continue from where you stopped.';
const CUT_OFF_TOOL_NOTICE =
  'Your reply was cut off while writing a tool call, so it did not run. Make the call again, smaller if you can.';

const replyText = (reply: ModelReply): string =>
  reply.parts.flatMap((part) => (part.type === 'text' ? [part.text] : [])).join('');

function closeStep(ctx: TurnContext): void {
  ctx.log.append('step/end', { stepId: ctx.state.stepId });
}

function handleEmpty(ctx: TurnContext): Action {
  const { state, log } = ctx;
  closeStep(ctx);
  // The nudge is logged once. Later tries just ask again, so the prefix stays append-only.
  if (!state.nudged) {
    state.nudged = true;
    log.append('user/message', { text: EMPTY_NUDGE }, 'harness');
    return 'next_iteration';
  }
  if (state.emptyRetries < MAX_EMPTY_RETRIES) {
    state.emptyRetries += 1;
    return 'next_iteration';
  }
  state.text = '(empty)';
  return state.finish('done');
}

/**
 * The stop gate: before a final answer reaches the user, checks such as verify-on-stop may send the model back.
 * The rejected answer stays in the log as the model's candidate; the user sees the answer that got through.
 */
const MAX_HOOK_RETRIES = 3;

/** A blocking pre_verify or Stop hook sends the model back, a few times at most. */
async function hookHold(ctx: TurnContext, outcome: HookOutcome, label: string): Promise<boolean> {
  const { state, log } = ctx;
  for (const message of outcome.messages) log.append('user/message', { text: message.text }, message.origin);
  if (outcome.blocked === null || state.hookRetries >= MAX_HOOK_RETRIES || ctx.signal.aborted) return false;
  state.hookRetries += 1;
  const text = `A ${label} hook held your answer: ${outcome.blocked}\nDeal with it, then answer again.`;
  log.append('user/message', { text }, 'hook');
  return true;
}

async function passStopGate(ctx: TurnContext, text: string): Promise<Action> {
  const { state, log, config } = ctx;
  const hooks = state.graceCall ? undefined : config.hooks;
  if (hooks !== undefined && (await hookHold(ctx, await hooks.preVerify(ctx.signal), 'pre_verify'))) return 'next_iteration';
  const gate = config.stopGate;
  const verdict = gate === undefined || state.graceCall ? { kind: 'accept' as const } : await gate.check(ctx.signal);
  if (verdict.kind === 'retry' && !ctx.signal.aborted) {
    log.append('user/message', { text: verdict.text, stopGate: true }, verdict.origin);
    return 'next_iteration';
  }
  if (hooks !== undefined && (await hookHold(ctx, await hooks.stop(text, ctx.signal), 'Stop'))) return 'next_iteration';
  state.text += text;
  const note = verdict.kind === 'accept' ? verdict.note : undefined;
  return state.finish(state.graceCall ? 'budget' : 'done', note);
}

/** Handles a reply with nothing to run: finished, cut off, refused or empty. */
export async function finishTextReply(ctx: TurnContext, reply: ModelReply): Promise<Action> {
  const { state, log } = ctx;
  const text = replyText(reply);

  if (reply.stopReason === 'refusal') {
    closeStep(ctx);
    state.text = text;
    return state.finish('refusal', 'The model declined this request.');
  }
  if (reply.stopReason === 'length') {
    closeStep(ctx);
    state.text += text;
    if (state.continuations >= MAX_CONTINUATIONS) return state.finish('done', 'The reply hit the output limit.');
    state.continuations += 1;
    log.append('user/message', { text: text === '' ? CUT_OFF_TOOL_NOTICE : CUT_OFF_NOTICE }, 'harness');
    return 'next_iteration';
  }
  if (reply.stopReason === 'pause') {
    closeStep(ctx);
    return 'next_iteration';
  }
  if (text === '') return handleEmpty(ctx);

  closeStep(ctx);
  return passStopGate(ctx, text);
}
