import { randomUUID } from 'node:crypto';
import type { SessionEvent } from '@hn/core';
import { closingRecords } from '@hn/session';
import { compactIfNeeded } from './turn-compact.ts';
import type { Action, TurnContext, TurnEnd } from './types.ts';

const WRAP_UP_NOTICE = 'You have used 80% of the time budget for this task. Start wrapping up.';

/** Every token the provider processed for this session, from the usage on its `assistant/attempt` rows. */
export function spentTokens(events: readonly SessionEvent[], counts: 'all' | 'fresh' = 'all'): number {
  const names = counts === 'fresh' ? ['input', 'output', 'cacheWrite'] : ['input', 'output', 'cacheRead', 'cacheWrite'];
  let total = 0;
  for (const event of events) {
    if (event.type !== 'assistant/attempt') continue;
    const usage = event.data['usage'] as Partial<Record<string, unknown>> | null | undefined;
    if (typeof usage !== 'object' || usage === null) continue;
    for (const name of names) {
      const value = usage[name];
      if (typeof value === 'number' && Number.isFinite(value) && value > 0) total += value;
    }
  }
  return total;
}

/** Starts a lap: stop if asked to, spend one iteration, open a step. */
export function beginIteration(ctx: TurnContext): Action {
  const { state, config, log } = ctx;
  if (ctx.signal.aborted) return state.finish('cancelled');
  if (config.tokenBudget !== undefined) {
    const spent = spentTokens(log.events, config.tokenBudgetCounts);
    if (spent >= config.tokenBudget) return state.finish('budget', `The token budget is spent: ${spent} of ${config.tokenBudget} tokens.`);
  }
  if (state.apiCalls >= config.maxIterations && !state.graceCall) {
    state.graceCall = true;
    log.append(
      'user/message',
      { text: 'You have reached the iteration limit. Summarise what is done and what is left. Do not call tools.' },
      'harness',
    );
  } else if (state.graceCall && state.apiCalls > config.maxIterations) {
    return state.finish('budget');
  }
  state.apiCalls += 1;
  state.stepId = randomUUID();
  log.append('step/start', { stepId: state.stepId });
  return 'next_phase';
}

/** Takes in whatever arrived during the last lap, as ordinary logged rows. */
export function prepareIteration(ctx: TurnContext): Action {
  const { state, config, log } = ctx;
  for (const text of ctx.takeSteers()) log.append('user/message', { text }, 'user');
  for (const notice of ctx.takeNotices()) log.append('user/message', { text: notice.text, notice: true }, notice.origin);

  const budget = config.wallClockBudgetMs;
  if (budget !== undefined && !state.warnedWallClock) {
    const elapsed = (config.now ?? Date.now)() - state.startedAt;
    if (elapsed >= budget * 0.8) {
      state.warnedWallClock = true;
      log.append('user/message', { text: WRAP_UP_NOTICE }, 'harness');
    }
  }
  return 'next_phase';
}

/**
 * Runs at the top of every lap, right after tools, which is what blows up a window. Compaction runs here,
 * at a step boundary, so it can never split a call from its result.
 */
export async function checkBudget(ctx: TurnContext): Promise<Action> {
  if ((await compactIfNeeded(ctx)) === 'ok') return 'next_phase';
  return ctx.state.finish('window_full', 'The context window is still full after compaction. Start a new session to continue.');
}

/** Closes everything this turn left open, so the log is legal however the turn ended. */
export function closeOpenRecords(ctx: TurnContext, end: TurnEnd): void {
  for (const record of closingRecords(ctx.log.events)) {
    const data = { ...record.data };
    if (record.type === 'tool/result' && end === 'cancelled') {
      data['content'] = 'CANCELLED: the user stopped this before it finished.';
      data['outcome'] = 'cancelled';
    }
    if (record.type === 'step/end' || record.type === 'turn/end') data['reason'] = end;
    ctx.log.append(record.type, data, record.origin);
  }
}
