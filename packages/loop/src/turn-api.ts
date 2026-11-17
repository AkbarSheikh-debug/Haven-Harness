import { onMeasured } from '@hn/context';
import { ProviderError, contextTokens, withRetry, type ModelReply, type Usage } from '@hn/provider';
import { assistantRow, toProviderMessages } from './messages.ts';
import { envelopeFor, runCompaction } from './turn-compact.ts';
import type { Action, TurnContext, TurnState } from './types.ts';

function addUsage(state: TurnState, usage: Usage | null): void {
  if (usage === null) return;
  state.usage = {
    input: state.usage.input + usage.input,
    output: state.usage.output + usage.output,
    cacheRead: state.usage.cacheRead + usage.cacheRead,
    cacheWrite: state.usage.cacheWrite + usage.cacheWrite,
  };
  state.lastContext = contextTokens(usage);
}

/** The first provider count after a fold says whether the fold helped; the breaker needs that answer. */
function judgeLastFold(ctx: TurnContext, usage: Usage | null): void {
  if (usage === null) return;
  const { compaction, config } = ctx;
  compaction.guards = onMeasured(compaction.guards, (config.now ?? Date.now)(), contextTokens(usage), compaction.budget.trigger);
}

async function requestReply(ctx: TurnContext): Promise<ModelReply> {
  const { config, log, state } = ctx;
  state.partialText = '';
  // Nothing goes to the provider until the log says what we are about to do.
  await log.flush();
  const signal = ctx.callSignal();
  return withRetry(
    () =>
      config.provider.complete({
        model: config.model,
        system: config.system,
        tools: config.tools.specs,
        messages: toProviderMessages(log.events),
        maxOutputTokens: config.maxOutputTokens,
        signal,
        ...(config.effort === undefined ? {} : { effort: config.effort }),
        ...(state.graceCall ? { toolChoice: 'none' as const } : {}),
        onEvent: (event) => {
          if (event.type === 'text') state.partialText += event.text;
          config.onEvent?.(event);
        },
      }),
    {
      ...config.retry,
      signal,
      onRetry: (error, attempt, delayMs) => {
        log.append('llm/retry', { reason: error.reason, attempt, delayMs, status: error.status });
      },
    },
  );
}

/** A correction keeps what the model already said, then adds the correction after it. */
function applyRedirect(ctx: TurnContext, correction: string): void {
  const { log, state } = ctx;
  if (state.partialText !== '') {
    log.append('assistant/message', { text: state.partialText, toolCalls: [], opaque: [] }, 'model-derived');
  }
  log.append('user/message', { text: correction }, 'user');
  log.append('step/end', { stepId: state.stepId, reason: 'redirected' });
}

export async function callModel(ctx: TurnContext): Promise<ModelReply | Action> {
  const { state, log } = ctx;
  try {
    const reply = await requestReply(ctx);
    addUsage(state, reply.usage);
    judgeLastFold(ctx, reply.usage);
    log.append('assistant/attempt', {
      envelope: envelopeFor(ctx.config),
      model: reply.model,
      stopReason: reply.stopReason,
      usage: reply.usage,
      transformations: reply.transformations ?? [],
    });
    log.append('assistant/message', assistantRow(reply), 'model-derived');
    return reply;
  } catch (error) {
    if (!(error instanceof ProviderError)) throw error;
    if (error.reason === 'aborted') {
      const correction = ctx.takeRedirect();
      if (correction === null) return state.finish('cancelled');
      applyRedirect(ctx, correction);
      return 'next_iteration';
    }
    if (error.reason === 'context_too_long') {
      if (state.overflowRetried) {
        return state.finish('window_full', 'The provider still says the context is too long after the largest fold.');
      }
      // One maximal balanced reduction, then one retry.
      state.overflowRetried = true;
      await runCompaction(ctx, 'overflow');
      log.append('step/end', { stepId: state.stepId, reason: 'compacted' });
      return 'next_iteration';
    }
    return state.finish('failed', `${error.reason}: ${error.message}`);
  }
}
