import { randomUUID } from 'node:crypto';
import { buildMicroRequest, defragRecords, finishMicro, microRecords, nextMicroTarget } from '@hn/context';
import type { SessionEvent } from '@hn/core';
import { Redactor } from '@hn/security';
import { deriveSurface } from '@hn/session';
import { routesOf, type CompactContext } from './turn-compact.ts';

const MICRO_TIMEOUT_MS = 60_000;

export type MicroResult = 'folded' | 'failed' | 'skipped' | 'none';

/** Whether micro-compaction is on: the newest `/micro on|off` in the log, else the configured default. */
export function microEnabled(events: readonly SessionEvent[], fallback: boolean): boolean {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index] as SessionEvent;
    if (event.type === 'command/run' && event.data['command'] === '/micro') return event.data['enabled'] === true;
  }
  return fallback;
}

/**
 * One micro fold: the oldest unfolded exchange becomes a short summary in its own place, then old micro
 * rows are condensed if they pass 2,000 tokens. It runs only between turns, when every call has its result.
 * A failure leaves the exchange as it was; the third failure at one exchange skips it.
 */
export async function runMicro(ctx: CompactContext): Promise<MicroResult> {
  const { config, log } = ctx;
  const redactor = config.compaction?.redactor ?? new Redactor();
  const target = nextMicroTarget(deriveSurface(log.events), log.events);
  if (target === null) {
    const defrag = defragRecords(deriveSurface(log.events));
    for (const record of defrag) log.append(record.type, record.data, record.origin);
    if (defrag.length > 0) await log.flush();
    return 'none';
  }
  const { exchange } = target;
  const compactionId = randomUUID();
  log.append('compaction/start', { compactionId, kind: 'micro', exchange: exchange.startSeq, tokens: exchange.tokens });
  await log.flush();

  let result: MicroResult = 'skipped';
  let reason: string | null = null;
  if (!target.skip) {
    result = 'failed';
    for (const route of routesOf(config)) {
      try {
        const timeout = AbortSignal.timeout(config.compaction?.timeoutMs ?? MICRO_TIMEOUT_MS);
        const request = buildMicroRequest(exchange, route.model, redactor);
        const reply = await route.provider.complete({ ...request, signal: AbortSignal.any([ctx.signal, timeout]) });
        const outcome = await finishMicro(reply, exchange, redactor);
        if (outcome.ok) {
          for (const record of microRecords(exchange, outcome.text, outcome.origin)) {
            log.append(record.type, record.data, record.origin);
          }
          result = 'folded';
          break;
        }
        reason = outcome.reason;
      } catch (error) {
        reason = redactor.redact(error instanceof Error ? error.message : String(error)).slice(0, 300);
      }
    }
  }
  const defrag = result === 'folded' ? defragRecords(deriveSurface(log.events)) : [];
  for (const record of defrag) log.append(record.type, record.data, record.origin);
  log.append('compaction/end', {
    compactionId,
    kind: 'micro',
    exchange: exchange.startSeq,
    outcome: result,
    condensed: defrag.length,
    ...(reason === null || result === 'folded' ? {} : { reason }),
  });
  await log.flush();
  return result;
}
