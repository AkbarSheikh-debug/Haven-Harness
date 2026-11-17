import type { SessionEvent } from '@hn/core';
import { costOf, type Usage } from '@hn/provider';

/** What a session or a family spent. Dollars are null when any part of it ran on a model without a known price. */
export interface Spend {
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number;
  readonly cacheWrite: number;
  readonly dollars: number | null;
}

export const NO_SPEND: Spend = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, dollars: 0 };

/** Every token the provider processed for us: fresh input, cache reads and writes, and output. */
export function tokensOf(spend: Pick<Spend, 'input' | 'output' | 'cacheRead' | 'cacheWrite'>): number {
  return spend.input + spend.output + spend.cacheRead + spend.cacheWrite;
}

export function usageOf(value: unknown): Usage | null {
  if (typeof value !== 'object' || value === null) return null;
  const record = value as Record<string, unknown>;
  const numbers = ['input', 'output', 'cacheRead', 'cacheWrite'].map((name) => record[name]);
  if (!numbers.every((number) => typeof number === 'number' && Number.isFinite(number) && number >= 0)) return null;
  const [input, output, cacheRead, cacheWrite] = numbers as [number, number, number, number];
  return { input, output, cacheRead, cacheWrite };
}

export function addSpend(a: Spend, b: Spend): Spend {
  return {
    input: a.input + b.input,
    output: a.output + b.output,
    cacheRead: a.cacheRead + b.cacheRead,
    cacheWrite: a.cacheWrite + b.cacheWrite,
    dollars: a.dollars === null || b.dollars === null ? null : a.dollars + b.dollars,
  };
}

export function spendOf(model: string, usage: Usage): Spend {
  return { ...usage, dollars: costOf(model, usage) };
}

/** A session's own spend: the usage on every `assistant/attempt` row. A fold or a resume keeps those rows, so the ledger survives both. */
export function ownSpend(events: readonly SessionEvent[]): Spend {
  let total = NO_SPEND;
  for (const event of events) {
    if (event.type !== 'assistant/attempt') continue;
    const usage = usageOf(event.data['usage']);
    if (usage === null) continue;
    total = addSpend(total, spendOf(String(event.data['model'] ?? ''), usage));
  }
  return total;
}

/** The data of a `budget/charge` row: one child's spend, recorded in the parent when the child settles. */
export interface ChargeData {
  readonly child: string;
  readonly model: string;
  readonly usage: Usage;
  readonly dollars: number | null;
  readonly why: string;
  [key: string]: unknown;
}

export function chargeData(child: string, model: string, usage: Usage, why: string): ChargeData {
  return { child, model, usage, dollars: costOf(model, usage), why };
}

/** Spend by child, from the parent's `budget/charge` rows. */
export function childSpend(events: readonly SessionEvent[]): ReadonlyMap<string, Spend> {
  const byChild = new Map<string, Spend>();
  for (const event of events) {
    if (event.type !== 'budget/charge') continue;
    const usage = usageOf(event.data['usage']);
    const child = event.data['child'];
    if (usage === null || typeof child !== 'string') continue;
    const dollars = typeof event.data['dollars'] === 'number' ? event.data['dollars'] : null;
    byChild.set(child, addSpend(byChild.get(child) ?? NO_SPEND, { ...usage, dollars }));
  }
  return byChild;
}

/** The family: this session plus every child it charged. Delegation saves the window, not the bill, and this says so. */
export function familySpend(events: readonly SessionEvent[]): Spend {
  let total = ownSpend(events);
  for (const spend of childSpend(events).values()) total = addSpend(total, spend);
  return total;
}

export function formatSpend(spend: Spend): string {
  const dollars = spend.dollars === null ? '' : `, $${spend.dollars.toFixed(4)}`;
  return `${tokensOf(spend).toLocaleString('en-US')} tokens (${spend.input + spend.cacheRead + spend.cacheWrite} in, ${spend.output} out${dollars})`;
}
