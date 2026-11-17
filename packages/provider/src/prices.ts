import type { Usage } from './types.ts';

/** Dollars per million tokens. Unknown models show no cost, rather than a wrong one. */
const PRICES: Readonly<Record<string, { input: number; output: number; cacheRead: number; cacheWrite: number }>> = {
  'claude-opus-5-5': { input: 4, output: 20, cacheRead: 0.2, cacheWrite: 5 },
  'claude-sonnet-5-5': { input: 2, output: 10, cacheRead: 0.2, cacheWrite: 2.5 },
};

export function costOf(model: string, usage: Usage): number | null {
  const price = PRICES[model];
  if (price === undefined) return null;
  const dollars =
    usage.input * price.input +
    usage.output * price.output +
    usage.cacheRead * price.cacheRead +
    usage.cacheWrite * price.cacheWrite;
  return dollars / 1_000_000;
}
