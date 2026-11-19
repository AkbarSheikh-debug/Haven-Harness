import type { Usage } from './types.ts';

/** Dollars per million tokens. */
export interface Price {
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number;
  readonly cacheWrite: number;
}

/**
 * Unknown models show no cost, rather than a wrong one (Phase 10, decision 7). A wrong price is worse than none, so
 * this table is small and a person can add to it; nothing is guessed for a model that is not in it.
 */
const BUILT_IN: Readonly<Record<string, Price>> = {
  'claude-opus-5-5': { input: 4, output: 20, cacheRead: 0.2, cacheWrite: 5 },
  'claude-sonnet-5-5': { input: 2, output: 10, cacheRead: 0.2, cacheWrite: 2.5 },
};

let overrides: ReadonlyMap<string, Price> = new Map();
let overridesChecked: string | null = null;

/** A price above this is a typo (a million dollars per million tokens), not a price. */
const MAX_PRICE = 10_000;
const FIELDS = ['input', 'output', 'cacheRead', 'cacheWrite'] as const;

export interface ParsedPrices {
  readonly prices: ReadonlyMap<string, Price>;
  /** The date the person says they checked these prices, shown beside every report that used them. */
  readonly checked: string | null;
  /** Entries that were refused, each with why. A refused entry is simply unpriced, so its cost shows as unknown. */
  readonly problems: readonly string[];
}

/**
 * Reads a price file: `{ "checked": "2026-11-19", "prices": { "<model>": { "input": 1, "output": 5, "cacheRead": 0.1,
 * "cacheWrite": 1.25 } } }`, dollars per million tokens. All four numbers are required, because a missing one would
 * be a guess, and a guess is a wrong price. An entry that is not exactly that is refused and named.
 */
export function parsePriceFile(text: string): ParsedPrices {
  const problems: string[] = [];
  const prices = new Map<string, Price>();
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { prices, checked: null, problems: ['the price file is not JSON'] };
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { prices, checked: null, problems: ['the price file is not an object'] };
  const file = raw as Record<string, unknown>;
  const checked = typeof file['checked'] === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(file['checked']) ? file['checked'] : null;
  if (checked === null) problems.push('"checked" must be the date you checked these prices, as YYYY-MM-DD');
  const table = file['prices'];
  if (typeof table !== 'object' || table === null || Array.isArray(table)) return { prices, checked, problems: [...problems, '"prices" must be an object of model names'] };
  for (const [model, entry] of Object.entries(table)) {
    if (model === '' || model.length > 200 || /[\u0000-\u001f\u007f]/.test(model)) {
      problems.push('a model name is empty, too long or has control characters');
      continue;
    }
    const record = typeof entry === 'object' && entry !== null && !Array.isArray(entry) ? (entry as Record<string, unknown>) : null;
    const numbers = record === null ? null : FIELDS.map((field) => record[field]);
    const exact = record !== null && Object.keys(record).length === FIELDS.length;
    if (numbers === null || !exact || !numbers.every((value) => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_PRICE)) {
      problems.push(`${model}: it needs exactly input, output, cacheRead and cacheWrite, each a number from 0 to ${MAX_PRICE} dollars per million tokens`);
      continue;
    }
    const [input, output, cacheRead, cacheWrite] = numbers as [number, number, number, number];
    prices.set(model, { input, output, cacheRead, cacheWrite });
  }
  // Without a date nothing is used: a price table nobody dated is the kind of thing that goes stale unseen.
  return checked === null ? { prices: new Map(), checked: null, problems } : { prices, checked, problems };
}

/** Prices from a person's file win over the built-in ones, model by model. */
export function registerPrices(prices: ReadonlyMap<string, Price>, checked: string | null): void {
  overrides = new Map(prices);
  overridesChecked = checked;
}

export function resetPrices(): void {
  overrides = new Map();
  overridesChecked = null;
}

export interface PriceTableInfo {
  readonly source: 'built-in' | 'built-in plus file';
  readonly checked: string | null;
  readonly models: readonly string[];
}

export function priceTableInfo(): PriceTableInfo {
  return { source: overrides.size === 0 ? 'built-in' : 'built-in plus file', checked: overridesChecked, models: [...new Set([...Object.keys(BUILT_IN), ...overrides.keys()])].sort() };
}

/** `Object.hasOwn`, so a model called `constructor` or `__proto__` is unpriced, not a number made of `NaN`. */
export function priceOf(model: string): Price | null {
  const own = overrides.get(model);
  if (own !== undefined) return own;
  return Object.hasOwn(BUILT_IN, model) ? (BUILT_IN[model] as Price) : null;
}

export function costOf(model: string, usage: Usage): number | null {
  const price = priceOf(model);
  if (price === null) return null;
  const dollars =
    usage.input * price.input +
    usage.output * price.output +
    usage.cacheRead * price.cacheRead +
    usage.cacheWrite * price.cacheWrite;
  return dollars / 1_000_000;
}
