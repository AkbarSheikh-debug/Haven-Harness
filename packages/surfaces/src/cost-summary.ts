import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { sanitizeForDisplay } from '@hn/core';
import type { JobCost, JobCostLine } from '@hn/orchestrate';
import { parsePriceFile, registerPrices } from '@hn/provider';

/** A person's own prices, beside the log key: `<home>/prices.json`. See `parsePriceFile` for the shape. */
export const PRICE_FILE = 'prices.json';
const MAX_PRICE_FILE_BYTES = 256 * 1024;

/**
 * Loads the person's price file, if there is one. No file is normal and silent. A file with a problem is said once
 * on stderr and never stops hn: the prices it could not read are unpriced, so their cost shows as unknown.
 */
export async function loadPriceFile(home: string, warn: (text: string) => void): Promise<void> {
  let text: string;
  try {
    text = await readFile(join(home, PRICE_FILE), 'utf8');
  } catch {
    return;
  }
  if (text.length > MAX_PRICE_FILE_BYTES) {
    warn(`hn: ${PRICE_FILE} is larger than ${MAX_PRICE_FILE_BYTES} bytes, so it was not used.\n`);
    return;
  }
  const parsed = parsePriceFile(text);
  for (const problem of parsed.problems) warn(`hn: ${PRICE_FILE}: ${sanitizeForDisplay(problem)}\n`);
  registerPrices(parsed.prices, parsed.checked);
}

/** Every job's total added together, for a fleet's last line. Null when no job reported a cost. */
export function sumJobCosts(results: readonly { readonly cost?: JobCost }[]): JobCostLine | null {
  let input = 0;
  let output = 0;
  let cacheRead = 0;
  let cacheWrite = 0;
  let dollars: number | null = 0;
  const unpriced = new Set<string>();
  let any = false;
  for (const result of results) {
    if (result.cost === undefined) continue;
    any = true;
    const { total } = result.cost;
    input += total.input;
    output += total.output;
    cacheRead += total.cacheRead;
    cacheWrite += total.cacheWrite;
    dollars = dollars === null || total.dollars === null ? null : dollars + total.dollars;
    for (const model of total.unpriced) unpriced.add(model);
  }
  if (!any) return null;
  const readIn = input + cacheRead + cacheWrite;
  return { input, output, cacheRead, cacheWrite, cacheHitRatio: readIn === 0 ? null : cacheRead / readIn, dollars, unpriced: [...unpriced].sort() };
}

export function formatCostLine(line: JobCostLine): string {
  const money = line.dollars === null ? `unknown (no price for ${line.unpriced.map((model) => sanitizeForDisplay(model)).join(', ')})` : `$${line.dollars.toFixed(4)}`;
  const cached = line.cacheHitRatio === null ? '' : `, ${Math.round(line.cacheHitRatio * 100)}% cached`;
  return `Cost: ${money}, ${line.input + line.cacheRead + line.cacheWrite} in, ${line.output} out${cached}.`;
}
