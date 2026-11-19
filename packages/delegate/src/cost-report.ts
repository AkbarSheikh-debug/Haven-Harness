import type { SessionEvent } from '@hn/core';
import { costOf, priceTableInfo, type PriceTableInfo, type Usage } from '@hn/provider';
import { usageOf } from './ledger.ts';

/**
 * What a session cost, split by role and by model (Phase 10, decision 7). Built from the log alone, so it is the same
 * for a live session, a resumed one and a log read later: the root session's own model calls, and each child's
 * charge joined to the role the manager recorded when it started it.
 *
 * A model with no price makes the dollars of everything it touched `null`, never 0, and is named in `unpriced`.
 * Tokens are always exact; only the money can be unknown.
 */

export interface CostLine {
  /** Fresh input tokens, not counting cache reads or writes. */
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number;
  readonly cacheWrite: number;
  /** Cache reads as a share of everything read in (fresh, cached and written); null when nothing was read in. */
  readonly cacheHitRatio: number | null;
  /** null when any model behind this line has no price. */
  readonly dollars: number | null;
  /** The models behind this line that have no price, so the reader can see why `dollars` is null. */
  readonly unpriced: readonly string[];
}

export interface RoleCost extends CostLine {
  readonly role: string;
}

export interface ModelCost extends CostLine {
  readonly model: string;
}

export interface CostReport {
  readonly total: CostLine;
  readonly byRole: readonly RoleCost[];
  readonly byModel: readonly ModelCost[];
  /** Where the prices came from and the date the person checked them, if they gave a file. */
  readonly prices: PriceTableInfo;
}

/** The role of the session you opened; children carry the role they were started under. */
export const ROOT_ROLE = 'main';
const UNKNOWN_ROLE = 'unknown';
const RECOVERED = 'recovered';

class Accumulator {
  input = 0;
  output = 0;
  cacheRead = 0;
  cacheWrite = 0;
  dollars: number | null = 0;
  readonly unpriced = new Set<string>();

  add(usage: Usage, dollars: number | null, model: string): void {
    this.input += usage.input;
    this.output += usage.output;
    this.cacheRead += usage.cacheRead;
    this.cacheWrite += usage.cacheWrite;
    if (dollars === null) {
      this.dollars = null;
      this.unpriced.add(model);
    } else if (this.dollars !== null) {
      this.dollars += dollars;
    }
  }

  line(): CostLine {
    const readIn = this.input + this.cacheRead + this.cacheWrite;
    return {
      input: this.input,
      output: this.output,
      cacheRead: this.cacheRead,
      cacheWrite: this.cacheWrite,
      cacheHitRatio: readIn === 0 ? null : this.cacheRead / readIn,
      dollars: this.dollars,
      unpriced: [...this.unpriced].sort(),
    };
  }
}

function bucket(map: Map<string, Accumulator>, key: string): Accumulator {
  let found = map.get(key);
  if (found === undefined) {
    found = new Accumulator();
    map.set(key, found);
  }
  return found;
}

export function costReport(events: readonly SessionEvent[]): CostReport {
  const roleOfChild = new Map<string, string>();
  for (const event of events) {
    if (event.type !== 'subagent/catalog') continue;
    const child = event.data['child'];
    const role = event.data['role'];
    if (typeof child === 'string' && typeof role === 'string') roleOfChild.set(child, role);
  }
  const total = new Accumulator();
  const roles = new Map<string, Accumulator>();
  const models = new Map<string, Accumulator>();
  const charge = (role: string, model: string, usage: Usage, dollars: number | null): void => {
    total.add(usage, dollars, model);
    bucket(roles, role).add(usage, dollars, model);
    bucket(models, model).add(usage, dollars, model);
  };
  for (const event of events) {
    const usage = usageOf(event.data['usage']);
    if (usage === null) continue;
    if (event.type === 'assistant/attempt') {
      const model = String(event.data['model'] ?? '');
      charge(ROOT_ROLE, model, usage, costOf(model, usage));
    } else if (event.type === 'budget/charge') {
      const child = event.data['child'];
      const model = typeof event.data['model'] === 'string' ? event.data['model'] : '';
      // The row's own dollars are what the ledger already counted, so the report and the budget never disagree.
      const dollars = typeof event.data['dollars'] === 'number' ? event.data['dollars'] : null;
      charge(typeof child === 'string' ? (roleOfChild.get(child) ?? UNKNOWN_ROLE) : UNKNOWN_ROLE, model === RECOVERED ? `${RECOVERED} (model not known)` : model, usage, dollars);
    }
  }
  const order = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
  return {
    total: total.line(),
    byRole: [...roles].sort(([a], [b]) => order(a, b)).map(([role, acc]) => ({ role, ...acc.line() })),
    byModel: [...models].sort(([a], [b]) => order(a, b)).map(([model, acc]) => ({ model, ...acc.line() })),
    prices: priceTableInfo(),
  };
}

/** A few lines for a person: one per role, then the total. */
export function formatCostReport(report: CostReport): string {
  const money = (line: CostLine): string => (line.dollars === null ? `unknown (no price for ${line.unpriced.join(', ')})` : `$${line.dollars.toFixed(4)}`);
  const ratio = (line: CostLine): string => (line.cacheHitRatio === null ? 'no cache data' : `${Math.round(line.cacheHitRatio * 100)}% cached`);
  const row = (name: string, line: CostLine): string => `${name.padEnd(12)} ${String(line.input + line.cacheRead + line.cacheWrite).padStart(9)} in ${String(line.output).padStart(8)} out  ${ratio(line).padEnd(14)} ${money(line)}`;
  return [...report.byRole.map((role) => row(role.role, role)), row('total', report.total)].join('\n');
}
