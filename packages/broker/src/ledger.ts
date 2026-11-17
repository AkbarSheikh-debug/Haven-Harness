import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Spend per person per UTC day, kept on the broker, where a client cannot reset it. A policy budget is checked
 * before a call goes upstream and the call's cost is added after; a call is refused once the day's total has
 * reached the budget, so one call can finish over it, and the next one cannot start.
 */

const queues = new Map<string, Promise<void>>();

/**
 * Replaces a file atomically, one write at a time per file. The text is made when the write's turn comes, so the
 * newest state is what lands; each write uses its own temporary name, so two never collide (found by the full
 * suite: two model calls ending together lost a reply when both renamed the same temporary file).
 */
export function writeAtomic(path: string, text: () => string): Promise<void> {
  const next = (queues.get(path) ?? Promise.resolve()).then(async () => {
    const temporary = `${path}.${randomBytes(6).toString('hex')}.tmp`;
    try {
      await writeFile(temporary, text(), { mode: 0o600 });
      await rename(temporary, path);
    } catch (error) {
      await rm(temporary, { force: true });
      throw error;
    }
  });
  queues.set(path, next.catch(() => undefined));
  return next;
}

export interface Spend {
  readonly usd: number;
  readonly tokens: number;
}

export class Ledger {
  readonly #dir: string;
  readonly #now: () => number;
  #day = '';
  #spend = new Map<string, Spend>();

  constructor(dir: string, now: () => number = Date.now) {
    this.#dir = dir;
    this.#now = now;
  }

  async #load(): Promise<void> {
    const day = new Date(this.#now()).toISOString().slice(0, 10);
    if (day === this.#day) return;
    this.#day = day;
    this.#spend = new Map();
    try {
      const saved = JSON.parse(await readFile(join(this.#dir, `${day}.json`), 'utf8')) as Record<string, Spend>;
      for (const [user, spend] of Object.entries(saved)) this.#spend.set(user, spend);
    } catch {
      // A new day.
    }
  }

  async spent(user: string): Promise<Spend> {
    await this.#load();
    return this.#spend.get(user) ?? { usd: 0, tokens: 0 };
  }

  /** Why this person may not start another call today, or null. */
  async check(user: string, budget: { maxCostUsd?: number; maxTokens?: number }): Promise<string | null> {
    const spent = await this.spent(user);
    if (budget.maxCostUsd !== undefined && spent.usd >= budget.maxCostUsd) return `The day's budget of $${budget.maxCostUsd} is spent ($${spent.usd.toFixed(4)}).`;
    if (budget.maxTokens !== undefined && spent.tokens >= budget.maxTokens) return `The day's budget of ${budget.maxTokens} tokens is spent (${spent.tokens}).`;
    return null;
  }

  async add(user: string, usd: number, tokens: number): Promise<void> {
    await this.#load();
    const before = this.#spend.get(user) ?? { usd: 0, tokens: 0 };
    this.#spend.set(user, { usd: before.usd + usd, tokens: before.tokens + tokens });
    await mkdir(this.#dir, { recursive: true, mode: 0o700 });
    const path = join(this.#dir, `${this.#day}.json`);
    await writeAtomic(path, () => JSON.stringify(Object.fromEntries(this.#spend)));
  }
}

/** At most `limit` requests per person in any 60 seconds. */
export class RateWindow {
  readonly #limit: number;
  readonly #now: () => number;
  readonly #seen = new Map<string, number[]>();

  constructor(limit: number, now: () => number = Date.now) {
    this.#limit = limit;
    this.#now = now;
  }

  take(user: string): boolean {
    const now = this.#now();
    const recent = (this.#seen.get(user) ?? []).filter((time) => time > now - 60_000);
    if (recent.length >= this.#limit) {
      this.#seen.set(user, recent);
      return false;
    }
    recent.push(now);
    this.#seen.set(user, recent);
    return true;
  }
}
