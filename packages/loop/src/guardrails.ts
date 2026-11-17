import { createHash } from 'node:crypto';

const WARN = { exactFailure: 2, sameToolFailure: 3, noProgress: 2 } as const;
const STOP = { exactFailure: 5, sameToolFailure: 8, noProgress: 5 } as const;

export type GuardVerdict =
  | { readonly kind: 'ok' }
  | { readonly kind: 'warn'; readonly message: string }
  | { readonly kind: 'stop'; readonly message: string };

const fingerprint = (...parts: readonly unknown[]): string =>
  createHash('sha256').update(JSON.stringify(parts)).digest('hex');

function bump(counts: Map<string, number>, key: string): number {
  const count = (counts.get(key) ?? 0) + 1;
  counts.set(key, count);
  return count;
}

/** Catches a model stuck repeating itself, before it spends the whole budget doing so. */
export class Guardrails {
  #exact = new Map<string, number>();
  #sameTool = new Map<string, number>();
  #seen = new Map<string, number>();

  observe(name: string, args: unknown, content: string, isError: boolean): GuardVerdict {
    if (isError) {
      const exact = bump(this.#exact, fingerprint(name, args));
      const sameTool = bump(this.#sameTool, name);
      if (exact >= STOP.exactFailure || sameTool >= STOP.sameToolFailure) {
        return { kind: 'stop', message: `${name} keeps failing. Stopping instead of retrying again.` };
      }
      if (exact >= WARN.exactFailure || sameTool >= WARN.sameToolFailure) {
        return { kind: 'warn', message: `${name} has failed repeatedly. Change your approach instead of retrying.` };
      }
      return { kind: 'ok' };
    }

    this.#sameTool.delete(name);
    const repeats = bump(this.#seen, fingerprint(name, args, content));
    if (repeats >= STOP.noProgress) {
      return { kind: 'stop', message: `${name} returned the same result ${repeats} times. Stopping.` };
    }
    if (repeats >= WARN.noProgress) {
      return { kind: 'warn', message: `${name} returned the same result as before. Try something different.` };
    }
    return { kind: 'ok' };
  }
}
