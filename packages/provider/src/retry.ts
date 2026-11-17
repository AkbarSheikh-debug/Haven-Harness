import { ProviderError } from './errors.ts';

export const MAX_ATTEMPTS = 5;

export interface RetryOptions {
  readonly maxAttempts?: number;
  readonly signal?: AbortSignal;
  readonly random?: () => number;
  readonly sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  readonly onRetry?: (error: ProviderError, attempt: number, delayMs: number) => void;
}

function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new ProviderError('aborted', 'Request aborted.'));
      return;
    }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(new ProviderError('aborted', 'Request aborted.'));
      },
      { once: true },
    );
  });
}

/** The server's Retry-After wins. Otherwise `min(60, 2^n)` seconds plus up to a second of jitter. */
export function retryDelayMs(attempt: number, retryAfterMs: number | undefined, random: () => number): number {
  if (retryAfterMs !== undefined) return retryAfterMs;
  return Math.min(60, 2 ** attempt) * 1000 + random() * 1000;
}

/** Runs one model call, retrying only what can succeed on a second try. */
export async function withRetry<T>(call: () => Promise<T>, options: RetryOptions = {}): Promise<T> {
  const maxAttempts = options.maxAttempts ?? MAX_ATTEMPTS;
  const sleep = options.sleep ?? abortableSleep;
  const random = options.random ?? Math.random;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await call();
    } catch (error) {
      if (!(error instanceof ProviderError) || !error.flags.retryable || attempt >= maxAttempts) throw error;
      const delayMs = retryDelayMs(attempt, error.retryAfterMs, random);
      options.onRetry?.(error, attempt, delayMs);
      await sleep(delayMs, options.signal);
    }
  }
}
