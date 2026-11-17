import { ProviderError, type ModelProvider, type ModelReply, type ModelRequest } from '@hn/provider';

export interface RateLimits {
  /** Requests per minute. Unset means no request limit. */
  readonly rpm?: number;
  /** Tokens per minute, counted from each request's estimate and corrected by its real usage. Unset means none. */
  readonly tpm?: number;
}

export interface RateLimiterOptions extends RateLimits {
  readonly now?: () => number;
  /** Waits `ms`, or rejects when the signal fires. */
  readonly sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

/** Waits for `ms`, ending early with an abort error when the signal fires. */
export function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(new ProviderError('aborted', 'Stopped while waiting for the rate limit.'));
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new ProviderError('aborted', 'Stopped while waiting for the rate limit.'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * A token bucket for requests and tokens per minute, shared by everyone who holds it: a parent and all its
 * children, or a whole fleet. A Retry-After from the provider pauses every holder, so one 429 does not become
 * a stampede of them.
 */
export class RateLimiter {
  readonly #rpm: number | undefined;
  readonly #tpm: number | undefined;
  readonly #now: () => number;
  readonly #sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  #requests: number;
  #tokens: number;
  #refilledAt: number;
  #pausedUntil = 0;
  /** Waiters are served in order, so a big request cannot be starved by a stream of small ones. */
  #queue: Promise<unknown> = Promise.resolve();

  constructor(options: RateLimiterOptions = {}) {
    for (const value of [options.rpm, options.tpm]) {
      if (value !== undefined && !(Number.isFinite(value) && value > 0)) throw new RangeError('rpm and tpm must be positive numbers.');
    }
    this.#rpm = options.rpm;
    this.#tpm = options.tpm;
    this.#now = options.now ?? Date.now;
    this.#sleep = options.sleep ?? abortableSleep;
    this.#requests = options.rpm ?? 0;
    this.#tokens = options.tpm ?? 0;
    this.#refilledAt = this.#now();
  }

  get pausedUntil(): number {
    return this.#pausedUntil;
  }

  #refill(): void {
    const now = this.#now();
    const elapsed = Math.max(0, now - this.#refilledAt);
    this.#refilledAt = now;
    if (this.#rpm !== undefined) this.#requests = Math.min(this.#rpm, this.#requests + (elapsed * this.#rpm) / 60_000);
    if (this.#tpm !== undefined) this.#tokens = Math.min(this.#tpm, this.#tokens + (elapsed * this.#tpm) / 60_000);
  }

  /** How long until one request of `tokens` may go, or 0 now. A request larger than the whole minute waits for a full bucket. */
  #waitMs(tokens: number): number {
    this.#refill();
    let wait = Math.max(0, this.#pausedUntil - this.#now());
    if (this.#rpm !== undefined && this.#requests < 1) wait = Math.max(wait, ((1 - this.#requests) * 60_000) / this.#rpm);
    if (this.#tpm !== undefined) {
      const need = Math.min(tokens, this.#tpm);
      if (this.#tokens < need) wait = Math.max(wait, ((need - this.#tokens) * 60_000) / this.#tpm);
    }
    return Math.ceil(wait);
  }

  /** Waits until one request of about `tokens` may go, then takes it from the buckets. */
  acquire(tokens: number, signal?: AbortSignal): Promise<void> {
    const turn = this.#queue.then(async () => {
      for (let wait = this.#waitMs(tokens); wait > 0; wait = this.#waitMs(tokens)) await this.#sleep(wait, signal);
      if (this.#rpm !== undefined) this.#requests -= 1;
      if (this.#tpm !== undefined) this.#tokens -= Math.min(tokens, this.#tpm);
    });
    this.#queue = turn.catch(() => undefined);
    return turn;
  }

  /** After a reply: the real count replaces the estimate. A bucket can go below zero, which makes the next caller wait. */
  settle(estimated: number, actual: number): void {
    if (this.#tpm === undefined) return;
    this.#refill();
    this.#tokens -= actual - Math.min(estimated, this.#tpm);
  }

  /** The provider said to wait. Everyone holding this limiter waits, not just the caller that got the 429. Capped at 10 minutes. */
  pause(ms: number): void {
    if (!(Number.isFinite(ms) && ms > 0)) return;
    this.#pausedUntil = Math.max(this.#pausedUntil, this.#now() + Math.min(ms, 10 * 60_000));
  }
}

/** Something that can be asked for a slot before each call: a local limiter, or a parent's over a child's channel. */
export interface RateGate {
  acquire(tokens: number, signal?: AbortSignal): Promise<void>;
  settle(estimated: number, actual: number): void;
  pause(ms: number): void;
}

/** A rough size of a request in tokens, for the bucket only: four characters a token over the whole request. */
export function estimateRequestTokens(request: ModelRequest): number {
  return Math.ceil((request.system.length + JSON.stringify(request.tools).length + JSON.stringify(request.messages).length) / 4) + request.maxOutputTokens;
}

/** Wraps a provider so every call waits for the shared bucket first, and a 429's Retry-After pauses all holders. */
export function limitProvider(provider: ModelProvider, gate: RateGate): ModelProvider {
  const complete = async (request: ModelRequest): Promise<ModelReply> => {
    const estimate = estimateRequestTokens(request);
    await gate.acquire(estimate, request.signal);
    try {
      const reply = await provider.complete(request);
      const usage = reply.usage;
      if (usage !== null) gate.settle(estimate, usage.input + usage.output + usage.cacheRead + usage.cacheWrite);
      return reply;
    } catch (error) {
      if (error instanceof ProviderError && error.reason === 'rate_limited') gate.pause(error.retryAfterMs ?? 5_000);
      throw error;
    }
  };
  return { route: provider.route, complete };
}

/** Limits from the environment: `HN_RATE_RPM` and `HN_RATE_TPM`. Anything that is not a positive number is ignored. */
export function rateLimitsFromEnv(env: NodeJS.ProcessEnv): RateLimits {
  const read = (name: string): number | undefined => {
    const value = Number(env[name]);
    return Number.isFinite(value) && value > 0 ? value : undefined;
  };
  const rpm = read('HN_RATE_RPM');
  const tpm = read('HN_RATE_TPM');
  return { ...(rpm === undefined ? {} : { rpm }), ...(tpm === undefined ? {} : { tpm }) };
}
