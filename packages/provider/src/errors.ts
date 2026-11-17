import { HnError } from '@hn/core';

export type FailoverReason =
  | 'rate_limited'
  | 'overloaded'
  | 'server_error'
  | 'timeout'
  | 'connection'
  | 'stream_cut'
  | 'context_too_long'
  | 'quota_exhausted'
  | 'auth'
  | 'permission'
  | 'bad_request'
  | 'not_found'
  | 'aborted';

export interface FailoverFlags {
  readonly retryable: boolean;
  readonly shouldCompress: boolean;
  readonly shouldRotateCredential: boolean;
  readonly shouldFallback: boolean;
}

const flags = (
  retryable: boolean,
  shouldFallback: boolean,
  shouldCompress = false,
  shouldRotateCredential = false,
): FailoverFlags => ({ retryable, shouldCompress, shouldRotateCredential, shouldFallback });

const REASON_FLAGS: Readonly<Record<FailoverReason, FailoverFlags>> = {
  rate_limited: flags(true, true),
  overloaded: flags(true, true),
  server_error: flags(true, true),
  timeout: flags(true, true),
  connection: flags(true, true),
  stream_cut: flags(true, false),
  context_too_long: flags(false, false, true),
  quota_exhausted: flags(false, true, false, true),
  auth: flags(false, true, false, true),
  permission: flags(false, true),
  bad_request: flags(false, false),
  not_found: flags(false, true),
  aborted: flags(false, false),
};

export class ProviderError extends HnError {
  readonly reason: FailoverReason;
  readonly flags: FailoverFlags;
  readonly status: number | undefined;
  readonly retryAfterMs: number | undefined;

  constructor(
    reason: FailoverReason,
    message: string,
    details: { status?: number; retryAfterMs?: number | undefined; cause?: unknown } = {},
  ) {
    super('PROVIDER_ERROR', message, details.cause === undefined ? undefined : { cause: details.cause });
    this.reason = reason;
    this.flags = REASON_FLAGS[reason];
    this.status = details.status;
    this.retryAfterMs = details.retryAfterMs;
  }
}

const CONTEXT_TOO_LONG =
  /prompt is too long|context[ _]length|maximum context|context window|too many (input )?tokens|exceeds? the (model|context)/i;
const QUOTA = /credit balance|insufficient[ _](quota|balance|funds)|billing|exceeded your current quota/i;

export function parseRetryAfter(
  value: string | null | undefined,
  now: number = Date.now(),
): number | undefined {
  if (value === null || value === undefined || value.trim() === '') return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
}

/** Status alone is not enough: "context too long" and "out of credit" both often arrive as a plain 400 or 429. */
export function classifyStatus(status: number, body: string): FailoverReason {
  if (CONTEXT_TOO_LONG.test(body)) return 'context_too_long';
  if (QUOTA.test(body) || status === 402) return 'quota_exhausted';
  if (status === 401) return 'auth';
  if (status === 403) return 'permission';
  if (status === 404) return 'not_found';
  if (status === 413) return 'context_too_long';
  if (status === 408) return 'timeout';
  if (status === 429) return 'rate_limited';
  if (status === 529) return 'overloaded';
  if (status >= 500) return 'server_error';
  return 'bad_request';
}
