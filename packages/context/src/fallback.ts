import { toolCallsOf, type Origin, type SessionEvent } from '@hn/core';
import { join, type Redactor } from '@hn/security';
import type { SummarySource } from './guards.ts';
import { effectiveCall } from './prune.ts';
import { composeSummary, normaliseSections, splitMiddle, type SummaryOutcome } from './summary.ts';
import { estimateText } from './tokens.ts';

const LIST_CAP = 40;
const PATH_CAP = 200;
const PATH_KEYS = ['path', 'file', 'file_path', 'cwd', 'directory', 'pattern'] as const;

export interface SummaryAttempt {
  readonly source: Exclude<SummarySource, 'static'>;
  readonly model: string;
  readonly run: () => Promise<SummaryOutcome>;
}

export interface ChainFailure {
  readonly source: SummarySource;
  readonly model: string;
  readonly reason: string;
}

export interface ChainResult {
  readonly text: string;
  readonly origin: Origin;
  readonly source: SummarySource;
  readonly model: string | null;
  readonly failures: readonly ChainFailure[];
  /** True when any attempt timed out, so the failure cooldown uses the timeout ladder. */
  readonly timedOut: boolean;
  /** False only when even the static summary is not smaller than what it replaces: a structural no-op. */
  readonly fits: boolean;
}

function isTimeout(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.name === 'TimeoutError' || error.name === 'AbortError' || /timed? ?out/i.test(error.message);
}

/** Printable, single-line, capped: a path from model arguments is data and is shown as data. */
function cleanPath(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, '').slice(0, PATH_CAP);
}

interface Facts {
  readonly counts: Map<string, number>;
  readonly failed: Map<string, number>;
  readonly files: Set<string>;
  errors: number;
}

function collectFacts(turns: readonly SessionEvent[]): Facts {
  const facts: Facts = { counts: new Map(), failed: new Map(), files: new Set(), errors: 0 };
  const names = new Map<string, string>();
  for (const row of turns) {
    for (const raw of toolCallsOf(row)) {
      const call = effectiveCall(raw);
      const name = cleanPath(call.name).slice(0, 64) || 'tool';
      names.set(call.id, name);
      facts.counts.set(name, (facts.counts.get(name) ?? 0) + 1);
      const args = (typeof call.args === 'object' && call.args !== null ? call.args : {}) as Record<string, unknown>;
      for (const key of PATH_KEYS) {
        const value = args[key];
        if (typeof value === 'string' && value !== '' && facts.files.size < LIST_CAP) facts.files.add(cleanPath(value));
      }
    }
    if (row.type === 'tool/result' && row.data['isError'] === true) {
      facts.errors += 1;
      const name = names.get(String(row.data['callId'])) ?? 'tool';
      facts.failed.set(name, (facts.failed.get(name) ?? 0) + 1);
    }
  }
  return facts;
}

/**
 * A summary built only from facts the harness holds: which tools ran, on which paths, and which failed.
 * It copies no free text from the model or a tool, so nothing in it can be an instruction.
 */
export function staticSummaryBody(middle: readonly SessionEvent[]): string {
  const { turns } = splitMiddle(middle);
  const facts = collectFacts(turns);
  const actions = [...facts.counts].slice(0, LIST_CAP).map(([name, count]) => `- ${name}: ${count} call(s)`);
  const errorLines = [...facts.failed].slice(0, LIST_CAP).map(([name, count]) => `- ${name}: ${count} failed call(s)`);
  const userTurns = turns.filter((row) => row.type === 'user/message').length;
  return [
    '## Historical Task Snapshot',
    `This summary was built by the harness without a model, because every summary model failed. It covers ${turns.length} rows and ${userTurns} user message(s), and lists only facts the harness recorded.`,
    '## Completed Actions',
    actions.length === 0 ? '(none)' : actions.join('\n'),
    '## Errors & Fixes',
    facts.errors === 0 ? '(none)' : `${facts.errors} tool call(s) failed:\n${errorLines.join('\n')}`,
    '## Relevant Files',
    facts.files.size === 0 ? '(none)' : [...facts.files].map((file) => `- ${file}`).join('\n'),
    '## Critical Context',
    'Details of these turns are gone from the window. Re-read files before relying on what they said.',
  ].join('\n');
}

/**
 * The fallback chain: the summary model (unless benched), the configured fallbacks, the main model, and
 * last the static summary, which needs no model. The first accepted summary wins; every failure is kept.
 */
export async function summarizeWithFallback(input: {
  readonly attempts: readonly SummaryAttempt[];
  readonly middle: readonly SessionEvent[];
  readonly surface: readonly SessionEvent[];
  readonly replacedTokens: number;
  readonly redactor: Redactor;
}): Promise<ChainResult> {
  const failures: ChainFailure[] = [];
  let timedOut = false;
  for (const attempt of input.attempts) {
    try {
      const outcome = await attempt.run();
      if (outcome.ok) {
        const { text, origin } = outcome;
        return { text, origin, source: attempt.source, model: attempt.model, failures, timedOut, fits: true };
      }
      failures.push({ source: attempt.source, model: attempt.model, reason: outcome.reason });
    } catch (error) {
      timedOut ||= isTimeout(error);
      const reason = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      failures.push({ source: attempt.source, model: attempt.model, reason: input.redactor.redact(reason).slice(0, 500) });
    }
  }
  const text = composeSummary(normaliseSections(staticSummaryBody(input.middle)), input.surface, input.redactor);
  return {
    text,
    origin: join(...input.middle.map((row) => row.origin)),
    source: 'static',
    model: null,
    failures,
    timedOut,
    fits: estimateText(text) < input.replacedTokens,
  };
}
