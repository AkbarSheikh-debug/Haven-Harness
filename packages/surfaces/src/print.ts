import { sanitizeForDisplay } from '@hn/core';
import { costReport } from '@hn/delegate';
import type { TurnEnd, TurnResult } from '@hn/loop';
import { costOf, type KeyStore } from '@hn/provider';
import type { Approver } from '@hn/security';
export { costOf } from '@hn/provider';
import type { CliOptions } from './session.ts';
import { Harness } from './harness.ts';
import type { FinishReport } from './sandbox.ts';

/** How long a headless run waits for background children before stopping them. */
export const CHILD_WAIT_MS = 15 * 60_000;

export const EXIT_DONE = 0;
export const EXIT_FAILED = 1;
export const EXIT_REFUSED = 2;
export const EXIT_OUT_OF_BUDGET = 3;

/** A fatal error as one safe line. Error text can carry a provider's response body, which is attacker-reachable like any model text. */
export function formatFatal(error: unknown, redact: (text: string) => string): string {
  return `${sanitizeForDisplay(redact(error instanceof Error ? error.message : String(error)))}\n`;
}

export function exitCodeFor(end: TurnEnd): number {
  if (end === 'done') return EXIT_DONE;
  if (end === 'budget' || end === 'window_full') return EXIT_OUT_OF_BUDGET;
  if (end === 'refusal' || end === 'cancelled') return EXIT_REFUSED;
  return EXIT_FAILED;
}

export function formatUsage(model: string, result: TurnResult): string {
  const { usage } = result;
  const input = usage.input + usage.cacheRead + usage.cacheWrite;
  const hitRate = input === 0 ? 0 : Math.round((usage.cacheRead / input) * 100);
  const cost = costOf(model, usage);
  return `${result.steps} steps, ${input} in, ${usage.output} out, ${hitRate}% cached${cost === null ? '' : `, $${cost.toFixed(4)}`}`;
}

/** What went back to the project when a box ended, and what was held for a person. */
export function describeHandback(report: FinishReport): string {
  const lines = [`Brought back ${report.result.applied.length} file(s) to your project.`];
  for (const entry of report.result.blocked) lines.push(`Held back: ${entry.path} (${entry.why})`);
  for (const entry of report.plan.skipped) lines.push(`Not imported: ${entry.path} (${entry.why})`);
  return `\n${lines.join('\n')}\n`;
}

export interface PrintOptions extends CliOptions {
  readonly prompt: string;
  readonly json: boolean;
  /** A granted child's approver: the parent's person, reached over the channel. Never anyone at this door. */
  readonly routed?: Approver;
  /**
   * `event`: the prompt was read from outside (a GitHub issue) and is not the user's instruction. The session starts as
   * untrusted as an event, which keeps the user-only powers (fetching a URL unseen) away from it. It can only lower trust.
   */
  readonly promptOrigin?: 'event';
}

/** The headless door. Nobody is here to ask, so it runs with no approver at all. */
export async function runPrint(options: PrintOptions, keys: KeyStore, write = (text: string) => process.stdout.write(text)): Promise<number> {
  const { approver: _unused, routed, prompt, json, promptOrigin, ...withoutApprover } = options;
  const harness = new Harness({
    ...withoutApprover,
    keys,
    // A long headless run can be steered or stopped from another terminal: hn steer <session> <text>.
    control: true,
    ...(routed === undefined ? {} : { approver: routed }),
    ...(json ? {} : { onEvent: (event) => event.type === 'text' && write(sanitizeForDisplay(event.text)) }),
  });
  try {
    const session = await harness.open();
    // A headless run waits for its background children (section 11.2), then gives the model one more turn to use
    // their reports. Children still running at the deadline are stopped, and their logs say so.
    const { sessionId: _id, ...result } = await harness.run(prompt, { waitForChildrenMs: CHILD_WAIT_MS, ...(promptOrigin === undefined ? {} : { origin: promptOrigin }) });
    // What the whole family cost, by role and model, from the log (Phase 10): `result.usage` is only this turn's own.
    const cost = costReport(session.agent.events);
    // Nobody is here to approve anything, so a box's changes on the host-exec manifest are held back, never applied.
    const handback = await harness.close();
    if (json) {
      const summary = handback === null ? {} : { handback: { applied: handback.result.applied, held: handback.result.blocked, notImported: handback.plan.skipped } };
      write(`${JSON.stringify({ sessionId: session.sessionId, ...result, text: sanitizeForDisplay(result.text), cost, ...summary })}\n`);
    } else {
      write('\n');
      if (result.detail !== undefined) process.stderr.write(`${sanitizeForDisplay(result.detail)}\n`);
      if (handback !== null) process.stderr.write(sanitizeForDisplay(describeHandback(handback)));
    }
    return exitCodeFor(result.end);
  } finally {
    await harness.close();
  }
}
