import { resolvePaths } from '@hn/config';
import { HnError, sanitizeForDisplay } from '@hn/core';
import type { KeyStore } from '@hn/provider';
import { controlSession } from './control.ts';
import { runFleetFile } from './fleet.ts';
import { RateLimiter, rateLimitsFromEnv } from '@hn/delegate';
import { spentTokens } from '@hn/loop';
import { RALPH_DEFAULT_LAPS, RALPH_MAX_LAPS, runRalph } from '@hn/orchestrate';
import { formatCostLine, sumJobCosts } from './cost-summary.ts';
import { Harness } from './harness.ts';
import { gatedCheck } from './root-tools.ts';

export interface CommandContext {
  readonly positionals: readonly string[];
  /** True when this hn was started from inside another session, which may only look. */
  readonly nested: boolean;
  readonly out: (text: string) => void;
}

export interface SessionCommandContext extends CommandContext {
  readonly keys: KeyStore;
  /** The CLI's model flags, used where a file leaves them out. */
  readonly defaults: { readonly model: string; readonly baseUrl?: string; readonly window?: number };
  readonly flags: Readonly<Record<string, string | boolean | undefined>>;
}

/** `hn fleet <file.json> [--results <file>] [--workers <n>]`: runs every job, prints results in input order, resumes from the results file. */
export async function runFleetCommand(context: SessionCommandContext): Promise<number | null> {
  const [command, file] = context.positionals;
  if (command !== 'fleet') return null;
  if (context.nested) throw new HnError('NESTED_HN', 'hn fleet cannot be started from inside an hn session.');
  if (file === undefined) throw new HnError('USAGE', 'Use: hn fleet <fleet.json> [--results <file>] [--workers <n>]');
  const workers = context.flags['workers'] === undefined ? undefined : Number(context.flags['workers']);
  if (workers !== undefined && !(Number.isSafeInteger(workers) && workers > 0)) throw new HnError('USAGE', '--workers takes a positive whole number.');
  let settled = 0;
  const report = await runFleetFile(file, {
    keys: context.keys,
    defaults: context.defaults,
    ...(typeof context.flags['results'] === 'string' ? { resultsFile: context.flags['results'] } : {}),
    ...(workers === undefined ? {} : { maxWorkers: workers }),
    onResult: (result) => {
      settled += 1;
      context.out(`${sanitizeForDisplay(`[${settled}] ${result.name}: ${result.status}${result.reason === undefined ? '' : ` (${result.reason})`}, ${result.tokens} tokens`)}\n`);
    },
  });
  const counts = Object.entries(report.counts).filter(([, count]) => count > 0).map(([status, count]) => `${count} ${status}`).join(', ');
  context.out(`\n${report.results.length} jobs: ${counts}. ${report.tokens} tokens this run.${report.resumedFromFile > 0 ? ` ${report.resumedFromFile} were already done in the results file.` : ''}\n`);
  const spent = sumJobCosts(report.results);
  if (spent !== null) context.out(`${formatCostLine(spent)}\n`);
  for (const result of report.results) context.out(`${sanitizeForDisplay(`${result.name}: ${result.status}${result.sessionId === null ? '' : `, session ${result.sessionId}`}`)}\n`);
  return report.counts.done === report.results.length ? 0 : 1;
}

/**
 * The Phase 6 subcommands that are not a session of their own: `hn steer` and `hn stop`. Returns null when the
 * command line is not one of them.
 */
export async function runControlCommand(context: CommandContext): Promise<number | null> {
  const [command, sessionId, ...rest] = context.positionals;
  if (command !== 'steer' && command !== 'stop') return null;
  // A tool's process could otherwise steer the very session that started it.
  if (context.nested) throw new HnError('NESTED_HN', `hn ${command} cannot be used from inside an hn session.`);
  if (sessionId === undefined) throw new HnError('USAGE', `Use: hn ${command} <session>${command === 'steer' ? ' <text>' : ''}`);
  const text = rest.join(' ');
  if (command === 'steer' && text.trim() === '') throw new HnError('USAGE', 'Use: hn steer <session> <text>');
  const answer = await controlSession(resolvePaths().home, sessionId, command, command === 'steer' ? text : undefined);
  if (answer['ok'] !== true) {
    context.out(`${sanitizeForDisplay(String(answer['error'] ?? 'refused'))}\n`);
    return 1;
  }
  context.out(command === 'steer' ? 'Sent. The session sees it at its next step.\n' : 'Asked the session to stop its turn.\n');
  return 0;
}

/**
 * `hn ralph <prompt> [--check <command>] [--until <phrase>] [--max <laps>] [--allow <tools>]` (decision 6): each lap
 * is a fresh root session in this folder, unattended (`dont-ask` with file edits unless --allow says otherwise), and
 * the check runs through that lap's own gated exec, so below tier 3 the loop stops as unchecked rather than run blind.
 */
export async function runRalphCommand(context: SessionCommandContext): Promise<number | null> {
  const [command, ...words] = context.positionals;
  if (command !== 'ralph') return null;
  if (context.nested) throw new HnError('NESTED_HN', 'hn ralph cannot be started from inside an hn session.');
  const prompt = words.join(' ');
  const check = typeof context.flags['check'] === 'string' ? context.flags['check'] : undefined;
  const until = typeof context.flags['until'] === 'string' ? context.flags['until'] : undefined;
  if (prompt.trim() === '' || (check === undefined && until === undefined)) throw new HnError('USAGE', 'Use: hn ralph <prompt> --check <command> and/or --until <phrase> [--max <laps>]');
  const maxLaps = context.flags['max'] === undefined ? RALPH_DEFAULT_LAPS : Number(context.flags['max']);
  if (!(Number.isSafeInteger(maxLaps) && maxLaps > 0 && maxLaps <= RALPH_MAX_LAPS)) throw new HnError('USAGE', `--max takes a whole number from 1 to ${RALPH_MAX_LAPS}.`);
  const allow = typeof context.flags['allow'] === 'string' ? context.flags['allow'].split(',') : ['write_file', 'edit_file'];
  const rate = new RateLimiter(rateLimitsFromEnv(process.env));
  let current: Harness | null = null;
  const result = await runRalph({
    prompt,
    maxLaps,
    ...(until === undefined ? {} : { until }),
    lap: async (text, lap) => {
      const harness = new Harness({ workdir: process.cwd(), mode: 'dont-ask', allow, keys: context.keys, rateGate: rate, verify: 'off', ...context.defaults });
      current = harness;
      try {
        // The first lap is the person's own words; later laps carry notes the laps wrote, so they are the harness's.
        const turn = await harness.run(text, { origin: lap === 1 ? 'user' : 'harness' });
        return { end: turn.end, text: turn.text, tokens: harness.session === null ? 0 : spentTokens(harness.session.agent.events, 'fresh') };
      } finally {
        if (check === undefined) await harness.close();
      }
    },
    ...(check === undefined
      ? {}
      : {
          check: async (signal: AbortSignal) => {
            const harness = current as Harness | null;
            try {
              const session = harness?.session ?? null;
              return session === null ? { ran: false, passed: false, output: '', reason: 'the lap has no session' } : await gatedCheck(session.exec, check, signal);
            } finally {
              await harness?.close();
            }
          },
        }),
    onLap: (lap) => context.out(`${sanitizeForDisplay(`lap ${lap.lap} (${lap.end})${lap.check === undefined ? '' : `, check ${lap.check.ran ? (lap.check.passed ? 'passed' : 'failed') : 'could not run'}`}: ${lap.text.slice(0, 200)}`)}\n`),
  });
  context.out(`ralph ${result.status} after ${result.laps.length} lap(s), ${result.tokens} tokens.\n`);
  return result.status === 'passed' || result.status === 'finished' ? 0 : 1;
}
