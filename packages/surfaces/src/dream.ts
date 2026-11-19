import { sessionPolicy } from './team.ts';
import { join } from 'node:path';
import { projectKey, resolvePaths } from '@hn/config';
import { sanitizeForDisplay } from '@hn/core';
import { memoryPaths, runDream, type DreamReport } from '@hn/memory';
import type { KeyStore } from '@hn/provider';
import { loadOrCreateLogKey } from '@hn/session';
import { completeWith } from './memory.ts';
import { chooseProvider, summaryRoutes } from './providers.ts';
import type { CliOptions } from './session.ts';

/** What a sweep found and did, for a person to read. Every line from memory passes through `sanitizeForDisplay`. */
export function formatDream(report: DreamReport, dryRun: boolean): string {
  const lines = [
    `${dryRun ? 'Dry run: nothing was asked or written.' : 'Dream finished.'} ${report.themes} themes, ${report.passing.length} past the gates, ${report.calls} model calls.`,
    ...report.passing.map((theme) => `  theme ${theme.words}: score ${theme.score.score.toFixed(2)}, recalled ${theme.score.recalls} times by ${theme.score.uniqueQueries} queries, ${theme.evidence} rows of evidence`),
    ...report.proposals.map((proposal) => `  proposed for ${proposal.kind === 'user' ? 'USER.md' : proposal.kind === 'rule' ? 'AGENTS.md' : 'MEMORY.md'}: ${proposal.text}`),
    ...(dryRun && report.passing.length > 0 ? ['  A real run would ask the model to turn each theme into one line and offer it as a card at the next session.'] : []),
  ];
  return sanitizeForDisplay(`${lines.join('\n')}\n`);
}

/**
 * `hn dream [--dry-run]` (decision 4): one sweep for the project in the current folder, by hand. It opens no
 * session, so it leaves no session log behind. The dreamer has no tools and uses the summary route.
 */
export async function runDreamCommand(options: CliOptions & { readonly dryRun: boolean }, keys: KeyStore): Promise<number> {
  const paths = resolvePaths(options.env);
  const memory = memoryPaths(paths.home, options.workdir);
  // Memory gates (slide 37): a policy can keep the dreamer away from this person's sessions.
  if (!(await sessionPolicy(options, paths.home, `dream-${process.pid}`)).policy.dreamAllowed()) {
    process.stdout.write('The policy does not allow dreaming over these sessions.\n');
    return 0;
  }
  const key = await loadOrCreateLogKey(paths.logKey);
  let complete = null;
  if (!options.dryRun) {
    const { provider, model, caps } = chooseProvider(options, keys);
    const route = summaryRoutes(provider, model, caps)[0];
    if (route !== undefined) complete = completeWith(route.provider, route.model, caps.maxOutput);
  }
  const report = await runDream({ paths: memory, sessionLogs: join(paths.sessions, projectKey(options.workdir)), key, now: new Date(), complete, dryRun: options.dryRun });
  process.stdout.write(formatDream(report, options.dryRun));
  return 0;
}
