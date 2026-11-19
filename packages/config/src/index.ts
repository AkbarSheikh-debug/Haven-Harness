import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

export interface HnPaths {
  readonly home: string;
  readonly sessions: string;
  readonly locks: string;
  readonly logKey: string;
}

/** `HN_HOME` wins, so tests and fleets never touch the real home. */
export function resolvePaths(env: NodeJS.ProcessEnv = process.env): HnPaths {
  const home = env['HN_HOME'] ?? join(homedir(), '.hn');
  return {
    home,
    sessions: join(home, 'sessions'),
    locks: join(home, 'locks'),
    logKey: join(home, 'log.key'),
  };
}

/** Windows drive letters vary in case, so `D:\x` and `d:\x` must be the same project. */
export function projectKey(workdir: string, platform: NodeJS.Platform = process.platform): string {
  const absolute = platform === 'win32' ? workdir : resolve(workdir);
  const normalized = platform === 'win32' ? absolute.replace(/^[A-Za-z]:/, (drive) => drive.toLowerCase()) : absolute;
  return createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

export const DEFAULTS = {
  maxIterations: 500,
  maxOutputTokens: 32_000,
  effort: 'high',
  mainModel: 'claude-opus-5-5',
  /** Writes compaction summaries on the Anthropic route (Phase 3 decision 1). A local route uses its main model. */
  summaryModel: 'claude-haiku-5-5',
} as const;
