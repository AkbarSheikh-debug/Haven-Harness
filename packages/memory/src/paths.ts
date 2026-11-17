import { join } from 'node:path';
import { projectKey } from '@hn/config';

/**
 * Where memory lives: under the harness home, never in the repo, because a
 * repo file is text anyone with commit access can write. `USER.md` is one per user; everything
 * else is one per project, so a coffee site and a snake game do not share a brain.
 */
export interface MemoryPaths {
  readonly root: string;
  /** Stable facts about the user. Always loaded. */
  readonly user: string;
  /** The project's folder, keyed by `projectKey`. */
  readonly project: string;
  readonly projectKey: string;
  /** Durable decisions for this project. Loaded as a frozen snapshot. */
  readonly memory: string;
  /** `YYYY-MM-DD.md` working notes. */
  readonly daily: string;
  /** The dream diary. For the user to read; never a promotion source. */
  readonly dreams: string;
  /** Dream proposals, appended only. The morning cards read them. */
  readonly proposals: string;
}

export function memoryPaths(home: string, workdir: string): MemoryPaths {
  const root = join(home, 'memory');
  const key = projectKey(workdir);
  const project = join(root, 'projects', key);
  return {
    root,
    user: join(root, 'USER.md'),
    project,
    projectKey: key,
    memory: join(project, 'MEMORY.md'),
    daily: join(project, 'daily'),
    dreams: join(project, 'DREAMS.md'),
    proposals: join(project, 'proposals.jsonl'),
  };
}

/** The local calendar day, because "today's notes" means the user's today. */
export function dayOf(date: Date): string {
  const pad = (value: number): string => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export function dailyNotePath(paths: MemoryPaths, date: Date): string {
  return join(paths.daily, `${dayOf(date)}.md`);
}
