import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { projectKey, resolvePaths } from '@hn/config';
import type { SubagentManager } from '@hn/delegate';
import type { Origin } from '@hn/core';
import type { Agent } from '@hn/loop';
import type { TaintTracker } from '@hn/security';
import { handoffFrame } from './handoff.ts';
import type { CliOptions } from './session-types.ts';
import { inboxOrigin } from './teams.ts';

/**
 * What a session does once its log is open and before its first turn: settles children the last run left from their
 * own logs, records where it came from, opens a team member's inbox, and starts a handoff from its note with the
 * parent's taint (handoff_keeps_taint); the note is never the user's words. Returns how anything outside the turn adds a
 * notice: the session's taint takes the notice's origin first, so a steer from another process or a member's message
 * leaves the session as untrusted as its source.
 */
export async function afterOpen(agent: Agent, options: CliOptions, taint: TaintTracker, manager: SubagentManager): Promise<SessionNotice> {
  const notice: SessionNotice = (text, origin) => {
    taint.observe(origin);
    agent.notice(text, origin);
  };
  await manager.recover();
  if (options.linkedFrom !== undefined) agent.record('session/link', { ...options.linkedFrom });
  options.inbox?.((text, origin) => notice(text, inboxOrigin(origin)));
  if (options.handoff !== undefined) {
    agent.record('session/link', { kind: 'handoff', parent: options.handoff.parent });
    taint.observe(options.handoff.origin);
    await agent.addContext(handoffFrame(options.handoff.parent, options.handoff.draft), options.handoff.origin);
  }
  return notice;
}

export type SessionNotice = (text: string, origin: Exclude<Origin, 'user' | 'human-selected'>) => void;

/** Finds the newest session for this project, for `--continue`. */
export async function latestSession(workdir: string, env?: NodeJS.ProcessEnv): Promise<string | undefined> {
  const directory = join(resolvePaths(env).sessions, projectKey(workdir));
  const names = await readdir(directory).catch(() => [] as string[]);
  const dated = await Promise.all(
    names
      .filter((name) => !name.includes('.'))
      .map(async (name) => ({ name, modified: (await stat(join(directory, name))).mtimeMs })),
  );
  return dated.sort((a, b) => b.modified - a.modified)[0]?.name;
}
