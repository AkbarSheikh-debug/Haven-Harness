import { createHash } from 'node:crypto';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { projectKey, resolvePaths } from '@hn/config';
import { parseLog, type LoadedLog } from '@hn/session';
import { MAX_FOLLOW_BYTES, MAX_LISTED_SESSIONS, MAX_LOG_FILE_BYTES, NO_TOTALS, SESSION_ID, buildReplay, type Replay, type ReplayStep } from './replay.ts';

/** Finding, opening and following the recorded sessions of a project: the file side of the replay, apart from what a log's events say. */

export interface SessionListing {
  readonly id: string;
  readonly modified: string;
  readonly bytes: number;
}

export type ReplayLoad = { readonly kind: 'replay'; readonly replay: Replay; /** Bytes of the file that were read, and the fingerprint of the steps shown, for following it as it grows. */ readonly follow: { readonly size: number; readonly prefix: string; readonly since: number } | null } | { readonly kind: 'missing' } | { readonly kind: 'too-large'; readonly bytes: number };

/** A fingerprint of the first steps of a replay, so a follower can tell that what it was already shown was not rewritten. */
export function prefixOf(steps: readonly ReplayStep[], count = steps.length): string {
  const hash = createHash('sha256');
  for (const step of steps.slice(0, count)) hash.update(JSON.stringify([step.seq, step.ts, step.kind, step.title, step.detail ?? '', step.diff === undefined ? null : [step.diff.path, step.diff.before, step.diff.after]]));
  return hash.digest('hex');
}

/** The sessions recorded for the project in `workdir`, newest first. Names only: a log is verified when it is opened. */
export async function listSessions(workdir: string, env?: NodeJS.ProcessEnv): Promise<SessionListing[]> {
  const folder = join(resolvePaths(env).sessions, projectKey(workdir));
  let names: string[];
  try {
    names = await readdir(folder);
  } catch {
    return [];
  }
  const found: SessionListing[] = [];
  for (const name of names) {
    if (!SESSION_ID.test(name)) continue;
    try {
      const info = await stat(join(folder, name));
      if (info.isFile()) found.push({ id: name, modified: info.mtime.toISOString(), bytes: info.size });
    } catch {
      // A file that vanished between the listing and the stat is not a session any more.
    }
  }
  return found.sort((a, b) => b.modified.localeCompare(a.modified) || a.id.localeCompare(b.id)).slice(0, MAX_LISTED_SESSIONS);
}

const NEWER_HN = 'This log was written by a newer hn than this one, so it cannot be verified here.';

const refusedReplay = (sessionId: string, reason: string): Replay => ({ sessionId, trust: 'refused', reason, createdAt: null, events: 0, steps: [], shownSteps: 0, truncated: false, crashed: false, hidden: {}, totals: NO_TOTALS });

type Opened = { readonly kind: 'ok'; readonly bytes: Buffer; readonly key: Buffer } | { readonly kind: 'missing' } | { readonly kind: 'too-large'; readonly bytes: number };

/** Reads a session's log and the key, within a size limit. The id is checked against the pattern before it is joined to anything. */
async function openLog(sessionId: string, workdir: string, env: NodeJS.ProcessEnv | undefined, limit: number): Promise<Opened> {
  if (!SESSION_ID.test(sessionId)) return { kind: 'missing' };
  const paths = resolvePaths(env);
  const path = join(paths.sessions, projectKey(workdir), sessionId);
  try {
    const info = await stat(path);
    if (!info.isFile()) return { kind: 'missing' };
    if (info.size > limit) return { kind: 'too-large', bytes: info.size };
    return { kind: 'ok', bytes: await readFile(path), key: await readFile(paths.logKey) };
  } catch {
    return { kind: 'missing' };
  }
}

/**
 * Opens one session's log and verifies it. The id must match the session-id pattern and is only ever joined to the
 * project's own sessions folder, so it cannot name another path. A missing key or log is `missing`, not a replay.
 */
export async function loadReplay(sessionId: string, workdir: string, env?: NodeJS.ProcessEnv): Promise<ReplayLoad> {
  const opened = await openLog(sessionId, workdir, env, MAX_LOG_FILE_BYTES);
  if (opened.kind !== 'ok') return opened;
  let log: LoadedLog;
  try {
    log = parseLog(opened.bytes, opened.key);
  } catch {
    // Only a log written by a newer hn throws. It cannot be read here, which is a refusal, not a guess.
    return { kind: 'replay', replay: refusedReplay(sessionId, NEWER_HN), follow: null };
  }
  const replay = buildReplay(log, sessionId);
  return { kind: 'replay', replay, follow: replay.trust === 'verified' ? { size: opened.bytes.length, prefix: prefixOf(replay.steps), since: replay.steps.length } : null };
}

/** What a follower already has: how many steps, the size of the file it was made from, and the fingerprint of those steps. */
export interface FollowQuery {
  readonly since: number;
  readonly size: number;
  readonly prefix: string;
}

export type FollowLoad =
  | { readonly kind: 'unchanged' }
  | { readonly kind: 'missing' }
  | { readonly kind: 'too-large'; readonly bytes: number }
  /** `replay.steps` holds only the steps after `since`; the totals and counts are for the whole log. A refused replay has none. */
  | { readonly kind: 'replay'; readonly replay: Replay; readonly follow: { readonly size: number; readonly prefix: string; readonly since: number } | null };

/**
 * A growing log, followed. Every call verifies the WHOLE log again from its first frame, so a break anywhere turns the answer
 * into a refusal and nothing after it is sent. A frame that is still being written is waited for (it is dropped as a torn tail, as
 * after a crash), not shown and not called forged. The steps the follower was already shown must be unchanged: a log that
 * still verifies but now tells a different story about them, or got shorter, is refused too.
 */
export async function followReplay(sessionId: string, workdir: string, env: NodeJS.ProcessEnv | undefined, query: FollowQuery): Promise<FollowLoad> {
  const opened = await openLog(sessionId, workdir, env, MAX_FOLLOW_BYTES);
  if (opened.kind !== 'ok') return opened;
  if (opened.bytes.length === query.size) return { kind: 'unchanged' };
  let log: LoadedLog;
  try {
    log = parseLog(opened.bytes, opened.key);
  } catch {
    return { kind: 'replay', replay: refusedReplay(sessionId, NEWER_HN), follow: null };
  }
  const replay = buildReplay(log, sessionId);
  if (replay.trust !== 'verified') return { kind: 'replay', replay, follow: null };
  if (query.since > replay.steps.length) return { kind: 'replay', replay: refusedReplay(sessionId, 'The log is now shorter than the part already shown, so it was cut or replaced while it was being followed. Nothing more is shown.'), follow: null };
  if (prefixOf(replay.steps, query.since) !== query.prefix) return { kind: 'replay', replay: refusedReplay(sessionId, 'The part of the log that was already shown has changed, so it was rewritten while it was being followed. Nothing more is shown.'), follow: null };
  return { kind: 'replay', replay: { ...replay, steps: replay.steps.slice(query.since) }, follow: { size: opened.bytes.length, prefix: prefixOf(replay.steps), since: replay.steps.length } };
}
