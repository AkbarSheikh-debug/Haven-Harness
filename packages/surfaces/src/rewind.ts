import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { projectKey, resolvePaths } from '@hn/config';
import { toolCallsOf, type SessionEvent } from '@hn/core';
import { newSessionId } from '@hn/loop';
import type { KeyStore } from '@hn/provider';
import { forkSession, lastForkBoundary, loadOrCreateLogKey, parseLog } from '@hn/session';
import { openSession } from './session.ts';
import type { CliOptions, OpenSession } from './session-types.ts';

export interface RewindPoint {
  /** 1-based number of the person's turn. */
  readonly turn: number;
  readonly seq: number;
  readonly text: string;
}

/** The turns a person can rewind to: each turn they typed, by number. */
export function rewindPoints(events: readonly SessionEvent[]): RewindPoint[] {
  const points: RewindPoint[] = [];
  for (const [index, event] of events.entries()) {
    if (event.type !== 'turn/start') continue;
    const asked = events.slice(index + 1).find((next) => next.type === 'user/message' && next.data['instructions'] !== true);
    if (asked?.origin !== 'user') continue;
    points.push({ turn: points.length + 1, seq: event.seq, text: String(asked.data['text'] ?? '').slice(0, 120) });
  }
  return points;
}

const WRITE_TOOLS = new Set(['write_file', 'edit_file']);

export interface RewindPlan {
  /** The fork boundary: the newest closed step before the chosen turn. */
  readonly boundary: number;
  /** The checkpoint taken right before the first change after the boundary, or null. */
  readonly checkpoint: number | null;
  /** True when that checkpoint is exactly the state at the boundary. */
  readonly exact: boolean;
  readonly nothingChanged: boolean;
  /** Files the agent's file tools wrote after the boundary: what a plain rewind puts back. */
  readonly paths: readonly string[];
  /** A shell or another tool changed things after the boundary, which only `--all` puts back. */
  readonly otherChanges: boolean;
  /** What a rewind cannot take back, said plainly. */
  readonly notUndone: readonly string[];
}

/**
 * Plans `/rewind` to just before turn `turn` (11.7). The boundary is the newest closed step before that turn. Files go
 * back to the checkpoint taken right before the first change after it, and only when that checkpoint really is the
 * state at the boundary: checkpoints are coalesced, and a near miss would silently restore the wrong state.
 */
export function planRewind(events: readonly SessionEvent[], turn: number): RewindPlan | string {
  const point = rewindPoints(events).find((candidate) => candidate.turn === turn);
  if (point === undefined) return `There is no turn ${turn} to go back to.`;
  const boundary = lastForkBoundary(events, point.seq - 1);
  const after = events.filter((event) => event.seq > boundary);
  const changes = after.filter((event) => event.type === 'audit/decision' && event.data['decision'] === 'allowed-once' && event.data['effect'] !== 'observe');
  const firstCheckpoint = after.find((event) => event.type === 'checkpoint/create');
  const changesBeforeCheckpoint = firstCheckpoint === undefined ? changes.length : changes.filter((event) => event.seq < firstCheckpoint.seq).length;
  const paths = new Set<string>();
  let otherChanges = false;
  for (const event of after) {
    for (const call of toolCallsOf(event)) {
      const path = (call.args as Record<string, unknown> | null)?.['path'];
      if (WRITE_TOOLS.has(call.name) && typeof path === 'string') paths.add(path.replaceAll('\\', '/'));
    }
  }
  for (const change of changes) if (!WRITE_TOOLS.has(String(change.data['tool']))) otherChanges = true;
  const notUndone: string[] = [];
  for (const event of after) {
    if (event.type === 'memory/write') notUndone.push(`a memory write to ${String(event.data['target'] ?? 'notes')}`);
    if (event.type === 'audit/decision' && event.data['decision'] === 'allowed-once' && (event.data['effect'] === 'external' || event.data['effect'] === 'irreversible')) notUndone.push(`${String(event.data['tool'])} (${String(event.data['effect'])})`);
    if (event.type === 'subagent/catalog' && event.data['kind'] === 'spawned') notUndone.push(`child ${String(event.data['role'])} ${String(event.data['child']).slice(0, 8)} and anything it did outside this project`);
  }
  return {
    boundary,
    checkpoint: firstCheckpoint === undefined ? null : Number(firstCheckpoint.data['seq']),
    exact: firstCheckpoint !== undefined && changesBeforeCheckpoint <= 1,
    nothingChanged: changes.length === 0,
    paths: [...paths],
    otherChanges,
    notUndone,
  };
}

export interface RewindDoor {
  readonly out: (text: string) => void;
}

/**
 * `/rewind <turn> [--all]`: a fork at the step boundary before that turn plus a file restore, so the old session stays
 * whole and resumable. A person's own edits survive unless `--all`. Memory writes, external effects and children are
 * listed as not undone. Returns the new session, or null when nothing was done.
 */
export async function runRewind(session: OpenSession, options: CliOptions, keys: KeyStore, door: RewindDoor, turn: number, all: boolean): Promise<OpenSession | null> {
  if (session.sandbox !== null) {
    door.out('/rewind is not available in a sandboxed session, because its changes come back through the box. Use /rollback.\n');
    return null;
  }
  const plan = planRewind(session.agent.events, turn);
  if (typeof plan === 'string') {
    door.out(`${plan}\n`);
    return null;
  }
  const lines: string[] = [];
  if (plan.nothingChanged) lines.push('No file changed after that point, so no file was restored.');
  else if (session.checkpoints === null || plan.checkpoint === null || !plan.exact) {
    lines.push('No checkpoint was taken exactly at that point (checkpoints are coalesced), so files were NOT restored. Use /rollback, or restore by hand.');
  } else {
    const report = await session.checkpoints.restoreTo(plan.checkpoint, { paths: all ? null : plan.paths });
    lines.push(`Restored ${report.restored.length} file(s) and removed ${report.deleted.length} to match checkpoint #${plan.checkpoint}.`);
    if (!all && plan.otherChanges) lines.push('Something other than the file tools (such as a shell command) changed things after that point; only /rewind --all puts those back.');
    if (!all) lines.push('Only files the agent wrote were restored, so your own edits are kept.');
    for (const skipped of report.skipped) lines.push(`not saved: ${skipped.path} (${skipped.why})`);
  }
  if (plan.notUndone.length > 0) lines.push(`Not undone, because a rewind cannot take them back:\n${plan.notUndone.map((item) => `  - ${item}`).join('\n')}`);

  const parent = session.sessionId;
  const paths = resolvePaths(options.env);
  const childId = newSessionId();
  session.agent.record('session/link', { kind: 'rewound-to', child: childId, boundary: plan.boundary });
  await session.agent.close();
  await session.close();
  const key = await loadOrCreateLogKey(paths.logKey);
  const folder = join(paths.sessions, projectKey(options.workdir));
  const source = parseLog(await readFile(join(folder, parent)), key);
  const writer = await forkSession({ source, path: join(folder, childId), sessionId: childId, key, boundarySeq: plan.boundary });
  await writer.close();
  const { sessionId: _old, ...rest } = options;
  const next = await openSession({ ...rest, sessionId: childId, linkedFrom: { kind: 'rewind', parent, boundary: plan.boundary } }, keys);
  door.out(`${lines.join('\n')}\nNow in session ${childId}, which ends just before turn ${turn}. The old session is ${parent}; resume it with hn --resume ${parent}.\n`);
  return next;
}
