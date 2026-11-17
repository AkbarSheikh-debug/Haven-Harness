import type { Origin } from '@hn/core';
import { join as joinOrigins } from '@hn/security';

export const MAX_TEAM_TASKS = 256;
export const LEAD = 'lead';

export type TaskStatus = 'open' | 'claimed' | 'done' | 'deleted';

export interface TeamTask {
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  readonly status: TaskStatus;
  readonly owner: string | null;
  readonly deps: readonly string[];
  /** Paths the task is meant to change. Writing outside them warns. */
  readonly scope: readonly string[];
  /** Bumped by every change to this task: the compare-and-set token. */
  readonly revision: number;
  readonly createdBy: string;
  /** The worst origin of everything that wrote this task, so a reader joins the writer's taint. */
  readonly origin: Origin;
  /** Where the work for this task lives, when a branch holds it (a merge conflict). */
  readonly ref?: string;
}

/** The whole graph. Every write replaces it with a new snapshot. */
export interface TeamSnapshot {
  readonly revision: number;
  readonly tasks: readonly TeamTask[];
}

export const EMPTY_SNAPSHOT: TeamSnapshot = { revision: 0, tasks: [] };

export type TeamAction =
  | { readonly kind: 'create'; readonly title: string; readonly detail?: string; readonly deps?: readonly string[]; readonly scope?: readonly string[]; readonly ref?: string }
  | { readonly kind: 'claim' | 'release' | 'reopen' | 'delete'; readonly id: string; readonly revision: number }
  | { readonly kind: 'edit'; readonly id: string; readonly revision: number; readonly title?: string; readonly detail?: string; readonly scope?: readonly string[] }
  | { readonly kind: 'set_dependencies'; readonly id: string; readonly revision: number; readonly deps: readonly string[] }
  | { readonly kind: 'complete'; readonly id: string; readonly revision: number; readonly changed?: readonly string[] }
  | { readonly kind: 'reassign'; readonly id: string; readonly revision: number; readonly to: string | null };

export type TeamError = 'TEAM_TASK_STALE_REVISION' | 'TEAM_TASK_CYCLE' | 'TEAM_TASK_NOT_FOUND' | 'TEAM_TASK_FORBIDDEN' | 'TEAM_TASK_STATE' | 'TEAM_TASK_LIMIT' | 'TEAM_TASK_INVALID';

export type ApplyResult =
  | { readonly ok: true; readonly snapshot: TeamSnapshot; readonly task: TeamTask; readonly warnings: readonly string[] }
  | { readonly ok: false; readonly code: TeamError; readonly message: string };

const fail = (code: TeamError, message: string): ApplyResult => ({ ok: false, code, message });

/** True when the dependency edges, with `id -> deps` replaced, contain a cycle. Checks the whole graph, every time. */
export function hasCycle(tasks: readonly TeamTask[], id: string, deps: readonly string[]): boolean {
  const edges = new Map<string, readonly string[]>(tasks.filter((task) => task.status !== 'deleted').map((task) => [task.id, task.id === id ? deps : task.deps]));
  const state = new Map<string, 'visiting' | 'done'>();
  const visit = (node: string): boolean => {
    if (state.get(node) === 'done') return false;
    if (state.get(node) === 'visiting') return true;
    state.set(node, 'visiting');
    for (const next of edges.get(node) ?? []) if (visit(next)) return true;
    state.set(node, 'done');
    return false;
  };
  return [...edges.keys()].some(visit);
}

function inScope(path: string, scope: readonly string[]): boolean {
  const normal = path.replaceAll('\\', '/');
  return scope.some((entry) => {
    const prefix = entry.replaceAll('\\', '/').replace(/\/+$/, '');
    return normal === prefix || normal.startsWith(`${prefix}/`);
  });
}

/**
 * One write to the graph. Every action names the task revision it last saw, and a stale one is refused, so two
 * members cannot both win a claim. Only the owner completes or releases; only the Lead reassigns, reopens or deletes;
 * a claim needs every dependency done; the dependency graph is revalidated whole for cycles; at most 256 tasks.
 */
export function applyAction(snapshot: TeamSnapshot, action: TeamAction, actor: string, origin: Origin): ApplyResult {
  const revision = snapshot.revision + 1;
  const replace = (task: TeamTask, warnings: readonly string[] = []): ApplyResult => {
    const next = { ...task, revision: task.revision + 1, origin: joinOrigins(task.origin, origin) };
    return { ok: true, snapshot: { revision, tasks: snapshot.tasks.map((existing) => (existing.id === task.id ? next : existing)) }, task: next, warnings };
  };
  if (action.kind === 'create') {
    if (snapshot.tasks.length >= MAX_TEAM_TASKS) return fail('TEAM_TASK_LIMIT', `A team has at most ${MAX_TEAM_TASKS} tasks.`);
    const title = action.title.trim();
    if (title === '' || title.length > 200) return fail('TEAM_TASK_INVALID', 'A task title is 1 to 200 characters.');
    const id = `t${snapshot.tasks.length + 1}`;
    const deps = [...new Set(action.deps ?? [])];
    for (const dep of deps) if (!snapshot.tasks.some((task) => task.id === dep && task.status !== 'deleted')) return fail('TEAM_TASK_NOT_FOUND', `There is no task ${dep}.`);
    const task: TeamTask = { id, title, detail: (action.detail ?? '').slice(0, 4_000), status: 'open', owner: null, deps, scope: [...(action.scope ?? [])], revision: 1, createdBy: actor, origin, ...(action.ref === undefined ? {} : { ref: action.ref }) };
    return { ok: true, snapshot: { revision, tasks: [...snapshot.tasks, task] }, task, warnings: [] };
  }
  const task = snapshot.tasks.find((candidate) => candidate.id === action.id);
  if (task === undefined || task.status === 'deleted') return fail('TEAM_TASK_NOT_FOUND', `There is no task ${action.id}.`);
  if (action.revision !== task.revision) return fail('TEAM_TASK_STALE_REVISION', `Task ${task.id} is at revision ${task.revision}, not ${action.revision}; read it again and retry.`);
  const lead = actor === LEAD;
  switch (action.kind) {
    case 'claim': {
      if (task.status !== 'open') return fail('TEAM_TASK_STATE', `Task ${task.id} is ${task.status}, not open.`);
      const waiting = task.deps.filter((dep) => snapshot.tasks.find((other) => other.id === dep)?.status !== 'done');
      if (waiting.length > 0) return fail('TEAM_TASK_STATE', `Task ${task.id} waits for ${waiting.join(', ')}.`);
      return replace({ ...task, status: 'claimed', owner: actor });
    }
    case 'release':
      if (task.owner !== actor && !lead) return fail('TEAM_TASK_FORBIDDEN', `Only ${task.owner ?? 'its owner'} or the lead can release task ${task.id}.`);
      if (task.status !== 'claimed') return fail('TEAM_TASK_STATE', `Task ${task.id} is not claimed.`);
      return replace({ ...task, status: 'open', owner: null });
    case 'complete': {
      if (task.status !== 'claimed' || task.owner !== actor) return fail('TEAM_TASK_FORBIDDEN', `Only the owner of a claimed task can complete it; task ${task.id} is ${task.status}${task.owner === null ? '' : ` by ${task.owner}`}.`);
      const outside = task.scope.length === 0 ? [] : (action.changed ?? []).filter((path) => !inScope(path, task.scope));
      return replace({ ...task, status: 'done' }, outside.length === 0 ? [] : [`Task ${task.id} changed files outside its scope: ${outside.join(', ')}.`]);
    }
    case 'reopen':
      if (!lead) return fail('TEAM_TASK_FORBIDDEN', 'Only the lead can reopen a task.');
      return replace({ ...task, status: 'open', owner: null });
    case 'delete':
      if (!lead) return fail('TEAM_TASK_FORBIDDEN', 'Only the lead can delete a task.');
      if (snapshot.tasks.some((other) => other.status !== 'deleted' && other.deps.includes(task.id))) return fail('TEAM_TASK_STATE', `Other tasks depend on ${task.id}.`);
      return replace({ ...task, status: 'deleted', owner: null });
    case 'reassign':
      if (!lead) return fail('TEAM_TASK_FORBIDDEN', 'Only the lead can reassign a task.');
      if (task.status === 'done') return fail('TEAM_TASK_STATE', `Task ${task.id} is done.`);
      return replace({ ...task, status: action.to === null ? 'open' : 'claimed', owner: action.to });
    case 'edit':
      if (task.owner !== actor && task.createdBy !== actor && !lead) return fail('TEAM_TASK_FORBIDDEN', `Only the owner, the creator or the lead can edit task ${task.id}.`);
      return replace({ ...task, ...(action.title === undefined ? {} : { title: action.title.slice(0, 200) }), ...(action.detail === undefined ? {} : { detail: action.detail.slice(0, 4_000) }), ...(action.scope === undefined ? {} : { scope: [...action.scope] }) });
    case 'set_dependencies': {
      const deps = [...new Set(action.deps)];
      for (const dep of deps) if (!snapshot.tasks.some((other) => other.id === dep && other.status !== 'deleted')) return fail('TEAM_TASK_NOT_FOUND', `There is no task ${dep}.`);
      if (deps.includes(task.id) || hasCycle(snapshot.tasks, task.id, deps)) return fail('TEAM_TASK_CYCLE', `Those dependencies would make a cycle through ${task.id}.`);
      return replace({ ...task, deps });
    }
  }
}

/** Every task a member owns goes back to open: what happens when a member dies. */
export function releaseAll(snapshot: TeamSnapshot, member: string): TeamSnapshot {
  if (!snapshot.tasks.some((task) => task.owner === member && task.status === 'claimed')) return snapshot;
  return {
    revision: snapshot.revision + 1,
    tasks: snapshot.tasks.map((task) => (task.owner === member && task.status === 'claimed' ? { ...task, status: 'open', owner: null, revision: task.revision + 1 } : task)),
  };
}

/** The graph as text for a member or the lead: one line per live task. */
export function describeTasks(snapshot: TeamSnapshot): string {
  const live = snapshot.tasks.filter((task) => task.status !== 'deleted');
  if (live.length === 0) return 'The team has no tasks.';
  return live
    .map((task) => `${task.id} r${task.revision} [${task.status}${task.owner === null ? '' : ` ${task.owner}`}] ${task.title}${task.deps.length === 0 ? '' : ` (after ${task.deps.join(', ')})`}${task.ref === undefined ? '' : ` ref ${task.ref}`}`)
    .join('\n');
}
