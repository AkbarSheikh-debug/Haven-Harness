import type { SessionEvent } from '@hn/core';

export const TODO_STATUSES = ['pending', 'in_progress', 'completed'] as const;
export type TodoStatus = (typeof TODO_STATUSES)[number];
export const GOAL_STATUSES = ['active', 'done', 'blocked', 'abandoned'] as const;
export type GoalStatus = (typeof GOAL_STATUSES)[number];

export interface Todo {
  readonly content: string;
  readonly status: TodoStatus;
}

export interface Goal {
  readonly objective: string;
  readonly criteria: string | null;
  readonly status: GoalStatus;
  readonly progress: string | null;
}

function isTodo(value: unknown): value is Todo {
  if (typeof value !== 'object' || value === null) return false;
  const todo = value as Record<string, unknown>;
  return typeof todo['content'] === 'string' && (TODO_STATUSES as readonly unknown[]).includes(todo['status']);
}

/** The list as the newest `todo/write` left it. A projection of the log, so it survives folds and resumes. */
export function currentTodos(events: readonly SessionEvent[]): Todo[] {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index] as SessionEvent;
    if (event.type !== 'todo/write') continue;
    const todos = event.data['todos'];
    return Array.isArray(todos) ? todos.filter(isTodo) : [];
  }
  return [];
}

/** The goal as the `goal/change` rows built it: a create sets it, an update changes status or progress. */
export function currentGoal(events: readonly SessionEvent[]): Goal | null {
  let goal: Goal | null = null;
  for (const event of events) {
    if (event.type !== 'goal/change') continue;
    const next = event.data['goal'] as Partial<Goal> | undefined;
    if (next === undefined || typeof next !== 'object' || next === null) continue;
    if (event.data['action'] === 'create' && typeof next.objective === 'string') {
      goal = { objective: next.objective, criteria: next.criteria ?? null, status: 'active', progress: null };
    } else if (event.data['action'] === 'update' && goal !== null) {
      const previous: Goal = goal;
      const known = (GOAL_STATUSES as readonly unknown[]).includes(next.status);
      const status: GoalStatus = known ? (next.status as GoalStatus) : previous.status;
      const progress = typeof next.progress === 'string' ? next.progress : previous.progress;
      goal = { ...previous, status, progress };
    }
  }
  return goal;
}

const MARK: Readonly<Record<TodoStatus, string>> = { pending: '[ ]', in_progress: '[>]', completed: '[x]' };

export function renderTodos(todos: readonly Todo[]): string {
  return todos.map((todo, index) => `${index + 1}. ${MARK[todo.status]} ${todo.content}`).join('\n');
}

/**
 * The goal and the todo list as one row, sent again after a fold so the plan outlives the turns that made it.
 * Both were written by the model, so the row is model text, inside a frame it cannot close.
 */
export function planStateText(events: readonly SessionEvent[]): string | null {
  const goal = currentGoal(events);
  const todos = currentTodos(events);
  if (goal === null && todos.length === 0) return null;
  const lines = ['The current plan, kept across the fold (written earlier in this session):'];
  if (goal !== null) {
    lines.push(`Goal (${goal.status}): ${goal.objective}`);
    if (goal.criteria !== null) lines.push(`Done when: ${goal.criteria}`);
    if (goal.progress !== null) lines.push(`Progress: ${goal.progress}`);
  }
  if (todos.length > 0) lines.push('Todos:', renderTodos(todos));
  const body = lines.join('\n').replace(/<\/(system-reminder)/gi, '<\\/$1');
  return `<system-reminder>\n${body}\n</system-reminder>`;
}
