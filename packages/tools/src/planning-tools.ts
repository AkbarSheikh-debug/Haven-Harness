import { sanitizeForDisplay } from '@hn/core';
import type { ToolArgs, ToolDefinition, ToolResult } from './types.ts';

const MAX_TODOS = 50;
const MAX_TODO_CHARS = 500;
const MAX_GOAL_CHARS = 2_000;
const MAX_QUESTION_CHARS = 1_000;
const MAX_OPTIONS = 4;
const STATUSES = ['pending', 'in_progress', 'completed'] as const;
const GOAL_STATUSES = ['active', 'done', 'blocked', 'abandoned'] as const;

export interface GoalView {
  readonly objective: string;
  readonly criteria: string | null;
  readonly status: string;
  readonly progress: string | null;
}

export interface QuestionOption {
  readonly label: string;
  readonly description?: string;
}

export interface Question {
  readonly question: string;
  readonly options: readonly QuestionOption[];
  readonly multiSelect: boolean;
}

/** What a person did with a question: picked options by number, or typed their own answer. */
export type Answer =
  | { readonly kind: 'options'; readonly picked: readonly number[] }
  | { readonly kind: 'text'; readonly text: string };

export interface PlanningOptions {
  /** The gate's way out of plan mode. Only reached after a person said yes. */
  readonly leavePlan: () => string;
  readonly goal: () => GoalView | null;
  /** True once untrusted text is in the session: then a goal is a person's decision, shown in full. */
  readonly tainted: () => boolean;
  /** A person at a door. Absent in unattended runs, where questions get a plain refusal. */
  readonly ask?: (question: Question) => Promise<Answer | null>;
}

const fail = (content: string): ToolResult => ({ content, isError: true, origin: 'harness' });
const text = (args: ToolArgs, name: string): string => (typeof args[name] === 'string' ? (args[name] as string).trim() : '');

type Base = Pick<ToolDefinition, 'name' | 'description' | 'parameters' | 'deferred' | 'concurrencySafe' | 'paths'>;

/** Every planning tool is deferred, so the `tools` array in the prompt never changes. */
function base(name: string, description: string, parameters: Record<string, unknown>): Base {
  const schema = { type: 'object', additionalProperties: false, ...parameters };
  return { name, description, parameters: schema, deferred: true, concurrencySafe: false, paths: () => [] };
}

function parseTodos(raw: unknown): { content: string; status: string }[] | string {
  if (!Array.isArray(raw) || raw.length > MAX_TODOS) return `todos must be a list of at most ${MAX_TODOS} items.`;
  const todos: { content: string; status: string }[] = [];
  for (const item of raw as unknown[]) {
    const entry = (typeof item === 'object' && item !== null ? item : {}) as Record<string, unknown>;
    const content = typeof entry['content'] === 'string' ? entry['content'].trim() : '';
    const status = entry['status'];
    if (content === '' || content.length > MAX_TODO_CHARS) return `Each todo needs content of 1 to ${MAX_TODO_CHARS} characters.`;
    if (!(STATUSES as readonly unknown[]).includes(status)) return `status must be one of ${STATUSES.join(', ')}.`;
    todos.push({ content, status: status as string });
  }
  if (todos.filter((todo) => todo.status === 'in_progress').length > 1) return 'Only one todo may be in_progress at a time.';
  return todos;
}

function todoWrite(): ToolDefinition {
  const item = { type: 'object', properties: { content: { type: 'string' }, status: { enum: [...STATUSES] } }, required: ['content', 'status'] };
  return {
    ...base('todo_write', 'Replace the task list for this work. Keep at most one item in_progress.', {
      properties: { todos: { type: 'array', items: item } },
      required: ['todos'],
    }),
    effect: 'observe',
    summary: () => 'update the task list',
    async execute(args) {
      const todos = parseTodos(args['todos']);
      if (typeof todos === 'string') return fail(todos);
      const done = todos.filter((todo) => todo.status === 'completed').length;
      const records = [{ type: 'todo/write' as const, data: { todos } }];
      return { content: `Task list saved: ${done} of ${todos.length} done.`, origin: 'harness', records };
    },
  };
}

function exitPlanMode(options: PlanningOptions): ToolDefinition {
  return {
    ...base('exit_plan_mode', 'Show the plan to the user and, if they approve it, leave plan mode so the work can start.', {
      properties: { plan: { type: 'string', description: 'The plan, as the user should read it.' } },
      required: ['plan'],
    }),
    effect: 'reversible',
    requiresHuman: () => true,
    summary: (args) => `Leave plan mode and start this plan:\n${text(args, 'plan')}`,
    target: () => 'leave plan mode',
    async execute(args) {
      if (text(args, 'plan') === '') return fail('Give the plan itself, so the user knows what they are approving.');
      const mode = options.leavePlan();
      return { content: `The user approved the plan. The session is now in ${mode} mode. Carry out the plan.`, origin: 'harness' };
    },
  };
}

function createGoal(options: PlanningOptions): ToolDefinition {
  return {
    ...base('create_goal', 'Set the goal for this session: what done means. Only one goal is active at a time.', {
      properties: { objective: { type: 'string' }, criteria: { type: 'string', description: 'How to tell it is done.' } },
      required: ['objective'],
    }),
    effect: 'reversible',
    requiresHuman: () => options.tainted(),
    summary: (args) => {
      const criteria = text(args, 'criteria');
      return `Set the goal: ${text(args, 'objective')}${criteria === '' ? '' : `\nDone when: ${criteria}`}`;
    },
    async execute(args) {
      const objective = text(args, 'objective');
      const criteria = text(args, 'criteria');
      if (objective === '' || objective.length + criteria.length > MAX_GOAL_CHARS) {
        return fail(`The goal needs an objective, under ${MAX_GOAL_CHARS} characters in all.`);
      }
      if (options.goal()?.status === 'active') return fail('A goal is already active. Finish, block or abandon it with update_goal first.');
      const goal = { objective, criteria: criteria === '' ? null : criteria };
      return { content: `Goal set: ${objective}`, origin: 'harness', records: [{ type: 'goal/change', data: { action: 'create', goal } }] };
    },
  };
}

function getGoal(options: PlanningOptions): ToolDefinition {
  return {
    ...base('get_goal', 'Show the current goal and its progress.', { properties: {} }),
    effect: 'observe',
    concurrencySafe: true,
    summary: () => 'read the goal',
    async execute() {
      const goal = options.goal();
      if (goal === null) return { content: 'No goal is set.', origin: 'harness' };
      const lines = [`Goal (${goal.status}): ${goal.objective}`];
      if (goal.criteria !== null) lines.push(`Done when: ${goal.criteria}`);
      if (goal.progress !== null) lines.push(`Progress: ${goal.progress}`);
      return { content: lines.join('\n'), origin: 'model-derived' };
    },
  };
}

function updateGoal(options: PlanningOptions): ToolDefinition {
  return {
    ...base('update_goal', 'Record progress on the goal, or mark it done, blocked or abandoned.', {
      properties: { status: { enum: [...GOAL_STATUSES] }, progress: { type: 'string' } },
    }),
    effect: 'reversible',
    requiresHuman: () => options.tainted(),
    summary: (args) => `Update the goal: ${text(args, 'status') || 'progress'} ${text(args, 'progress')}`.trim(),
    async execute(args) {
      if (options.goal() === null) return fail('There is no goal to update. Set one with create_goal.');
      const status = args['status'];
      if (status !== undefined && !(GOAL_STATUSES as readonly unknown[]).includes(status)) {
        return fail(`status must be one of ${GOAL_STATUSES.join(', ')}.`);
      }
      const progress = text(args, 'progress').slice(0, MAX_GOAL_CHARS);
      const goal = { ...(status === undefined ? {} : { status }), ...(progress === '' ? {} : { progress }) };
      return { content: 'Goal updated.', origin: 'harness', records: [{ type: 'goal/change', data: { action: 'update', goal } }] };
    },
  };
}

function parseQuestion(args: ToolArgs): Question | string {
  const question = text(args, 'question');
  if (question === '' || question.length > MAX_QUESTION_CHARS) return `question must be 1 to ${MAX_QUESTION_CHARS} characters.`;
  const raw = args['options'];
  if (!Array.isArray(raw) || raw.length < 2 || raw.length > MAX_OPTIONS) return `Give 2 to ${MAX_OPTIONS} options.`;
  // Model text is shown to a person, so it is cleaned the way every door shows model text.
  const options: QuestionOption[] = [];
  for (const item of raw as unknown[]) {
    const entry = (typeof item === 'object' && item !== null ? item : {}) as Record<string, unknown>;
    const label = typeof entry['label'] === 'string' ? sanitizeForDisplay(entry['label'].trim().slice(0, 200)) : '';
    if (label === '') return 'Every option needs a label.';
    const description = typeof entry['description'] === 'string' ? sanitizeForDisplay(entry['description'].slice(0, 500)) : undefined;
    options.push(description === undefined ? { label } : { label, description });
  }
  return { question: sanitizeForDisplay(question), options, multiSelect: args['multiSelect'] === true };
}

/**
 * `ask_user_question`. A pick among options the model wrote is `human-selected`, never `user`: the person chose,
 * but the words are the model's. Only text the person typed comes back as `user`.
 */
function askUserQuestion(options: PlanningOptions): ToolDefinition {
  const option = { type: 'object', properties: { label: { type: 'string' }, description: { type: 'string' } }, required: ['label'] };
  return {
    ...base('ask_user_question', 'Ask the user one question with 2 to 4 options. They may also type their own answer.', {
      properties: { question: { type: 'string' }, options: { type: 'array', items: option }, multiSelect: { type: 'boolean' } },
      required: ['question', 'options'],
    }),
    effect: 'observe',
    summary: (args) => `ask: ${text(args, 'question')}`,
    async execute(args) {
      const question = parseQuestion(args);
      if (typeof question === 'string') return fail(question);
      if (options.ask === undefined) return fail('Nobody is here to answer. Decide with what you know, and say what you assumed.');
      const answer = await options.ask(question);
      if (answer === null) return fail('The user did not answer.');
      if (answer.kind === 'text') return { content: `The user answered in their own words: ${answer.text}`, origin: 'user' };
      const picked = answer.picked.filter((index) => index >= 0 && index < question.options.length);
      if (picked.length === 0) return fail('The user did not pick an option.');
      const labels = picked.map((index) => `${index + 1}. ${question.options[index]?.label ?? ''}`).join('; ');
      return { content: `The user picked: ${labels}`, origin: 'human-selected' };
    },
  };
}

export function createPlanningTools(options: PlanningOptions): ToolDefinition[] {
  return [todoWrite(), exitPlanMode(options), createGoal(options), getGoal(options), updateGoal(options), askUserQuestion(options)];
}
