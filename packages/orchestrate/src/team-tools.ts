import type { ToolArgs, ToolDefinition, ToolResult } from '@hn/tools';
import { LEAD, describeTasks, type TeamAction } from './team-graph.ts';
import type { Team } from './team.ts';

const list = (value: unknown): string[] => (Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []);

/** A tool call's arguments as one graph action. Anything malformed is a clear refusal, never a guess. */
export function toAction(args: ToolArgs): TeamAction | string {
  const kind = String(args['action'] ?? '');
  const id = typeof args['id'] === 'string' ? args['id'] : '';
  const revision = Number(args['revision']);
  if (kind === 'create') {
    return { kind, title: String(args['title'] ?? ''), ...(typeof args['detail'] === 'string' ? { detail: args['detail'] } : {}), deps: list(args['deps']), scope: list(args['scope']) };
  }
  if (!['claim', 'release', 'reopen', 'delete', 'edit', 'set_dependencies', 'complete', 'reassign'].includes(kind)) return `Unknown action "${kind}". Use list, create, claim, release, edit, set_dependencies, complete, reopen, reassign or delete.`;
  if (id === '' || !Number.isSafeInteger(revision)) return `${kind} needs the task id and the revision you last saw (list shows both).`;
  switch (kind) {
    case 'edit':
      return { kind, id, revision, ...(typeof args['title'] === 'string' ? { title: args['title'] } : {}), ...(typeof args['detail'] === 'string' ? { detail: args['detail'] } : {}), ...(Array.isArray(args['scope']) ? { scope: list(args['scope']) } : {}) };
    case 'set_dependencies':
      return { kind, id, revision, deps: list(args['deps']) };
    case 'reassign':
      return { kind, id, revision, to: typeof args['to'] === 'string' ? args['to'] : null };
    default:
      return { kind: kind as 'claim' | 'release' | 'reopen' | 'delete' | 'complete', id, revision };
  }
}

const taskParameters = {
  type: 'object',
  properties: {
    action: { type: 'string', description: 'list, create, claim, release, edit, set_dependencies, complete, reopen, reassign or delete' },
    id: { type: 'string' },
    revision: { type: 'integer', description: 'The task revision you last saw; a stale one is refused.' },
    title: { type: 'string' },
    detail: { type: 'string' },
    deps: { type: 'array', items: { type: 'string' } },
    scope: { type: 'array', items: { type: 'string' } },
    to: { type: 'string' },
  },
  required: ['action'],
  additionalProperties: false,
};

const observe = { effect: 'observe' as const, concurrencySafe: false, paths: () => [] };
const refused = (error: unknown): ToolResult => ({ content: error instanceof Error ? error.message : String(error), isError: true, origin: 'harness' });

/** A member's tools: they speak to the Lead over the member's private channel, and the Lead decides. */
export function createMemberTools(ask: (request: Record<string, unknown>) => Promise<unknown>): ToolDefinition[] {
  return [
    {
      name: 'team_task',
      description: 'The team task graph. list shows every task with its revision; claim an open task before working on it, and complete it when its work is in your folder (the lead then merges it). Every change names the revision you last saw.',
      parameters: taskParameters,
      ...observe,
      summary: (args) => `team task: ${String(args['action'])} ${String(args['id'] ?? args['title'] ?? '')}`,
      async execute(args) {
        try {
          if (args['action'] === 'list') return { content: String(await ask({ op: 'list' })), isError: false, origin: 'child' };
          const action = toAction(args);
          if (typeof action === 'string') return { content: action, isError: true, origin: 'harness' };
          return { content: String(await ask({ op: 'task', action })), isError: false, origin: 'child' };
        } catch (error) {
          return refused(error);
        }
      },
    },
    {
      name: 'team_message',
      description: 'Send a short message to another member by name, or to "lead".',
      parameters: { type: 'object', properties: { to: { type: 'string' }, text: { type: 'string' } }, required: ['to', 'text'], additionalProperties: false },
      ...observe,
      summary: (args) => `message ${String(args['to'])}: ${String(args['text']).slice(0, 200)}`,
      async execute(args) {
        try {
          return { content: String(await ask({ op: 'message', to: String(args['to']), text: String(args['text']) })), isError: false, origin: 'harness' };
        } catch (error) {
          return refused(error);
        }
      },
    },
  ];
}

/** The Lead's tools (experimental): start members, drive the graph, message, and wait for news. */
export function createLeadTools(team: Team): ToolDefinition[] {
  return [
    {
      name: 'team_spawn',
      deferred: true,
      description: 'Start a team member: a worker in its own clone of the project, with a name (never reused) and a brief. Members use the task graph and messages; their completed work is merged by your queue. At most 16 members.',
      parameters: { type: 'object', properties: { name: { type: 'string' }, brief: { type: 'string' } }, required: ['name', 'brief'], additionalProperties: false },
      ...observe,
      summary: (args) => `start team member ${String(args['name'])}: ${String(args['brief']).slice(0, 200)}`,
      async execute(args) {
        try {
          return { content: await team.addMember(String(args['name']), String(args['brief'])), isError: false, origin: 'harness' };
        } catch (error) {
          return refused(error);
        }
      },
    },
    {
      name: 'team_task',
      deferred: true,
      description: 'The team task graph, as the lead: list, create, edit, set_dependencies, reopen, reassign, delete. Every change names the revision you last saw.',
      parameters: taskParameters,
      ...observe,
      summary: (args) => `team task: ${String(args['action'])} ${String(args['id'] ?? args['title'] ?? '')}`,
      async execute(args) {
        if (args['action'] === 'list') return { content: describeTasks(team.snapshot), isError: false, origin: 'harness' };
        const action = toAction(args);
        if (typeof action === 'string') return { content: action, isError: true, origin: 'harness' };
        const result = team.apply(LEAD, action, 'model-derived');
        if (!result.ok) return { content: `${result.code}: ${result.message}`, isError: true, origin: 'harness' };
        return { content: [`${result.task.id} is now ${result.task.status} (revision ${result.task.revision}).`, ...result.warnings].join('\n'), isError: false, origin: 'harness' };
      },
    },
    {
      name: 'team_message',
      deferred: true,
      description: 'Send a message to a member by name. A running member reads it at its next step.',
      parameters: { type: 'object', properties: { to: { type: 'string' }, text: { type: 'string' } }, required: ['to', 'text'], additionalProperties: false },
      ...observe,
      summary: (args) => `message ${String(args['to'])}: ${String(args['text']).slice(0, 200)}`,
      async execute(args) {
        try {
          return { content: team.message(LEAD, String(args['to']), String(args['text']), 'model-derived'), isError: false, origin: 'harness' };
        } catch (error) {
          return refused(error);
        }
      },
    },
    {
      name: 'wait_agent',
      deferred: true,
      description: 'Wait until something happens in the team (a member finishes, a message for you, a merge), for 10 seconds to 1 hour.',
      parameters: { type: 'object', properties: { seconds: { type: 'integer' } }, additionalProperties: false },
      ...observe,
      summary: (args) => `wait up to ${String(args['seconds'] ?? 60)} s for the team`,
      async execute(args, context) {
        return { content: await team.wait(Number(args['seconds'] ?? 60), context.signal), isError: false, origin: 'child' };
      },
    },
  ];
}
