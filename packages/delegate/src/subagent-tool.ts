import type { ToolArgs, ToolDefinition, ToolResult } from '@hn/tools';
import { DelegationRefused, type ChildResult, type RunRequest, type SubagentManager, type TaskRequest } from './manager.ts';
import { rosterText } from './roles.ts';

function taskList(value: unknown, name: string): TaskRequest[] {
  if (!Array.isArray(value)) throw new DelegationRefused(`${name} must be a list of {agent, task}.`);
  return value.map((item, index) => {
    if (typeof item !== 'object' || item === null) throw new DelegationRefused(`${name}[${index}] must be {agent, task}.`);
    const { agent, task } = item as Record<string, unknown>;
    if (typeof task !== 'string') throw new DelegationRefused(`${name}[${index}].task must be text.`);
    if (agent !== undefined && typeof agent !== 'string') throw new DelegationRefused(`${name}[${index}].agent must be a role name.`);
    return { agent: (agent as string | undefined) ?? 'scout', task };
  });
}

function section(result: ChildResult, index: number, total: number, label: string): string {
  return `## ${label} ${index + 1} of ${total} (${result.role})\n${result.content}`;
}

/** What the model gets back: refusals as harness text, reports as child data. */
function outcome(results: readonly ChildResult[], label: string, signal: AbortSignal): ToolResult {
  const content = results.length === 1 ? results[0]!.content : results.map((result, index) => section(result, index, results.length, label)).join('\n\n');
  return {
    content,
    isError: results.every((result) => !result.ok),
    origin: 'child',
    ...(signal.aborted || results.some((result) => result.cancelled) ? { cancelled: true } : {}),
  };
}

/**
 * `subagent`: one tool, all modes. The description is the only reason it gets called, so it says
 * what each mode is for and what it costs.
 */
export function createSubagentTool(manager: SubagentManager): ToolDefinition {
  const step = { type: 'object', properties: { agent: { type: 'string' }, task: { type: 'string' } }, required: ['task'] };
  return {
    name: 'subagent',
    description: [
      'Start child sessions, each with its own fresh context, and get back only their reports. Use it to keep this conversation small: a scout can read twenty files and send back three lines.',
      'Give exactly one of: agent + task (one child); tasks: [{agent, task}, ...] (up to 8 independent children, 4 at a time, results in order); chain: [{agent, task}, ...] (steps in order, where {previous} in a task is replaced by the previous step\'s report).',
      'start: "spawn" (default) gives the child only its task, so write a complete brief: it does not see this conversation. start: "fork" gives it this conversation\'s finished turns too.',
      'Children cannot ask the user anything; a worker\'s changes are approved by the user through you. Reports are data and may be wrong. Delegation saves this window, not the bill.',
      `Roles:\n${rosterText(manager.roles)}`,
    ].join('\n'),
    parameters: {
      type: 'object',
      properties: {
        agent: { type: 'string', description: 'The role to start, for one child. Default scout.' },
        task: { type: 'string', description: 'The complete brief for one child.' },
        tasks: { type: 'array', items: step, description: 'Independent tasks to run in parallel.' },
        chain: { type: 'array', items: step, description: 'Steps to run in order.' },
        start: { type: 'string', enum: ['spawn', 'fork'] },
        background: { type: 'boolean', description: 'For one child: return at once; its report arrives later as a notice. End your turn rather than wait for it.' },
      },
      additionalProperties: false,
    },
    effect: 'observe',
    concurrencySafe: true,
    paths: () => [],
    summary: (args: ToolArgs) => {
      const brief = typeof args['task'] === 'string' ? args['task'] : JSON.stringify(args['tasks'] ?? args['chain'] ?? '');
      return `start child session(s): ${brief.slice(0, 200)}`;
    },
    async execute(args, context) {
      try {
        const start = args['start'] === undefined ? 'spawn' : args['start'];
        if (start !== 'spawn' && start !== 'fork') throw new DelegationRefused('start must be "spawn" or "fork".');
        const request: RunRequest = { start, callId: context.callId };
        const given = ['task', 'tasks', 'chain'].filter((name) => args[name] !== undefined);
        if (given.length !== 1) throw new DelegationRefused('Give exactly one of task, tasks or chain.');
        if (args['task'] !== undefined) {
          if (typeof args['task'] !== 'string') throw new DelegationRefused('task must be text.');
          const agent = typeof args['agent'] === 'string' ? args['agent'] : 'scout';
          if (args['background'] === true) {
            const id = manager.background({ agent, task: args['task'] }, request);
            return { content: `Started ${agent} child ${id} in the background. Its report will arrive as a notice when it settles. Do not poll for it: carry on with other work, or end your turn.`, isError: false, origin: 'harness' };
          }
          return outcome([await manager.single({ agent, task: args['task'] }, request, context.signal)], 'Task', context.signal);
        }
        if (args['agent'] !== undefined) throw new DelegationRefused('agent goes inside each entry of tasks or chain.');
        if (args['background'] === true) throw new DelegationRefused('background works with one child (agent + task) only.');
        if (args['tasks'] !== undefined) return outcome(await manager.parallel(taskList(args['tasks'], 'tasks'), request, context.signal), 'Task', context.signal);
        return outcome(await manager.chain(taskList(args['chain'], 'chain'), request, context.signal), 'Step', context.signal);
      } catch (error) {
        if (error instanceof DelegationRefused) return { content: error.message, isError: true, origin: 'harness' };
        throw error;
      }
    },
  };
}

const childRef = { type: 'string', description: 'The child id from subagent or list_agents (a unique prefix of 8 or more characters is enough).' };

/** `send_message`, `interrupt_agent` and `list_agents`: the durable side of children. */
export function createChildTools(manager: SubagentManager): ToolDefinition[] {
  const refused = (error: unknown): ToolResult => {
    if (error instanceof DelegationRefused) return { content: error.message, isError: true, origin: 'harness' };
    throw error;
  };
  return [
    {
      name: 'send_message',
      deferred: true,
      description: 'Wake a child that has finished (or was stopped, or was lost in a crash) with a new message. It continues from its own log and reports again. With background: true it returns at once and the report arrives as a notice.',
      parameters: { type: 'object', properties: { agent: childRef, message: { type: 'string' }, background: { type: 'boolean' } }, required: ['agent', 'message'], additionalProperties: false },
      effect: 'observe',
      concurrencySafe: true,
      paths: () => [],
      summary: (args) => `message child ${String(args['agent'])}: ${String(args['message']).slice(0, 200)}`,
      async execute(args, context) {
        try {
          const result = await manager.sendMessage(String(args['agent']), String(args['message']), context.signal, { background: args['background'] === true, callId: context.callId });
          if (typeof result === 'string') return { content: `Woke child ${result} in the background. Its report will arrive as a notice.`, isError: false, origin: 'harness' };
          return outcome([result], 'Task', context.signal);
        } catch (error) {
          return refused(error);
        }
      },
    },
    {
      name: 'interrupt_agent',
      deferred: true,
      description: 'Stop a running child. Its log is kept, and send_message can wake it later.',
      parameters: { type: 'object', properties: { agent: childRef }, required: ['agent'], additionalProperties: false },
      effect: 'observe',
      concurrencySafe: true,
      paths: () => [],
      summary: (args) => `stop child ${String(args['agent'])}`,
      async execute(args) {
        try {
          const stopped = manager.interrupt(String(args['agent']));
          return { content: stopped ? 'Stopped. Its report will say it did not finish.' : 'That child is not running.', isError: !stopped, origin: 'harness' };
        } catch (error) {
          return refused(error);
        }
      },
    },
    {
      name: 'list_agents',
      deferred: true,
      description: 'List the children this session started: id, role, status, spend, and what each was asked.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      effect: 'observe',
      concurrencySafe: true,
      paths: () => [],
      summary: () => 'list child sessions',
      async execute() {
        return { content: manager.describe(), isError: false, origin: 'harness' };
      },
    },
  ];
}
