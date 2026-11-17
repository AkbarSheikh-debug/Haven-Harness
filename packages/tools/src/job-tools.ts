import type { SessionEvent } from '@hn/core';
import type { ProcessSignal } from '@hn/operations';
import type { Job, JobManager } from './jobs.ts';
import type { ToolArgs, ToolContext, ToolDefinition, ToolResult } from './types.ts';

/** The most new output one read returns; older output is cut from the front, so the newest is always shown. */
const MAX_READ_CHARS = 20_000;
const MAX_INPUT_CHARS = 10_000;
const SIGNALS: readonly ProcessSignal[] = ['interrupt', 'terminate', 'kill'];

const fail = (content: string): ToolResult => ({ content, isError: true, origin: 'harness' });
const idOf = (args: ToolArgs): string => (typeof args['id'] === 'string' ? args['id'] : '');

function tail(bytes: Buffer): string {
  const text = bytes.toString('utf8');
  if (text.length <= MAX_READ_CHARS) return text;
  return `[... ${text.length - MAX_READ_CHARS} earlier chars not shown ...]\n${text.slice(-MAX_READ_CHARS)}`;
}

/** New output and the state of a job, as one message. */
export function describeOutput(job: Job, output: { stdout: Buffer; stderr: Buffer }): string {
  const parts = [
    output.stdout.length === 0 ? '' : tail(output.stdout).trimEnd(),
    output.stderr.length === 0 ? '' : `[stderr]\n${tail(output.stderr).trimEnd()}`,
  ].filter((part) => part !== '');
  const state = job.status === 'running' ? 'still running' : `${job.status}${job.code === null ? '' : ` with code ${job.code}`}`;
  return `${parts.length === 0 ? '(no new output)' : parts.join('\n')}\n\n[${job.id} ${state}]`;
}

/** Jobs a previous run of this session left behind, from the log. A crash closed them as `lost`. */
function loggedJobs(events: readonly SessionEvent[]): Map<string, { command: string; status: string }> {
  const jobs = new Map<string, { command: string; status: string }>();
  for (const event of events) {
    const id = event.data['jobId'];
    if (typeof id !== 'string') continue;
    if (event.type === 'job/registered') jobs.set(id, { command: String(event.data['command'] ?? ''), status: 'running' });
    if (event.type === 'job/settled') {
      const known = jobs.get(id);
      if (known !== undefined) known.status = String(event.data['status'] ?? 'settled');
    }
  }
  return jobs;
}

function lookup(context: ToolContext, args: ToolArgs, kind: Job['kind']): Job | string {
  const jobs = context.jobs;
  if (jobs === undefined) return 'Jobs are not available in this session.';
  const job = jobs.get(idOf(args));
  if (job === null || job.kind !== kind) {
    return `No ${kind === 'terminal' ? 'terminal' : 'job'} ${JSON.stringify(idOf(args).slice(0, 40))} belongs to this session.`;
  }
  return job;
}

type Spec = Pick<ToolDefinition, 'name' | 'description' | 'parameters' | 'deferred' | 'paths'>;

function spec(name: string, description: string, properties: Record<string, unknown>, required: string[] = []): Spec {
  const parameters = { type: 'object', properties, required, additionalProperties: false };
  return { name, description, parameters, deferred: true, paths: () => [] };
}

const ID = { id: { type: 'string' } };

function listTool(name: string, kind: Job['kind'], history: () => readonly SessionEvent[]): ToolDefinition {
  return {
    ...spec(name, kind === 'bash' ? 'List background jobs and their state.' : 'List open terminals.', {}),
    effect: 'observe',
    concurrencySafe: true,
    summary: () => name,
    async execute(_args, context) {
      const live = (context.jobs?.list() ?? []).filter((job) => job.kind === kind);
      const lines = live.map((job) => `${job.id}  ${job.status}${job.code === null ? '' : ` (${job.code})`}  ${job.command.slice(0, 120)}`);
      const known = new Set(live.map((job) => job.id));
      const prefix = kind === 'bash' ? 'job-' : 'term-';
      for (const [id, entry] of loggedJobs(history())) {
        if (!known.has(id) && id.startsWith(prefix)) lines.push(`${id}  ${entry.status}  ${entry.command.slice(0, 120)}`);
      }
      return { content: lines.length === 0 ? 'None.' : lines.join('\n'), origin: 'harness' };
    },
  };
}

function readTool(name: string, kind: Job['kind']): ToolDefinition {
  return {
    ...spec(name, 'Show the output since you last looked, and whether it is still running.', ID, ['id']),
    effect: 'observe',
    concurrencySafe: true,
    summary: (args) => `${name} ${idOf(args)}`,
    async execute(args, context) {
      const job = lookup(context, args, kind);
      if (typeof job === 'string') return fail(job);
      return { content: describeOutput(job, (context.jobs as JobManager).take(job)), origin: 'tool-output' };
    },
  };
}

function stopTool(name: string, kind: Job['kind'], description: string, closeInput: boolean): ToolDefinition {
  return {
    ...spec(name, description, ID, ['id']),
    effect: 'observe',
    concurrencySafe: false,
    summary: (args) => `${name} ${idOf(args)}`,
    async execute(args, context) {
      const job = lookup(context, args, kind);
      if (typeof job === 'string') return fail(job);
      if (closeInput) job.process.closeInput();
      (context.jobs as JobManager).signal(job, 'kill');
      await Promise.race([job.process.exited, new Promise((resolve) => setTimeout(resolve, 5_000))]);
      return { content: `Stopped ${job.id}.`, origin: 'harness' };
    },
  };
}

function terminalOpen(): ToolDefinition {
  const description =
    'Start an interactive program, such as a shell or a REPL, and keep it open. Plain pipes: no colours or full-screen programs.';
  return {
    ...spec('terminal_open', description, { command: { type: 'string' } }, ['command']),
    effect: 'execution',
    concurrencySafe: false,
    command: (args) => String(args['command']),
    summary: (args) => `open a terminal: ${String(args['command'])}`,
    async execute(args, context) {
      if (context.jobs === undefined) return fail('Terminals are not available in this session.');
      const job = context.jobs.start('terminal', String(args['command']), context.workdir);
      if (typeof job === 'string') return fail(job);
      return { content: `Opened ${job.id}. Send input with terminal_send and read with terminal_read.`, origin: 'harness' };
    },
  };
}

/** What is typed into a terminal runs, so it passes the gate as a command, exactly as typed. */
function terminalSend(): ToolDefinition {
  const properties = { ...ID, input: { type: 'string' }, newline: { type: 'boolean' } };
  return {
    ...spec('terminal_send', 'Type input into an open terminal. A newline is added unless newline is false.', properties, ['id', 'input']),
    effect: 'execution',
    concurrencySafe: false,
    command: (args) => String(args['input']),
    summary: (args) => `type into ${idOf(args)}: ${String(args['input'])}`,
    async execute(args, context) {
      const job = lookup(context, args, 'terminal');
      if (typeof job === 'string') return fail(job);
      const input = String(args['input']);
      if (input.length > MAX_INPUT_CHARS) return fail(`Input is limited to ${MAX_INPUT_CHARS} characters.`);
      if (job.status !== 'running') return fail(`${job.id} is not running.`);
      job.process.write(args['newline'] === false ? input : `${input}\n`);
      return { content: `Sent to ${job.id}. Read the reply with terminal_read.`, origin: 'harness' };
    },
  };
}

function terminalSignal(): ToolDefinition {
  return {
    ...spec('terminal_signal', 'Send interrupt, terminate or kill to an open terminal.', { ...ID, signal: { enum: [...SIGNALS] } }, ['id', 'signal']),
    effect: 'observe',
    concurrencySafe: false,
    summary: (args) => `signal ${idOf(args)} ${String(args['signal'])}`,
    async execute(args, context) {
      const job = lookup(context, args, 'terminal');
      if (typeof job === 'string') return fail(job);
      const kind = args['signal'] as ProcessSignal;
      if (!SIGNALS.includes(kind)) return fail(`signal must be one of ${SIGNALS.join(', ')}.`);
      (context.jobs as JobManager).signal(job, kind);
      return { content: `Sent ${kind} to ${job.id}.`, origin: 'harness' };
    },
  };
}

/** The long-running family. All deferred, so the `tools` array in the prompt never changes. */
export function createJobTools(history: () => readonly SessionEvent[]): ToolDefinition[] {
  return [
    listTool('job_list', 'bash', history),
    readTool('job_output', 'bash'),
    stopTool('job_kill', 'bash', 'Stop a background job and everything it started.', false),
    terminalOpen(),
    terminalSend(),
    readTool('terminal_read', 'terminal'),
    terminalSignal(),
    listTool('terminal_list', 'terminal', history),
    stopTool('terminal_close', 'terminal', 'Close a terminal and stop everything it started.', true),
  ];
}
