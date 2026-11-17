import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { EventType, Origin, SessionEvent } from '@hn/core';
import type { SubagentManager, WorkspaceHooks } from '@hn/delegate';
import type { ProcessOperations, SafeFiles } from '@hn/operations';
import { LeasePool, createWorkflowTools, defaultLimits, processLauncher, type SavedWorkflowLoader, type WorkflowHandlers, type WorkflowLimits } from '@hn/orchestrate';
import type { TrustStore } from '@hn/security';
import type { HarnessDispatcher, ToolDefinition } from '@hn/tools';
import type { InstructionApprover } from './instructions.ts';

/** Tools a script may never call: delegation (agents go through agent()), the script runners themselves, and asking a person. */
export const NOT_FROM_A_SCRIPT: ReadonlySet<string> = new Set([
  'workflow', 'run_code', 'subagent', 'send_message', 'interrupt_agent', 'list_agents', 'external_agent',
  'ask_user_question', 'exit_plan_mode', 'team_spawn', 'team_task', 'team_message', 'wait_agent',
]);

const NAME = /^[a-z][a-z0-9-]{0,63}$/;

/** The first JSON value in an answer: the whole text, a fenced block, or the outermost braces or brackets. */
export function extractJson(text: string): unknown {
  const candidates = [text.trim(), /```(?:json)?\s*\n([\s\S]*?)```/.exec(text)?.[1] ?? '', text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1), text.slice(text.indexOf('['), text.lastIndexOf(']') + 1)];
  for (const candidate of candidates) {
    if (candidate.trim() === '') continue;
    try {
      return JSON.parse(candidate);
    } catch {
      // Try the next shape.
    }
  }
  return undefined;
}

/**
 * An agent's answer under a schema: a schema miss is a failure, so the value is null. Only the shape a workflow
 * needs is checked: the top-level type, and the required keys of an object.
 */
export function shapeAnswer(text: string, schema: unknown): unknown {
  if (schema === undefined || schema === null) return text;
  const value = extractJson(text);
  if (value === undefined) return null;
  const spec = schema as { type?: unknown; required?: unknown };
  if (spec.type === 'object' && (typeof value !== 'object' || value === null || Array.isArray(value))) return null;
  if (spec.type === 'array' && !Array.isArray(value)) return null;
  if (Array.isArray(spec.required) && typeof value === 'object' && value !== null && !Array.isArray(value)) {
    for (const key of spec.required) if (typeof key === 'string' && !(key in value)) return null;
  }
  return value;
}

export interface WorkflowSetup {
  readonly tier: number;
  readonly unsafeBelowTier3?: boolean;
  readonly processes: ProcessOperations | undefined;
  readonly root: string;
  readonly boxed: boolean;
  readonly manager: SubagentManager;
  readonly dispatcher: () => HarnessDispatcher;
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  readonly events: () => readonly SessionEvent[];
  readonly notify: (text: string, origin: Exclude<Origin, 'user' | 'human-selected'>) => void;
  readonly home: string;
  readonly projectRoot: string;
  readonly files: SafeFiles | null;
  readonly trust: TrustStore;
  readonly approve?: InstructionApprover;
  readonly workspaces?: WorkspaceHooks;
  readonly limits?: WorkflowLimits;
}

/** Saved workflows by name: the user's own load as they are; a project's only after a person approved its exact bytes. */
function savedLoader(setup: WorkflowSetup): SavedWorkflowLoader {
  return async (name) => {
    if (!NAME.test(name)) return { refused: 'A workflow name is lowercase letters, digits and hyphens.' };
    const mine = await readFile(join(setup.home, 'workflows', `${name}.js`), 'utf8').catch(() => null);
    if (mine !== null) return { script: mine };
    if (setup.files === null) return null;
    const path = join(setup.projectRoot, '.hn', 'workflows', `${name}.js`);
    const bytes = await setup.files.read(setup.projectRoot, path, 64 * 1024).catch(() => null);
    if (bytes === null) return null;
    const check = setup.trust.check(path, bytes);
    if (check.state !== 'trusted') {
      const file = { path, display: `.hn/workflows/${name}.js`, state: check.state, diff: check.diff ?? null, content: bytes };
      if (setup.approve === undefined || !(await setup.approve(file))) return { refused: `The project workflow ${name} is not approved, so it does not run.` };
      await setup.trust.approve(path, bytes);
    }
    return { script: bytes.toString('utf8') };
  };
}

/**
 * `workflow` and `run_code` for a root session. A script's agents are children on their own lease pool (never null
 * for lack of capacity); its tools go through this session's own dispatcher, so `call_tool` is unwrapped before the
 * gate sees the call, and every call is checked and logged as if the model had made it.
 */
export function createWorkflows(setup: WorkflowSetup): ToolDefinition[] {
  if (setup.processes === undefined) return [];
  const limits = setup.limits ?? defaultLimits();
  const pool = new LeasePool(limits.concurrency);
  let writers: Promise<unknown> = Promise.resolve();
  /** Writers without private clones run one at a time in the shared checkout; landings are in order either way. */
  const serially = <T>(work: () => Promise<T>): Promise<T> => {
    const next = writers.then(work, work);
    writers = next.catch(() => undefined);
    return next;
  };
  const handlers: WorkflowHandlers = {
    agent: async ({ prompt, opts }, signal) => {
      const release = await pool.acquire(signal);
      try {
        const task = { agent: typeof opts['agent'] === 'string' ? opts['agent'] : 'scout', task: prompt };
        const writes = setup.manager.plan(task, { start: 'spawn' }).mode !== 'read-only';
        let result;
        if (writes && setup.workspaces !== undefined && (await setup.workspaces.check()) === null) {
          const childId = randomUUID();
          const workdir = await setup.workspaces.create(childId);
          result = await setup.manager.leased(task, { start: 'spawn', workdir }, signal, childId);
          const landing = await serially(() => setup.workspaces!.land(childId, `workflow agent: ${prompt.slice(0, 200)}`));
          if (!landing.ok) return { value: null, origin: 'child', child: childId };
        } else if (writes) {
          result = await serially(() => setup.manager.leased(task, { start: 'spawn' }, signal));
        } else {
          result = await setup.manager.leased(task, { start: 'spawn' }, signal);
        }
        const value = result.ok && result.report !== null ? shapeAnswer(result.report.text, opts['schema']) : null;
        return { value, origin: 'child', child: result.childId };
      } finally {
        release();
      }
    },
    tool: async ({ key, name, args }, signal) => {
      const dispatcher = setup.dispatcher();
      const id = `wf-${key}`;
      const checked = dispatcher.check({ id, name, args });
      if (checked.kind !== 'ok') return { value: { ok: false, content: checked.message }, origin: 'harness' };
      if (NOT_FROM_A_SCRIPT.has(checked.name)) return { value: { ok: false, content: `${checked.name} cannot be called from a workflow or run_code.` }, origin: 'harness' };
      const outcome = await dispatcher.run({ id, name: checked.name, args: checked.args }, signal);
      return { value: { ok: !outcome.isError, content: outcome.content }, origin: outcome.origin };
    },
  };
  return createWorkflowTools({
    tier: setup.tier,
    ...(setup.unsafeBelowTier3 === true ? { unsafeBelowTier3: true } : {}),
    launch: processLauncher({ processes: setup.processes, cwd: setup.root, where: setup.boxed ? 'box' : 'local' }),
    handlers,
    record: setup.record,
    events: setup.events,
    limits,
    saved: savedLoader(setup),
    notify: setup.notify,
  });
}
