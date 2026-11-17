import type { EventType, Origin } from '@hn/core';
import { join as joinOrigins } from '@hn/security';
import type { ToolArgs, ToolDefinition, ToolResult } from '@hn/tools';
import { nextOccurrence, occurrences, parseRRule } from './rrule.ts';
import { DEFAULT_CATCH_UP_MS, MAX_SCHEDULE_PROMPT, newScheduleId, type Schedule, type ScheduleStore } from './schedules.ts';

export interface ScheduleToolsOptions {
  readonly store: ScheduleStore;
  /** The project: a schedule runs here, and the tools see only this project's schedules. */
  readonly workdir: string;
  readonly sessionId: string;
  readonly tainted: () => boolean;
  /** The worst origin the session has seen; a schedule's prompt carries at least `model-derived`. */
  readonly worst: () => Origin;
  /**
   * Null when a person approves each card and so picks the allowlist; otherwise the most a schedule made here may allow,
   * so an unattended session can never schedule a run that does more than it may.
   */
  readonly allowCeiling: () => readonly string[] | null;
  /** The strict scan, for a prompt written in a tainted session. */
  readonly scan: (text: string) => Promise<string | null>;
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  /** How the run reaches a model: the creating session's own route. */
  readonly route?: { readonly model?: string; readonly baseUrl?: string; readonly window?: number };
  readonly now?: () => Date;
}

const harness = (content: string, isError = false): ToolResult => ({ content, isError, origin: 'harness' });
const list = (value: unknown): string[] | null => (Array.isArray(value) && value.every((item) => typeof item === 'string') ? (value as string[]) : null);

/** The card text: everything the run will do, in full, because nobody will be watching when it does. */
function describe(fields: { name: string; rrule: string; prompt: string; allow: readonly string[]; workdir: string; start: Date }, now: Date): string {
  const rule = parseRRule(fields.rrule);
  const next = typeof rule === 'string' ? [] : occurrences(rule, fields.start, new Date(now.getTime() - 1), new Date(now.getTime() + 400 * 24 * 60 * 60_000), 3);
  return [
    `schedule "${fields.name}": ${fields.rrule}`,
    `next runs: ${next.length === 0 ? 'none' : next.map((date) => date.toString()).join('; ')}`,
    `runs unattended in ${fields.workdir}, mode dont-ask, allowed without asking: ${fields.allow.length === 0 ? 'nothing (it can only read)' : fields.allow.join(', ')}`,
    'prompt:',
    fields.prompt,
  ].join('\n');
}

/**
 * `schedule_create`, `schedule_edit`, `schedule_list`, `schedule_view` and `schedule_delete` (deferred, root sessions only;
 * grants keep them from children). A schedule is persistence: from a tainted session, creating or changing one needs a
 * person in every mode and its prompt gets the strict scan (`tainted_schedule_requires_human`).
 */
export function createScheduleTools(options: ScheduleToolsOptions): ToolDefinition[] {
  const now = (): Date => options.now?.() ?? new Date();
  const mine = (schedule: Schedule): boolean => schedule.workdir === options.workdir;
  const ceilingProblem = (allow: readonly string[]): string | null => {
    const ceiling = options.allowCeiling();
    if (ceiling === null) return null;
    const extra = allow.filter((name) => !ceiling.includes(name));
    return extra.length === 0 ? null : `An unattended session cannot schedule a run that may do more than it may: ${extra.join(', ')} is not on this session's allowlist.`;
  };
  const fieldProblem = (args: ToolArgs, creating: boolean): string | null => {
    if (creating || args['name'] !== undefined) if (typeof args['name'] !== 'string' || !/^[\w .-]{1,64}$/.test(args['name'])) return 'name is 1 to 64 letters, digits, spaces, dots, dashes or underscores.';
    if (creating || args['rrule'] !== undefined) {
      const rule = typeof args['rrule'] === 'string' ? parseRRule(args['rrule']) : 'rrule is text such as FREQ=DAILY;BYHOUR=9;BYMINUTE=0.';
      if (typeof rule === 'string') return `rrule: ${rule}`;
    }
    if (creating || args['prompt'] !== undefined) if (typeof args['prompt'] !== 'string' || args['prompt'].trim() === '' || args['prompt'].length > MAX_SCHEDULE_PROMPT) return `prompt is 1 to ${MAX_SCHEDULE_PROMPT} characters.`;
    if (args['allow'] !== undefined) {
      const allow = list(args['allow']);
      if (allow === null) return 'allow is a list of tool names.';
      const problem = ceilingProblem(allow);
      if (problem !== null) return problem;
    }
    if (args['start'] !== undefined && (typeof args['start'] !== 'string' || Number.isNaN(Date.parse(args['start'])))) return 'start is an ISO time.';
    if (args['catchUpMinutes'] !== undefined && !(Number.isSafeInteger(args['catchUpMinutes']) && (args['catchUpMinutes'] as number) >= 0 && (args['catchUpMinutes'] as number) <= 10_080)) return 'catchUpMinutes is 0 to 10080.';
    return null;
  };
  const scanned = async (prompt: string | undefined): Promise<string | null> => {
    if (prompt === undefined || !options.tainted()) return null;
    const problem = await options.scan(prompt);
    return problem === null ? null : `The schedule's prompt was refused by the strict scan: ${problem}`;
  };
  const writtenBy = (): Origin => joinOrigins(options.worst(), 'model-derived');

  const create: ToolDefinition = {
    name: 'schedule_create',
    deferred: true,
    description: 'Schedule a prompt to run later, unattended, in this project: an RRULE (FREQ=MINUTELY|HOURLY|DAILY|WEEKLY with INTERVAL, BYDAY, BYHOUR, BYMINUTE, COUNT, UNTIL; local time), the prompt, and the tools it may use without asking (allow). It runs in dont-ask mode.',
    parameters: {
      type: 'object',
      properties: { name: { type: 'string' }, rrule: { type: 'string' }, prompt: { type: 'string' }, allow: { type: 'array', items: { type: 'string' } }, start: { type: 'string' }, catchUpMinutes: { type: 'integer' } },
      required: ['name', 'rrule', 'prompt'],
      additionalProperties: false,
    },
    effect: 'execution',
    concurrencySafe: false,
    paths: () => [],
    requiresHuman: () => options.tainted(),
    refuse: (args) => fieldProblem(args, true),
    summary: (args) => `create a ${describe({ name: String(args['name']), rrule: String(args['rrule']), prompt: String(args['prompt']), allow: list(args['allow']) ?? [], workdir: options.workdir, start: typeof args['start'] === 'string' ? new Date(args['start']) : now() }, now())}`,
    async execute(args): Promise<ToolResult> {
      const refused = await scanned(String(args['prompt']));
      if (refused !== null) return harness(refused, true);
      const at = now();
      const schedule: Schedule = {
        id: newScheduleId(),
        name: String(args['name']),
        rrule: String(args['rrule']).replace(/^RRULE:/i, ''),
        dtstart: (typeof args['start'] === 'string' ? new Date(args['start']) : at).toISOString(),
        prompt: String(args['prompt']),
        workdir: options.workdir,
        allow: list(args['allow']) ?? [],
        ...(options.route?.model === undefined ? {} : { model: options.route.model }),
        ...(options.route?.baseUrl === undefined ? {} : { baseUrl: options.route.baseUrl }),
        ...(options.route?.window === undefined ? {} : { window: options.route.window }),
        origin: writtenBy(),
        createdBy: options.sessionId,
        createdAt: at.toISOString(),
        enabled: true,
        catchUpMs: typeof args['catchUpMinutes'] === 'number' ? args['catchUpMinutes'] * 60_000 : DEFAULT_CATCH_UP_MS,
        lastRun: null,
      };
      await options.store.update((schedules) => ({ schedules: [...schedules, schedule], result: null }));
      options.record('schedule/change', { action: 'create', id: schedule.id, name: schedule.name, rrule: schedule.rrule, allow: schedule.allow, origin: schedule.origin });
      const rule = parseRRule(schedule.rrule);
      const next = typeof rule === 'string' ? null : nextOccurrence(rule, new Date(schedule.dtstart), new Date(at.getTime() - 1));
      return harness(`Created schedule ${schedule.id} (${schedule.name}). Next run: ${next === null ? 'none' : next.toString()}. It runs only when hn schedule run-due is called (the OS scheduler entry from hn schedule install).`);
    },
  };

  const edit: ToolDefinition = {
    name: 'schedule_edit',
    deferred: true,
    description: 'Change a schedule in this project: name, rrule, prompt, allow, enabled (false pauses it) or catchUpMinutes.',
    parameters: {
      type: 'object',
      properties: { id: { type: 'string' }, name: { type: 'string' }, rrule: { type: 'string' }, prompt: { type: 'string' }, allow: { type: 'array', items: { type: 'string' } }, enabled: { type: 'boolean' }, catchUpMinutes: { type: 'integer' } },
      required: ['id'],
      additionalProperties: false,
    },
    effect: 'execution',
    concurrencySafe: false,
    paths: () => [],
    requiresHuman: () => options.tainted(),
    refuse: (args) => (typeof args['id'] !== 'string' ? 'id names the schedule.' : fieldProblem(args, false)),
    summary: (args) => `change schedule ${String(args['id'])}:\n${Object.entries(args).filter(([key]) => key !== 'id').map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`).join('\n')}`,
    async execute(args): Promise<ToolResult> {
      const refused = await scanned(typeof args['prompt'] === 'string' ? args['prompt'] : undefined);
      if (refused !== null) return harness(refused, true);
      const changed = await options.store.update((schedules) => {
        const found = schedules.find((schedule) => schedule.id === args['id'] && mine(schedule));
        if (found === undefined) return { schedules, result: null };
        const next: Schedule = {
          ...found,
          ...(typeof args['name'] === 'string' ? { name: args['name'] } : {}),
          ...(typeof args['rrule'] === 'string' ? { rrule: args['rrule'].replace(/^RRULE:/i, ''), lastRun: null, dtstart: now().toISOString() } : {}),
          // A new prompt is this session's words: it carries this session's taint, however clean the old one was.
          ...(typeof args['prompt'] === 'string' ? { prompt: args['prompt'], origin: writtenBy() } : {}),
          ...(list(args['allow']) === null ? {} : { allow: list(args['allow']) as string[] }),
          ...(typeof args['enabled'] === 'boolean' ? { enabled: args['enabled'] } : {}),
          ...(typeof args['catchUpMinutes'] === 'number' ? { catchUpMs: args['catchUpMinutes'] * 60_000 } : {}),
        };
        return { schedules: schedules.map((schedule) => (schedule.id === found.id ? next : schedule)), result: next };
      });
      if (changed === null) return harness(`There is no schedule ${String(args['id'])} in this project.`, true);
      options.record('schedule/change', { action: 'edit', id: changed.id, fields: Object.keys(args).filter((key) => key !== 'id'), origin: changed.origin });
      return harness(`Changed schedule ${changed.id} (${changed.name}).`);
    },
  };

  const view = (schedule: Schedule): string => {
    const rule = parseRRule(schedule.rrule);
    const next = typeof rule === 'string' || !schedule.enabled ? null : nextOccurrence(rule, new Date(schedule.dtstart), schedule.lastRun === null ? now() : new Date(Math.max(Date.parse(schedule.lastRun), now().getTime())));
    return `${schedule.id} "${schedule.name}" ${schedule.rrule} ${schedule.enabled ? 'enabled' : 'paused'}; next ${next === null ? 'none' : next.toISOString()}; last ${schedule.lastRun ?? 'never'}; allow ${schedule.allow.join(',') || 'nothing'}; prompt written by ${schedule.origin}`;
  };

  const listTool: ToolDefinition = {
    name: 'schedule_list',
    deferred: true,
    description: 'List the schedules of this project with their next and last runs.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    effect: 'observe',
    concurrencySafe: true,
    paths: () => [],
    summary: () => 'list schedules',
    async execute(): Promise<ToolResult> {
      const { schedules } = await options.store.load();
      const here = schedules.filter(mine);
      return harness(here.length === 0 ? 'This project has no schedules.' : here.map(view).join('\n'));
    },
  };

  const viewTool: ToolDefinition = {
    name: 'schedule_view',
    deferred: true,
    description: 'Show one schedule of this project in full, prompt included.',
    parameters: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false },
    effect: 'observe',
    concurrencySafe: true,
    paths: () => [],
    summary: (args) => `view schedule ${String(args['id'])}`,
    async execute(args): Promise<ToolResult> {
      const found = (await options.store.load()).schedules.find((schedule) => schedule.id === args['id'] && mine(schedule));
      if (found === undefined) return harness(`There is no schedule ${String(args['id'])} in this project.`, true);
      // The prompt is shown as data: it may have been written in another, tainted session.
      return { content: `${view(found)}\n<schedule-prompt>\n${found.prompt}\n</schedule-prompt>`, isError: false, origin: found.origin === 'user' ? 'harness' : found.origin };
    },
  };

  const remove: ToolDefinition = {
    name: 'schedule_delete',
    deferred: true,
    description: 'Delete a schedule of this project.',
    parameters: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false },
    effect: 'reversible',
    concurrencySafe: false,
    paths: () => [],
    summary: (args) => `delete schedule ${String(args['id'])}`,
    async execute(args): Promise<ToolResult> {
      const removed = await options.store.update((schedules) => {
        const found = schedules.find((schedule) => schedule.id === args['id'] && mine(schedule));
        return { schedules: schedules.filter((schedule) => schedule !== found), result: found ?? null };
      });
      if (removed === null) return harness(`There is no schedule ${String(args['id'])} in this project.`, true);
      options.record('schedule/change', { action: 'delete', id: removed.id, name: removed.name });
      return harness(`Deleted schedule ${removed.id} (${removed.name}).`);
    },
  };

  return [create, edit, listTool, viewTool, remove];
}
