/** The on-disk log format this build reads and writes. */
export const LOG_FORMAT_VERSION = 1;

/** Events the model can see. Everything else is log-only. */
export const SURFACE_EVENT_TYPES = [
  'user/message',
  'assistant/message',
  'system/message',
  'developer/message',
  'tool/result',
] as const;

export const LOG_ONLY_EVENT_TYPES = [
  'turn/start',
  'turn/end',
  'step/start',
  'step/end',
  'tool/call',
  'assistant/attempt',
  'request/header',
  'request/context',
  'llm/retry',
  'session/end-seed',
  'session/title',
  'model/selection',
  'agent/inbox/spliced',
  'working-directory/change',
  'workspace/changes',
  'mode/change',
  'todo/write',
  'goal/change',
  'schedule/change',
  'approval/asked',
  'approval/decided',
  'approval/policy',
  'hook/invoked',
  'hook/result',
  'command/run',
  'command/done',
  'compaction/start',
  'compaction/prune',
  'compaction/summary',
  'compaction/end',
  'image/offload',
  'subagent/catalog',
  'subagent/descriptor',
  'budget/charge',
  'session/link',
  'team/member',
  'team/task',
  'team/message',
  'team/merge',
  'workflow/run-start',
  'workflow/run-end',
  'workflow/agent-start',
  'workflow/agent-end',
  'workflow/phase',
  'workflow/log',
  'workflow/tool',
  'job/registered',
  'job/settled',
  'backend/change',
  'checkpoint/create',
  'sandbox/event',
  'taint/change',
  'memory/write',
  'memory/search',
  'dream/proposal',
  'dream/run',
  'dream/answer',
  'audit/decision',
  'event/received',
  'event/filtered',
  'event/routed',
  'thread/link',
  'spill/stored',
] as const;

export type SurfaceEventType = (typeof SURFACE_EVENT_TYPES)[number];
export type LogOnlyEventType = (typeof LOG_ONLY_EVENT_TYPES)[number];
export type EventType = SurfaceEventType | LogOnlyEventType;

export const ORIGINS = [
  'user',
  'human-selected',
  'harness',
  'workspace',
  'tool-output',
  'web',
  'mcp',
  'child',
  'event',
  'ipc',
  'hook',
  'memory',
  'model-derived',
] as const;

export type Origin = (typeof ORIGINS)[number];

export interface SessionEvent {
  readonly seq: number;
  readonly ts: string;
  readonly type: EventType;
  readonly origin: Origin;
  readonly data: Readonly<Record<string, unknown>>;
}

export interface ToolCall {
  readonly id: string;
  readonly name: string;
  readonly args: unknown;
}

const SURFACE_TYPES: ReadonlySet<string> = new Set(SURFACE_EVENT_TYPES);
const KNOWN_TYPES: ReadonlySet<string> = new Set([...SURFACE_EVENT_TYPES, ...LOG_ONLY_EVENT_TYPES]);
const KNOWN_ORIGINS: ReadonlySet<string> = new Set(ORIGINS);
const EVENT_KEYS: ReadonlySet<string> = new Set(['seq', 'ts', 'type', 'origin', 'data']);

export function isSurfaceEvent(event: SessionEvent): boolean {
  return SURFACE_TYPES.has(event.type);
}

/** Returns the event when `raw` is a well-formed event, otherwise `null`. */
export function parseEvent(raw: unknown): SessionEvent | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  if (Object.keys(record).some((key) => !EVENT_KEYS.has(key))) return null;
  const { seq, ts, type, origin, data } = record;
  if (!Number.isSafeInteger(seq) || (seq as number) < 1) return null;
  if (typeof ts !== 'string' || Number.isNaN(Date.parse(ts))) return null;
  if (typeof type !== 'string' || !KNOWN_TYPES.has(type)) return null;
  if (typeof origin !== 'string' || !KNOWN_ORIGINS.has(origin)) return null;
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return null;
  return {
    seq: seq as number,
    ts,
    type: type as EventType,
    origin: origin as Origin,
    data: data as Record<string, unknown>,
  };
}

/** The tool calls an `assistant/message` made. Malformed entries are ignored. */
export function toolCallsOf(event: SessionEvent): ToolCall[] {
  if (event.type !== 'assistant/message') return [];
  const calls = event.data['toolCalls'];
  if (!Array.isArray(calls)) return [];
  return calls.filter(
    (call): call is ToolCall =>
      typeof call === 'object' &&
      call !== null &&
      typeof (call as ToolCall).id === 'string' &&
      typeof (call as ToolCall).name === 'string',
  );
}
