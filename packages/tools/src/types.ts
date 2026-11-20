import type { Origin } from '@hn/core';
import type { ImageData } from '@hn/provider';
import type { Operations } from '@hn/operations';
import type { Effect, PathUse, ProposedChange, TaintTracker } from '@hn/security';
import type { JobManager } from './jobs.ts';

export type ToolArgs = Readonly<Record<string, unknown>>;

export interface ToolContext {
  readonly workdir: string;
  readonly ops: Operations;
  readonly signal: AbortSignal;
  readonly callId: string;
  /** Tracks where content came from, so text written while the session was tainted stays tainted when read back. */
  readonly taint?: TaintTracker;
  /** This session's jobs and terminals. Absent where the backend cannot keep a process alive. */
  readonly jobs?: JobManager;
}

/** A log-only record a tool asks the loop to append after its result, such as `todo/write`. */
export interface ToolRecord {
  readonly type: 'todo/write' | 'goal/change' | 'mode/change' | 'memory/write' | 'memory/search';
  readonly data: Readonly<Record<string, unknown>>;
}

export interface ToolResult {
  readonly content: string;
  readonly isError?: boolean;
  readonly origin?: Origin;
  readonly cancelled?: boolean;
  readonly records?: readonly ToolRecord[];
  /** Pictures for the model, such as `read_image`'s. The loop drops them for a model without vision. */
  readonly images?: readonly ImageData[];
}

export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly parameters: Readonly<Record<string, unknown>>;
  /** Deferred tools stay out of the prompt until `tool_search` finds them. */
  readonly deferred?: boolean;
  readonly effect: Effect;
  readonly concurrencySafe: boolean;
  paths(args: ToolArgs): readonly PathUse[];
  command?(args: ToolArgs): string;
  summary(args: ToolArgs): string;
  /** The real destination (a URL, a host), shown on the approval card apart from the model's own words. */
  target?(args: ToolArgs): string;
  /**
   * The file change this call would make, as text, for a door that can show a diff. Read-only: it may read the file and
   * must never write. A failure or null means no preview, and the summary stands alone.
   */
  preview?(args: ToolArgs, context: Pick<ToolContext, 'workdir' | 'ops'>): Promise<ProposedChange | null>;
  /** A reason to refuse this call outright, before the gate and before any person is asked; null to go on. */
  refuse?(args: ToolArgs): string | null;
  /** True when this call must be shown to a person in every mode, and refused when nobody is there. */
  requiresHuman?(args: ToolArgs): boolean;
  /** Where this tool's description came from, when it is not the harness. `tool_search` reports it, because a description is text from outside. */
  readonly origin?: Origin;
  execute(args: ToolArgs, context: ToolContext): Promise<ToolResult>;
}

export class ToolProblem extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

export function stringArg(args: ToolArgs, name: string): string {
  return args[name] as string;
}
