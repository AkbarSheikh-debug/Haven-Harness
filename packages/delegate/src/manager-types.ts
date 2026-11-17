import type { ModelCaps } from '@hn/provider';
import type { EventType, SessionEvent } from '@hn/core';
import type { Mode } from '@hn/security';
import type { ChildReport, ChildRun } from './report.ts';
import type { Role } from './roles.ts';

/** The limits on children. Every one is a cap, and a request past a cap is refused, never queued. */
export interface DelegationLimits {
  /** 1: a child cannot start children. 0 turns delegation off. */
  readonly maxDepth: number;
  /** Children running at once across the tree. The root uses no slot. */
  readonly maxActive: number;
  readonly maxParallelTasks: number;
  readonly maxConcurrency: number;
  readonly maxChainSteps: number;
  /** Tokens one child may spend, before the family cap cuts it further. */
  readonly childTokens: number;
  /** Tokens the root and all its children may spend together. */
  readonly familyTokens: number;
  /** Below this a child is not worth starting. */
  readonly minChildTokens: number;
  readonly timeoutMs: number;
}

export const DEFAULT_LIMITS: DelegationLimits = {
  maxDepth: 1,
  maxActive: 8,
  maxParallelTasks: 8,
  maxConcurrency: 4,
  maxChainSteps: 8,
  childTokens: 3_000_000,
  familyTokens: 30_000_000,
  minChildTokens: 20_000,
  timeoutMs: 15 * 60_000,
};

/** Steps per role: a scout answers one question, a worker carries out a plan. */
export const ITERATIONS: Readonly<Record<string, number>> = { scout: 40, planner: 40, reviewer: 40, worker: 150 };
export const DEFAULT_ITERATIONS = 60;
export const MAX_BRIEF_CHARS = 16_000;

/** Everything a launcher needs to start (or wake) one child process. */
export interface LaunchSpec {
  readonly childId: string;
  readonly role: Role;
  readonly model: string;
  readonly brief: string;
  readonly mode: Mode;
  readonly allow: readonly string[];
  readonly tools: readonly string[];
  readonly maxIterations: number;
  readonly tokenBudget: number;
  /** The child starts with the parent's taint, or with text from another child in its brief. */
  readonly tainted: boolean;
  /** Seed the child's log with the parent's finished turns before it starts. */
  readonly fork: boolean;
  /** Wake a child that already has a log: the same id, a new turn. */
  readonly resume: boolean;
  /** The folder the child works in. Null means the parent's own. */
  readonly workdir: string | null;
  /** A team member's name: its grant says so, and it gets the member tools. */
  readonly team?: string;
  readonly signal: AbortSignal;
}

export interface ResolvedModel {
  readonly model: string;
  readonly caps: ModelCaps;
}

/** Private clones for parallel writers. Without them, parallel children may only read. */
export interface WorkspaceHooks {
  /** Null when parallel writers can run here; otherwise why not. */
  check(): Promise<string | null>;
  /** A clone for one child; returns the folder it works in. */
  create(childId: string): Promise<string>;
  /** Brings the child's work back into the project, or reports a conflict. Removes the clone either way. */
  land(childId: string, summary: string): Promise<{ readonly ok: boolean; readonly text: string }>;
}

export interface ManagerOptions {
  readonly parentId: string;
  /** True inside a child: children cannot start children (maxDepth 1). */
  readonly nested: boolean;
  readonly roles: readonly Role[];
  readonly parentMode: () => Mode;
  readonly parentAllow: readonly string[];
  /** Tool names the parent's dispatcher has. */
  readonly parentTools: () => readonly string[];
  readonly tier: number;
  readonly resolveModel: (role: Role) => ResolvedModel;
  readonly launch: (spec: LaunchSpec) => Promise<ChildRun>;
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  /** The parent's log, for the ledger and the catalog. */
  readonly events: () => readonly SessionEvent[];
  /** The parent's current context size in tokens, so a fork that cannot fit the child's window is refused first. */
  readonly contextTokens: () => number;
  readonly tainted: () => boolean;
  readonly limits?: Partial<DelegationLimits>;
  readonly onStart?: (brief: string, signal: AbortSignal) => Promise<void>;
  readonly onStop?: (report: string, signal: AbortSignal) => Promise<void>;
  /** A background child settled: its report, framed as child data, for the parent's next step. */
  readonly notify?: (text: string) => void;
  /** A child's own log, verified, or null. Repair reads it before writing that an outcome is unknown. */
  readonly childLog?: (childId: string) => Promise<readonly SessionEvent[] | null>;
  readonly workspaces?: WorkspaceHooks;
}

export interface TaskRequest {
  readonly agent: string;
  readonly task: string;
}

export interface RunRequest {
  readonly start: 'spawn' | 'fork';
  readonly workdir?: string | null;
  /** The parent's tool call that started this, so repair can find the child after a crash. */
  readonly callId?: string;
  /** Start the child as this team member. */
  readonly team?: string;
}

/** One finished child, as the tool shows it. */
export interface ChildResult {
  readonly childId: string;
  readonly role: string;
  readonly ok: boolean;
  /** The framed report, or the honest account of a child that did not finish. */
  readonly content: string;
  readonly report: ChildReport | null;
  readonly cancelled: boolean;
}

export type ChildStatus = 'running' | 'done' | 'failed' | 'cancelled' | 'lost';

/** What the parent knows about one child, folded from its catalog rows. */
export interface ChildInfo {
  readonly id: string;
  readonly role: string;
  readonly roleHash: string;
  readonly status: ChildStatus;
  readonly end: string | null;
  readonly brief: string;
}

export class DelegationRefused extends Error {}

