import type { Budget, BudgetOverrides, GuardState } from '@hn/context';
import type { EventType, Origin, SessionEvent } from '@hn/core';
import type { Effort, ImageData, ModelCaps, ModelProvider, StreamEvent, ToolSpec, Usage } from '@hn/provider';
import type { RetryOptions } from '@hn/provider';
import type { Redactor } from '@hn/security';
import type { InstructionHooks } from './turn-instructions.ts';
import type { MemoryHooks } from './turn-memory.ts';
import { Guardrails } from './guardrails.ts';

export interface ToolCallRequest {
  readonly id: string;
  readonly name: string;
  readonly args: unknown;
}

export interface ToolOutcome {
  readonly content: string;
  readonly isError: boolean;
  readonly origin: Origin;
  /** Set when the tool stopped because the user cancelled. */
  readonly cancelled?: boolean;
  /** Pictures for the model. Kept only when the model can see them. */
  readonly images?: readonly ImageData[];
  /** Log-only records the tool asks for, appended right after its result. */
  readonly records?: readonly {
    readonly type: 'todo/write' | 'goal/change' | 'mode/change' | 'memory/write' | 'memory/search';
    readonly data: Readonly<Record<string, unknown>>;
  }[];
}

export type CallCheck =
  | { readonly kind: 'ok'; readonly name: string; readonly args: unknown }
  | { readonly kind: 'unknown'; readonly message: string }
  | { readonly kind: 'invalid'; readonly message: string };

/** The only door to a tool. `run` passes the gate and never throws. */
export interface ToolDispatcher {
  readonly specs: readonly ToolSpec[];
  check(call: ToolCallRequest): CallCheck;
  isConcurrencySafe(name: string, args: unknown): boolean;
  /** Paths a call touches, used to stop a writer overlapping anything else. */
  touches(name: string, args: unknown): { readonly reads: readonly string[]; readonly writes: readonly string[] };
  run(call: ToolCallRequest, signal: AbortSignal): Promise<ToolOutcome>;
  /** Resets the per-step output budget. */
  beginStep?(): void;
}

/** The session log plus the same events in memory. There is no second copy of the conversation. */
export interface LiveLog {
  readonly events: SessionEvent[];
  append(type: EventType, data: Record<string, unknown>, origin?: Origin): SessionEvent;
  flush(): Promise<void>;
}

/** One place a summary can come from, tried in order. */
export interface SummaryRoute {
  readonly source: 'summary' | 'fallback' | 'main';
  readonly provider: ModelProvider;
  readonly model: string;
  /** The summary model's own window, so a replay that would not fit takes the flat shape. */
  readonly window: number;
}

export interface CompactionConfig {
  /** Default: the main model only. The static summary always follows the last route. */
  readonly routes?: readonly SummaryRoute[];
  readonly redactor?: Redactor;
  readonly overrides?: BudgetOverrides;
  /** Per summary call. Default 120 s. */
  readonly timeoutMs?: number;
  /** Micro-compaction after each turn. Off by default, because each pass costs a cache miss. */
  readonly micro?: boolean;
  /** Fold one exchange every N turns. Default 1. */
  readonly microEveryNTurns?: number;
}

/** What a set of hooks said: a reason when one blocked, and anything they want the model to read. */
export interface HookOutcome {
  readonly blocked: string | null;
  readonly messages: readonly { readonly text: string; readonly origin: Origin }[];
}

/** The points where user-configured hooks run. Each returns at once with nothing to say when no hook matches. */
export interface LoopHooks {
  sessionStart(signal: AbortSignal): Promise<HookOutcome>;
  userPrompt(text: string, signal: AbortSignal): Promise<HookOutcome>;
  preTool(call: ToolCallRequest, signal: AbortSignal): Promise<HookOutcome>;
  postTool(call: ToolCallRequest, outcome: ToolOutcome, signal: AbortSignal): Promise<HookOutcome>;
  preVerify(signal: AbortSignal): Promise<HookOutcome>;
  stop(text: string, signal: AbortSignal): Promise<HookOutcome>;
}

/** What a stop gate says about a final answer: let it through (with a note for the user), or send the model back. */
export type StopGateVerdict =
  | { readonly kind: 'accept'; readonly note?: string }
  | { readonly kind: 'retry'; readonly text: string; readonly origin: Origin };

/**
 * Checks that run before a final answer goes to the user, such as verify-on-stop. It hears about every tool
 * round, so it can tell a turn that changed something from one that only answered.
 */
export interface StopGate {
  noteRound(toolNames: readonly string[]): void;
  check(signal: AbortSignal): Promise<StopGateVerdict>;
}

/** Compaction state that outlives a turn: the budget, fixed at open, and the guards. */
export interface CompactionHolder {
  readonly budget: Budget;
  guards: GuardState;
  /**
   * Provider count over our estimate at the newest anchor, never below 1. Every estimate made without
   * an anchor (right after a fold) is scaled by it, so a provider that counts more than we do cannot
   * push a request past the window.
   */
  calibration: number;
}

export interface LoopConfig {
  readonly provider: ModelProvider;
  readonly caps: ModelCaps;
  readonly tools: ToolDispatcher;
  readonly model: string;
  readonly system: string;
  readonly maxOutputTokens: number;
  readonly effort?: Effort;
  readonly maxIterations: number;
  readonly maxParallelToolCalls: number;
  readonly wallClockBudgetMs?: number;
  /**
   * Tokens this session may spend over its whole life, counted from the `assistant/attempt` rows in its log, so a
   * resume does not reset it. A child gets one from its grant. Over it, the turn ends as `budget`.
   */
  readonly tokenBudget?: number;
  /**
   * `fresh` counts only tokens that were not cache reads, as fleet jobs do (section 4): otherwise a 600k budget is
   * about six laps at 100k of mostly cached context. Default `all`.
   */
  readonly tokenBudgetCounts?: 'all' | 'fresh';
  readonly retry?: Pick<RetryOptions, 'sleep' | 'random' | 'maxAttempts'>;
  readonly onEvent?: (event: StreamEvent) => void;
  readonly now?: () => number;
  readonly compaction?: CompactionConfig;
  /** The instruction chain: a snapshot at start and after folds, deltas after file tools. */
  readonly instructions?: InstructionHooks;
  /** Memory: a frozen snapshot after the instructions, recall per user turn, a flush before folds. */
  readonly memory?: MemoryHooks;
  /**
   * Runs after every tool round with the names of the tools that ran, such as a skill's `validate:` check.
   * What it returns is appended as messages before the step ends.
   */
  readonly stopGate?: StopGate;
  readonly hooks?: LoopHooks;
  readonly afterToolRound?: (
    toolNames: readonly string[],
    signal: AbortSignal,
  ) => Promise<readonly { readonly text: string; readonly origin: Origin }[]>;
}

export type TurnEnd =
  | 'done'
  | 'cancelled'
  | 'budget'
  | 'window_full'
  | 'refusal'
  | 'guardrail'
  | 'invalid_calls'
  | 'failed';

export interface TurnResult {
  readonly text: string;
  readonly end: TurnEnd;
  readonly detail?: string;
  readonly usage: Usage;
  readonly steps: number;
}

/** What a phase tells the loop to do next. */
export type Action = 'next_phase' | 'next_iteration' | 'end_turn';

export class TurnState {
  readonly turnId: string;
  readonly startedAt: number;
  readonly guard = new Guardrails();
  apiCalls = 0;
  outerErrors = 0;
  unknownStrikes = 0;
  invalidStrikes = 0;
  nudged = false;
  emptyRetries = 0;
  continuations = 0;
  warnedWallClock = false;
  graceCall = false;
  text = '';
  end: TurnEnd = 'done';
  detail: string | undefined;
  stepId = '';
  partialText = '';
  usage: Usage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
  lastContext = 0;
  /** One maximal fold and one retry when the provider says the context is too long. */
  overflowRetried = false;
  /** Times a pre_verify or Stop hook sent the model back this turn. Capped, so a hook cannot trap a turn. */
  hookRetries = 0;

  constructor(turnId: string, startedAt: number) {
    this.turnId = turnId;
    this.startedAt = startedAt;
  }

  finish(end: TurnEnd, detail?: string): 'end_turn' {
    this.end = end;
    this.detail = detail;
    return 'end_turn';
  }
}

export interface TurnContext {
  readonly config: LoopConfig;
  readonly log: LiveLog;
  readonly state: TurnState;
  /** Fires on `/stop`. */
  readonly signal: AbortSignal;
  /** Fires on `/stop` or a correction, and ends only the current model call. */
  readonly callSignal: () => AbortSignal;
  readonly takeSteers: () => string[];
  /** Notices that arrived during the turn, such as a background child settling, each with its real origin. */
  readonly takeNotices: () => { readonly text: string; readonly origin: Origin }[];
  readonly takeRedirect: () => string | null;
  readonly compaction: CompactionHolder;
}
