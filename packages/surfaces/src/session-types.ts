import type { TeamLogin } from './team.ts';
import type { ImportPlan, } from '@hn/operations';
import type { StreamEvent } from '@hn/provider';
import type { Agent } from '@hn/loop';
import type { Approver, EgressPolicy, Gate, Guardian } from '@hn/security';
import type { HarnessExec, Answer, McpApprover, McpServer, McpServerConfig, Question, SearchBackend, ToolDefinition } from '@hn/tools';
import type { Origin } from '@hn/core';
import type { Team } from '@hn/orchestrate';
import type { RateGate, SubagentManager } from '@hn/delegate';
import type { InstructionAccess, InstructionApprover } from './instructions.ts';
import type { ReviewResult } from './review.ts';
import type { SessionCheckpoints } from './checkpointing.ts';
import type { FinishReport, SandboxOptions } from './sandbox.ts';
import type { Sandbox } from './native-sandbox.ts';

export interface CliOptions {
  readonly workdir: string;
  readonly mode: string;
  readonly model: string;
  readonly baseUrl?: string;
  /** Team mode: model calls and policy come from the broker this login names. */
  readonly team?: TeamLogin;
  readonly window?: number;
  readonly numCtx?: number;
  readonly allow?: readonly string[];
  readonly sessionId?: string;
  readonly approver?: Approver;
  readonly onEvent?: (event: StreamEvent) => void;
  readonly env?: NodeJS.ProcessEnv;
  /** Tests only, never a command-line flag: run without the native helper, which leaves files open to link races. */
  readonly unsafeNoHelper?: boolean;
  /** Run the tools in a verified box (a container, or the Windows native box), on a copy of the project. */
  readonly sandbox?: SandboxOptions;
  /** An operator's claim of an outer boundary. Capped at dont-ask, never counts for yolo. */
  readonly externalSandbox?: boolean;
  /** Reviews calls in `smart` mode. */
  readonly guardian?: Guardian;
  /** A search provider. Without one there is no `web_search` tool. */
  readonly search?: SearchBackend;
  /** MCP servers to use instead of `<home>/mcp.json`. Tests only. */
  readonly mcp?: readonly McpServerConfig[];
  /** A person's yes or no for a new or changed MCP server or tool. Without one only what is already approved is used. */
  readonly mcpApprover?: McpApprover;
  /** A person's yes or no for an instruction file nobody approved yet. Without one such files are not loaded. */
  readonly instructionApprover?: InstructionApprover;
  /** The mode `exit_plan_mode` leads into, fixed at launch. Default `safe`. */
  readonly afterPlan?: string;
  /** A person who answers `ask_user_question`. Without one the tool says nobody is here. */
  readonly asker?: (question: Question) => Promise<Answer | null>;
  /** The check verify-on-stop runs: a command, `off`, or unset to find the project's own. */
  readonly verify?: string;
  /** Set when this session is a child: the parent's id. Its log goes beside the parent's, and it cannot spawn. */
  readonly childOf?: string;
  /** A child of a tainted parent starts tainted. */
  readonly inheritTaint?: boolean;
  readonly maxIterations?: number;
  /** A child's grant: the role's prompt, added after the harness's own. Fixed for the session, so the prefix stays the same. */
  readonly rolePrompt?: string;
  /** A child's grant: only these tools exist in the session. */
  readonly tools?: readonly string[];
  /** A child's grant: tokens the session may spend over its life. */
  readonly tokenBudget?: number;
  /** `fresh`: the token budget leaves out cache reads, as fleet jobs count it. */
  readonly tokenBudgetCounts?: 'all' | 'fresh';
  /** A child's channel to its parent's shared rate limiter. Without one the session makes its own from HN_RATE_RPM and HN_RATE_TPM. */
  readonly rateGate?: RateGate;
  /** `/handoff`: this session starts from a note drafted in its parent, which it is linked to and whose taint it keeps. */
  readonly handoff?: { readonly parent: string; readonly draft: string; readonly origin: Exclude<Origin, 'user' | 'human-selected'> };
  /** Agent teams (experimental): the Lead's tools in a root session. */
  readonly teams?: boolean;
  /** A child's parent project key, from its grant: a child in a clone files its log beside its parent's. */
  readonly childProject?: string;
  /** Set in a team member: its roster name. */
  readonly teamMember?: string;
  /** A team member's tools, which talk to its Lead over the channel. */
  readonly memberTools?: readonly ToolDefinition[];
  /** A team member's inbox: lines the Lead pushes, delivered at the member's next step boundary. */
  readonly inbox?: (deliver: (text: string, origin: string) => void) => void;
  /** Tests only, never a flag: let `workflow` and `run_code` run below tier 3, outside any box. */
  readonly unsafeWorkflowsBelowTier3?: boolean;
  /** Recorded as a `session/link` row when the session opens, such as the session a `/rewind` forked from. */
  readonly linkedFrom?: Readonly<Record<string, unknown>>;
  /** Recorded as `subagent/descriptor` when a child session opens: who started it, as what, with which limits. */
  readonly descriptor?: Readonly<Record<string, unknown>>;
  /** Tests only, never a flag: the clock memory reads (notes, snapshot, dreams), so a simulated week can pass in one run. */
  readonly now?: () => Date;
}

export interface OpenSession {
  readonly agent: Agent;
  readonly sessionId: string;
  readonly gate: Gate;
  /** The sandbox tier this session runs at. Below 3 there is no boundary. */
  readonly tier: number;
  /** True when an operator claimed the boundary instead of it being verified. */
  readonly assertedTier: boolean;
  /** The folder the tools work in: the project itself, or the box's copy of it. */
  readonly root: string;
  readonly sandbox: Sandbox | null;
  /** Null only when the native helper is absent (tests). */
  readonly checkpoints: SessionCheckpoints | null;
  /** Doors tell it which URLs the user typed, because under the Rule of Two only those may be fetched unseen. */
  readonly egress: EgressPolicy;
  /** The family's shared rate limiter, for children to reach over their channels. */
  readonly rate: RateGate;
  readonly mcp: readonly McpServer[];
  /** Things the user should know before they start: tools that are off and why, servers that did not connect. */
  readonly notes: readonly string[];
  /** The instruction chain, so a door can ask about files that changed during the session. Null without the helper. */
  readonly instructions: InstructionAccess | null;
  /** Starts one child with a brief, as `spawn_agent` would, for doors that start a child themselves (/skill-test). */
  /** Background review of this session, or null where there is no memory (a child). The REPL runs it every 10 turns. */
  readonly review: (() => Promise<ReviewResult>) | null;
  readonly memoryPaths: import('@hn/memory').MemoryPaths | null;
  readonly dream: ((dryRun: boolean) => Promise<import('@hn/memory').DreamReport>) | null;
  /** Memory gates: false when the policy keeps /learn away from this person's sessions. */
  readonly learnAllowed?: boolean;
  runChild(brief: string, signal: AbortSignal): Promise<{ readonly content: string; readonly isError: boolean }>;
  /** `/handoff`: drafts `## Context` and `## Task` from this session with one tool-less call. */
  draftHandoff(signal: AbortSignal): Promise<{ readonly text: string; readonly by: 'model' | 'harness' }>;
  /** The worst origin this session has seen, which a handoff carries into the next session. */
  worst(): Origin;
  /** The session takes `origin` into its taint, as when a turn's prompt was written by a model or another process. */
  observe(origin: Origin): void;
  /** Runs a command the harness starts from project data (verify, a fleet's hidden check) as a gated call. */
  readonly exec: HarnessExec;
  /** A notice from outside the turn (a steer over the control channel, a member's message). It taints the session first. */
  notice(text: string, origin: Exclude<Origin, 'user' | 'human-selected'>): void;
  /** The agent team this session leads (`--teams`), or null. */
  readonly team: Team | null;
  /** Starts and tracks this session's children. Doors use it for presets; the model uses the `subagent` tool. */
  readonly subagents: SubagentManager;
  /** Ends the session. For a box this stops it and brings changes back, asking `approve` about each manifest file. */
  close(approve?: (plan: ImportPlan) => Promise<ReadonlyMap<string, string>>): Promise<FinishReport | null>;
}
