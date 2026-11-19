import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Origin, SessionEvent } from '@hn/core';
import { Agent, type LoopConfig, type ToolCallRequest, type ToolDispatcher, type ToolOutcome } from '@hn/loop';
import { PROPOSAL_TTL_MS, appendProposal, newProposalId, writeMemory, type MemoryPaths } from '@hn/memory';
import type { Usage } from '@hn/provider';
import { isUntrusted } from '@hn/security';
import { forkSession, parseLog } from '@hn/session';
import { parseMemoryOps } from '@hn/tools';

/** Background review runs after every this many user turns (section 4). */
export const REVIEW_EVERY_TURNS = 10;
const REVIEW_MAX_ITERATIONS = 16;
const REVIEW_WALL_CLOCK_MS = 5 * 60_000;

export const REVIEW_PROMPT = [
  'Background review. This message comes from the harness, not from the user.',
  'Look back over this session and save what a future session on this project should know.',
  "Use the memory tool: target notes for working notes; target memory (the project) or user (the user) for a lasting fact, which becomes a proposal the user decides on later.",
  'Save facts, never orders. Do not call any other tool. If nothing is worth saving, answer "nothing".',
].join('\n');

export interface ReviewResult {
  readonly notes: number;
  readonly proposals: number;
  readonly usage: Usage;
  readonly steps: number;
  readonly end: string;
}

export interface ReviewerOptions {
  readonly parentPath: string;
  readonly childrenDir: string;
  readonly key: Buffer;
  readonly lockDir: string;
  /** The parent's loop config. The review sends the same system prompt and the same tool specs, so the cache still hits. */
  readonly config: LoopConfig;
  readonly paths: MemoryPaths;
  /** The parent's worst origin, which every note and proposal from the review keeps. */
  readonly worst: () => Origin;
  readonly redact?: (row: string) => string;
  readonly now?: () => Date;
}

/** The newest user rows, as evidence for a proposal: what the person was doing when the review saw it. */
function evidenceFrom(events: readonly SessionEvent[], sessionId: string): { session: string; seq: number; origin: Origin; quote: string }[] {
  return events
    .filter((event) => event.type === 'user/message' && event.origin === 'user')
    .slice(-3)
    .map((event) => ({ session: sessionId, seq: event.seq, origin: event.origin, quote: String(event.data['text']).slice(0, 640) }));
}

/**
 * A dispatcher that offers the parent's exact tool list but runs only `memory`, and only into notes or
 * proposals: the gate for a system principal that may write proposals and nothing else (section 4).
 */
function reviewDispatcher(options: ReviewerOptions, parentEvents: readonly SessionEvent[], parentId: string, counts: { notes: number; proposals: number }): ToolDispatcher {
  const now = options.now ?? (() => new Date());
  const refuse = (content: string): ToolOutcome => ({ content, isError: true, origin: 'harness' });
  return {
    specs: options.config.tools.specs,
    check: (call) => ({ kind: 'ok', name: call.name, args: call.args }),
    isConcurrencySafe: () => false,
    touches: () => ({ reads: [], writes: [] }),
    async run(call: ToolCallRequest): Promise<ToolOutcome> {
      if (call.name !== 'memory') return refuse('Background review can only use the memory tool, to save notes or propose lasting facts.');
      const args = (typeof call.args === 'object' && call.args !== null ? call.args : {}) as Record<string, unknown>;
      const ops = parseMemoryOps(args);
      if (typeof ops === 'string') return refuse(ops);
      const target = args['target'] ?? 'notes';
      const origin = options.worst();
      const taint = isUntrusted(origin) ? 'untrusted' : 'clean';
      if (target === 'notes') {
        const write = await writeMemory({ paths: options.paths, target: 'notes', ops, who: 'review', sourceSession: parentId, origin, taint, why: 'background review', approvedBy: null, now: now() });
        if (!write.result.ok) return refuse(write.result.reason);
        counts.notes += ops.length;
        return { content: `Saved to today's notes.`, isError: false, origin: 'harness' };
      }
      if (target !== 'memory' && target !== 'user') return refuse('target must be notes, memory or user.');
      if (ops.some((op) => op.op !== 'add')) return refuse('A review can only propose new entries; it cannot change or remove existing ones.');
      const created = now();
      for (const op of ops) {
        if (op.op !== 'add') continue;
        await appendProposal(options.paths, {
          v: 1, id: newProposalId(), kind: target, text: op.text.trim(), why: typeof args['why'] === 'string' ? args['why'].slice(0, 500) : 'noticed in background review',
          evidence: evidenceFrom(parentEvents, parentId), source: 'review', origin, created: created.toISOString(), expires: new Date(created.getTime() + PROPOSAL_TTL_MS).toISOString(), score: null,
        });
        counts.proposals += 1;
      }
      return { content: `Proposed for ${target === 'memory' ? 'MEMORY.md' : 'USER.md'}. The user decides at the start of a later session.`, isError: false, origin: 'harness' };
    },
  };
}

/**
 * Background review (section 4): a fork of the parent at its newest closed step, in its own log beside the
 * parent's, run for one harness-origin turn of at most 16 steps. The parent's log is read, never written.
 */
export function createReviewer(options: ReviewerOptions): () => Promise<ReviewResult> {
  return async () => {
    const source = parseLog(await readFile(options.parentPath), options.key);
    const parentId = options.parentPath.split(/[\\/]/).at(-1) ?? 'parent';
    const sessionId = `review-${randomUUID()}`;
    const path = join(options.childrenDir, sessionId);
    const writer = await forkSession({ source, path, sessionId, key: options.key });
    await writer.close();
    const counts = { notes: 0, proposals: 0 };
    const config: LoopConfig = {
      provider: options.config.provider,
      caps: options.config.caps,
      model: options.config.model,
      system: options.config.system,
      tools: reviewDispatcher(options, source.events, parentId, counts),
      maxOutputTokens: options.config.maxOutputTokens,
      ...(options.config.effort === undefined ? {} : { effort: options.config.effort }),
      maxIterations: REVIEW_MAX_ITERATIONS,
      maxParallelToolCalls: 4,
      wallClockBudgetMs: REVIEW_WALL_CLOCK_MS,
      ...(options.config.compaction === undefined ? {} : { compaction: options.config.compaction }),
    };
    const agent = await Agent.open({ config, path, sessionId, key: options.key, lockDir: options.lockDir, ...(options.redact === undefined ? {} : { redact: options.redact }) });
    try {
      const result = await agent.run(REVIEW_PROMPT, { origin: 'harness' });
      return { notes: counts.notes, proposals: counts.proposals, usage: result.usage, steps: result.steps, end: result.end };
    } finally {
      await agent.close();
    }
  };
}
