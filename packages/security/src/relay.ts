import { randomUUID } from 'node:crypto';
import { MAX_CARD_BYTES } from './approval.ts';
import type { ApprovalAnswer, ApprovalCard, Approver, Audit } from './gate.ts';

export interface RelayContext {
  readonly approver: Approver | undefined;
  readonly audit: Audit;
  /** The session is in a mode that never asks a person (dont-ask). */
  readonly neverAsks: boolean;
  /** The session's prompt limiter: false means prompting is paused. */
  readonly allowPrompt: () => boolean;
}

/**
 * Shows a child's card to this session's person, labelled with the child. The guardian never
 * decides it, a yes counts once, and with nobody here or in a mode that never asks, the answer is no. Every card is
 * an asked and decided pair in the audit chain, with the child it came from.
 */
export async function relayCard(context: RelayContext, card: ApprovalCard, from: string): Promise<'once' | 'deny'> {
  const { approver, audit } = context;
  const approvalId = randomUUID();
  const summary = `child ${from.replace(/[^A-Za-z0-9 ._:-]/g, '_').slice(0, 80)} asks:\n${card.summary}`;
  const byteCount = Buffer.byteLength(summary);
  const callId = `relay:${card.approvalId}`;
  audit('approval/asked', { approvalId, callId, tool: card.tool, summary, requiresHuman: true, relayedFrom: from });
  const refuse = (why: string): 'deny' => {
    audit('approval/decided', { approvalId, callId, answer: 'deny', by: 'harness', why, relayedFrom: from });
    return 'deny';
  };
  if (approver === undefined) return refuse('nobody is here');
  if (context.neverAsks) return refuse('this session never asks');
  if (byteCount > MAX_CARD_BYTES) return refuse('too large to review');
  if (!context.allowPrompt()) return refuse('prompting is paused');
  const shown: ApprovalCard = {
    approvalId,
    tool: card.tool,
    effect: card.effect,
    summary,
    ...(card.target === undefined ? {} : { target: card.target }),
    byteCount,
    canRememberForSession: false,
  };
  let answer: ApprovalAnswer;
  try {
    answer = await approver(shown);
  } catch {
    answer = 'deny';
  }
  const result = answer === 'deny' ? 'deny' : 'once';
  audit('approval/decided', { approvalId, callId, answer: result, by: 'human', relayedFrom: from });
  return result;
}
