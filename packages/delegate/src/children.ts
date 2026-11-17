import type { SessionEvent } from '@hn/core';
import type { Usage } from '@hn/provider';
import { DelegationRefused, type ChildInfo, type ChildStatus } from './manager-types.ts';
import { framedReport } from './report.ts';
import { formatSpend, type Spend } from './ledger.ts';

export const asUsage = (usage: Usage | null): Usage => usage ?? { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };

export function statusOf(end: string): ChildStatus {
  if (end === 'done') return 'done';
  if (end === 'cancelled') return 'cancelled';
  if (end === 'lost' || end === 'timeout') return 'lost';
  return 'failed';
}

/** The children a parent's log names, newest state last. Survives a resume, because it is a fold of the log. */
export function childrenOf(events: readonly SessionEvent[]): Map<string, ChildInfo> {
  const children = new Map<string, ChildInfo>();
  for (const event of events) {
    if (event.type !== 'subagent/catalog') continue;
    const id = event.data['child'];
    if (typeof id !== 'string') continue;
    const before = children.get(id);
    const kind = event.data['kind'];
    if (kind === 'spawned' || kind === 'message') {
      children.set(id, {
        id,
        role: String(event.data['role'] ?? before?.role ?? '?'),
        roleHash: String(event.data['roleHash'] ?? before?.roleHash ?? ''),
        status: 'running',
        end: null,
        brief: String(event.data['brief'] ?? before?.brief ?? ''),
      });
    } else if (kind === 'settled' && before !== undefined) {
      const end = String(event.data['end'] ?? 'lost');
      children.set(id, { ...before, status: statusOf(end), end });
    }
  }
  return children;
}

/** The text of a child's last finished turn, from its own log, or null when its last turn did not end well. */
export function finalAnswer(events: readonly SessionEvent[]): { text: string; end: string } | null {
  const turnEnd = events.findLast((event) => event.type === 'turn/end');
  if (turnEnd === undefined) return null;
  const answer = events.findLast((event) => event.type === 'assistant/message' && event.seq < turnEnd.seq);
  return { text: String(answer?.data['text'] ?? ''), end: String(turnEnd.data['reason'] ?? 'unknown') };
}


/**
 * Repair for a `subagent` call the parent never finished: before writing "outcome unknown",
 * read the child's log. What a finished child said comes back as its report; otherwise the result says exactly which
 * child did not finish and how to wake it.
 */
export async function repairFromChildLogs(callId: string, events: readonly SessionEvent[], childLog: ((childId: string) => Promise<readonly SessionEvent[] | null>) | undefined): Promise<{ content: string; isError: boolean; origin: 'child' | 'harness' } | null> {
  const ids = events.filter((event) => event.type === 'subagent/catalog' && event.data['callId'] === callId && (event.data['kind'] === 'spawned' || event.data['kind'] === 'message')).map((event) => ({ id: String(event.data['child']), role: String(event.data['role']) }));
  if (ids.length === 0) return null;
  const parts: string[] = [];
  let allDone = true;
  for (const { id, role } of ids) {
    const log = (await childLog?.(id).catch(() => null)) ?? null;
    const answer = log === null ? null : finalAnswer(log);
    if (answer !== null && answer.end === 'done') {
      parts.push(framedReport({ text: answer.text, end: 'done', sessionId: id, usage: null, steps: 0 }, role, `${id} (recovered from the child's own log)`));
    } else {
      allDone = false;
      parts.push(`Child ${id} (${role}) did not finish before this session stopped. Its log is kept; wake it with send_message to let it carry on.`);
    }
  }
  return { content: `This session stopped before the child's result came back. From the child's own log:\n${parts.join('\n\n')}`, isError: !allDone, origin: allDone ? 'child' : 'harness' };
}


/** One line per child, for `list_agents` and the REPL. */
export function describeChildren(children: readonly ChildInfo[], spend: ReadonlyMap<string, Spend>): string {
  if (children.length === 0) return 'This session has started no children.';
  return children
    .map((child) => {
      const cost = spend.get(child.id);
      return `${child.id} ${child.role} ${child.status}${child.end === null ? '' : ` (${child.end})`}${cost === undefined ? '' : `, ${formatSpend(cost)}`}: ${child.brief.slice(0, 120).replace(/\s+/g, ' ')}`;
    })
    .join('\n');
}

/** A child named by its full id or by a prefix of at least 8 characters that names only one. */
export function findChild(children: readonly ChildInfo[], reference: string): ChildInfo {
  const exact = children.find((child) => child.id === reference);
  if (exact !== undefined) return exact;
  const matches = reference.length >= 8 ? children.filter((child) => child.id.startsWith(reference)) : [];
  if (matches.length === 1) return matches[0]!;
  throw new DelegationRefused(matches.length > 1 ? `"${reference}" names more than one child; give more of its id.` : `There is no child "${reference}". list_agents shows them.`);
}
