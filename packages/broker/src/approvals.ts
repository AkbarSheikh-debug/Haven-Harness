import { randomBytes } from 'node:crypto';
import type { Identity } from '@hn/security';
import { readJson, refusal, sendJson } from './http.ts';
import type { BrokerContext, Route } from './server.ts';
import type { Authenticated } from './tokens.ts';

/**
 * Approvals decided on the broker. An action that needs one (a push to a protected ref) becomes a
 * request bound to the requester and the exact action text, commit included. Who may decide it is read from the
 * requester's own policy, so a person cannot pick a looser approver; with `separate`, the requester cannot decide
 * their own. An approval is good for one use within an hour. Every request and decision is an audit row.
 */

interface Request {
  readonly id: string;
  readonly requester: Identity;
  readonly action: string;
  readonly created: number;
  state: 'pending' | 'approved' | 'denied' | 'used';
  decidedBy: string | null;
}

const TTL = 3600_000;

export interface Approvals {
  readonly routes: readonly Route[];
  /** For an action that needs an approval: null once one is approved (and consumed), otherwise why not yet. */
  hook(context: BrokerContext, who: Authenticated, action: string): Promise<string | null>;
}

export function brokerApprovals(): Approvals {
  const requests = new Map<string, Request>();
  const live = (now: number): Request[] => [...requests.values()].filter((request) => now - request.created < TTL);

  /** Why this person may not decide this request, or null. */
  function cannotDecide(context: BrokerContext, approver: Identity, request: Request): string | null {
    const policy = context.policyFor(request.requester);
    if (!policy.mayApprove(approver)) return `${approver.user} is not an approver for ${request.requester.user}'s requests.`;
    if (policy.separateApprover() && approver.user === request.requester.user) return 'The person who asked cannot approve their own request.';
    return null;
  }

  return {
    async hook(context, who, action) {
      const now = context.now();
      const same = live(now).filter((request) => request.requester.user === who.identity.user && request.action === action);
      const approved = same.find((request) => request.state === 'approved');
      if (approved !== undefined) {
        approved.state = 'used';
        context.audit('broker/approval-used', { id: approved.id, user: who.identity.user, action, decidedBy: approved.decidedBy });
        return null;
      }
      const denied = same.find((request) => request.state === 'denied');
      if (denied !== undefined) return `This was refused by ${denied.decidedBy ?? 'an approver'} (request ${denied.id}).`;
      const pending = same.find((request) => request.state === 'pending') ?? { id: randomBytes(6).toString('hex'), requester: who.identity, action, created: now, state: 'pending' as const, decidedBy: null };
      if (!requests.has(pending.id)) {
        requests.set(pending.id, pending);
        context.audit('broker/approval-requested', { id: pending.id, user: who.identity.user, action });
      }
      return `This needs an approval. Request ${pending.id} is waiting; an approver can decide it with: hn approvals approve ${pending.id}`;
    },
    routes: [
      {
        method: 'GET',
        path: '/v1/approvals',
        async handle(context, request, response) {
          const who = context.auth(request, response, 'session');
          if (who === null) return;
          const mine = live(context.now()).filter((item) => item.state === 'pending' && cannotDecide(context, who.identity, item) === null);
          sendJson(response, 200, { requests: mine.map((item) => ({ id: item.id, requester: item.requester.user, action: item.action, created: item.created })) });
        },
      },
      {
        method: 'POST',
        path: '/v1/approvals/decide',
        async handle(context, request, response) {
          const who = context.auth(request, response, 'session');
          if (who === null) return;
          const body = (await readJson(request, 4096)) as Record<string, unknown> | null;
          const id = body?.['id'];
          const decision = body?.['decision'];
          if (typeof id !== 'string' || (decision !== 'approve' && decision !== 'deny')) return refusal(response, 400, 'Expected {id, decision: approve | deny}.');
          const found = requests.get(id);
          if (found === undefined || context.now() - found.created >= TTL) return refusal(response, 404, 'No such request, or it expired.');
          if (found.state !== 'pending') return refusal(response, 409, `This request was already ${found.state}.`);
          const why = cannotDecide(context, who.identity, found);
          if (why !== null) {
            context.audit('broker/approval-refused', { id, approver: who.identity.user, reason: why });
            return refusal(response, 403, why);
          }
          found.state = decision === 'approve' ? 'approved' : 'denied';
          found.decidedBy = who.identity.user;
          context.audit('broker/approval-decided', { id, approver: who.identity.user, requester: found.requester.user, action: found.action, decision });
          sendJson(response, 200, { id, state: found.state });
        },
      },
    ],
  };
}
