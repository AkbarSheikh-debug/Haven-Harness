import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { ApprovalAnswer, ApprovalCard, Effect } from '@hn/security';
import type { RateGate } from './rate-limit.ts';

/**
 * The private channel between a parent and one child: Node's IPC pipe, with every message carrying a
 * per-child token that only the two of them hold. The parent treats every message as hostile: a wrong token, an
 * unknown kind or a malformed field is dropped, and a request that cannot be answered is answered no.
 */

export function newChannelToken(): string {
  return randomBytes(24).toString('base64url');
}

const EFFECTS: readonly Effect[] = ['observe', 'reversible', 'execution', 'external', 'irreversible'];
const MAX_TEXT = 64 * 1024;

export type ChildRequest =
  | { readonly kind: 'approve'; readonly id: number; readonly card: ApprovalCard }
  | { readonly kind: 'rate-acquire'; readonly id: number; readonly tokens: number }
  | { readonly kind: 'rate-settle'; readonly estimated: number; readonly actual: number }
  | { readonly kind: 'rate-pause'; readonly ms: number }
  | { readonly kind: 'team'; readonly id: number; readonly request: Readonly<Record<string, unknown>> };

export type ParentReply =
  | { readonly t: string; readonly kind: 'answer'; readonly id: number; readonly answer: 'once' | 'deny' }
  | { readonly t: string; readonly kind: 'rate-ok'; readonly id: number; readonly ok: boolean }
  | { readonly t: string; readonly kind: 'team-reply'; readonly id: number; readonly ok: boolean; readonly value?: unknown; readonly error?: string };

function sameToken(given: unknown, token: string): boolean {
  if (typeof given !== 'string') return false;
  const a = Buffer.from(given);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

const text = (value: unknown, max = MAX_TEXT): value is string => typeof value === 'string' && value.length <= max;
const count = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value < 1e12;

function cardOf(value: unknown): ApprovalCard | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const card = value as Record<string, unknown>;
  if (!text(card['approvalId'], 200) || !text(card['tool'], 200) || !text(card['summary'])) return null;
  if (typeof card['effect'] !== 'string' || !(EFFECTS as readonly string[]).includes(card['effect'])) return null;
  if (card['target'] !== undefined && !text(card['target'], 4_096)) return null;
  const summary = card['summary'];
  return {
    approvalId: card['approvalId'],
    tool: card['tool'],
    effect: card['effect'] as Effect,
    summary,
    ...(card['target'] === undefined ? {} : { target: card['target'] as string }),
    byteCount: Buffer.byteLength(summary),
    // Whatever the child says, a relayed approval is never remembered (parent_session_grant_not_inherited).
    canRememberForSession: false,
  };
}

/** Parses one message from a child. Null means drop it: wrong token, unknown kind, or a field out of shape. */
export function parseChildMessage(raw: unknown, token: string): ChildRequest | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const message = raw as Record<string, unknown>;
  if (!sameToken(message['t'], token)) return null;
  const id = message['id'];
  const validId = Number.isSafeInteger(id) && (id as number) > 0;
  switch (message['kind']) {
    case 'approve': {
      const card = cardOf(message['card']);
      return card !== null && validId ? { kind: 'approve', id: id as number, card } : null;
    }
    case 'rate-acquire':
      return validId && count(message['tokens']) ? { kind: 'rate-acquire', id: id as number, tokens: message['tokens'] } : null;
    case 'rate-settle':
      return count(message['estimated']) && count(message['actual']) ? { kind: 'rate-settle', estimated: message['estimated'], actual: message['actual'] } : null;
    case 'rate-pause':
      return count(message['ms']) ? { kind: 'rate-pause', ms: message['ms'] } : null;
    case 'team': {
      const request = message['request'];
      const ok = validId && typeof request === 'object' && request !== null && !Array.isArray(request) && JSON.stringify(request).length <= MAX_TEXT;
      return ok ? { kind: 'team', id: id as number, request: request as Record<string, unknown> } : null;
    }
    default:
      return null;
  }
}

/** What the parent does with a child's requests. */
export interface ChildServerHandlers {
  /** Shows the card to the parent's person through the parent's gate. Rejects or throws mean no. */
  approve(card: ApprovalCard): Promise<'once' | 'deny'>;
  readonly rate?: RateGate;
  /** A team member's request to its Lead: the task graph or a message. Only a member's channel has it. */
  team?(request: Readonly<Record<string, unknown>>): Promise<unknown>;
  /** Told about every dropped message, so a forged one can be logged. */
  onDropped?(raw: unknown): void;
}

/** The parent's end: one handler per child message. Replies only ever say yes once, or no. */
export function serveChild(token: string, handlers: ChildServerHandlers): (raw: unknown, reply: (message: ParentReply) => void) => void {
  return (raw, reply) => {
    const request = parseChildMessage(raw, token);
    if (request === null) {
      handlers.onDropped?.(raw);
      return;
    }
    switch (request.kind) {
      case 'approve':
        void handlers
          .approve(request.card)
          .catch(() => 'deny' as const)
          .then((answer) => reply({ t: token, kind: 'answer', id: request.id, answer: answer === 'once' ? 'once' : 'deny' }));
        return;
      case 'rate-acquire':
        if (handlers.rate === undefined) {
          reply({ t: token, kind: 'rate-ok', id: request.id, ok: true });
          return;
        }
        void handlers.rate.acquire(request.tokens).then(
          () => reply({ t: token, kind: 'rate-ok', id: request.id, ok: true }),
          () => reply({ t: token, kind: 'rate-ok', id: request.id, ok: false }),
        );
        return;
      case 'rate-settle':
        handlers.rate?.settle(request.estimated, request.actual);
        return;
      case 'rate-pause':
        handlers.rate?.pause(request.ms);
        return;
      case 'team':
        if (handlers.team === undefined) {
          reply({ t: token, kind: 'team-reply', id: request.id, ok: false, error: 'This child is not a team member.' });
          return;
        }
        void handlers.team(request.request).then(
          (value) => reply({ t: token, kind: 'team-reply', id: request.id, ok: true, value }),
          (error: unknown) => reply({ t: token, kind: 'team-reply', id: request.id, ok: false, error: error instanceof Error ? error.message : String(error) }),
        );
        return;
    }
  };
}

/** How a child talks to its pipe: `process.send` and `process.on('message')` in a real child. */
export interface ChildPort {
  send(message: unknown): void;
  onMessage(listener: (message: unknown) => void): void;
  onClose(listener: () => void): void;
}

/**
 * The child's end. Approvals and rate-limit slots are asked of the parent; when the pipe is gone every pending and
 * later approval is a no, because a child must never decide for itself what its parent's person would say.
 */
export class ParentChannel {
  readonly #token: string;
  readonly #port: ChildPort;
  readonly #pending = new Map<number, (reply: Record<string, unknown> | null) => void>();
  readonly #inbox: ((text: string, origin: string) => void)[] = [];
  #next = 1;
  #closed = false;

  constructor(token: string, port: ChildPort) {
    this.#token = token;
    this.#port = port;
    port.onMessage((raw) => {
      if (typeof raw !== 'object' || raw === null) return;
      const reply = raw as Record<string, unknown>;
      if (!sameToken(reply['t'], token)) return;
      // A message the parent pushes: an inbox line for a team member, delivered at the next step boundary.
      if (reply['kind'] === 'inbox' && typeof reply['text'] === 'string' && typeof reply['origin'] === 'string') {
        for (const listener of this.#inbox) listener(reply['text'].slice(0, MAX_TEXT), reply['origin']);
        return;
      }
      if (!Number.isSafeInteger(reply['id'])) return;
      const resolve = this.#pending.get(reply['id'] as number);
      this.#pending.delete(reply['id'] as number);
      resolve?.(reply);
    });
    port.onClose(() => {
      this.#closed = true;
      for (const resolve of this.#pending.values()) resolve(null);
      this.#pending.clear();
    });
  }

  #request(message: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    if (this.#closed) return Promise.resolve(null);
    const id = this.#next++;
    return new Promise((resolve) => {
      this.#pending.set(id, resolve);
      try {
        this.#port.send({ ...message, t: this.#token, id });
      } catch {
        this.#pending.delete(id);
        resolve(null);
      }
    });
  }

  /** Inbox lines the parent pushes, for a team member. */
  onInbox(listener: (text: string, origin: string) => void): void {
    this.#inbox.push(listener);
  }

  /** A team member's request to its Lead. A closed pipe is an error, never a guess. */
  async team(request: Record<string, unknown>): Promise<unknown> {
    const reply = await this.#request({ kind: 'team', request });
    if (reply === null) throw new Error('The lead is gone.');
    if (reply['kind'] !== 'team-reply' || reply['ok'] !== true) throw new Error(String(reply['error'] ?? 'The lead refused.'));
    return reply['value'];
  }

  /** A message that needs no answer. A broken pipe is the same as a closed one. */
  #tell(message: Record<string, unknown>): void {
    if (this.#closed) return;
    try {
      this.#port.send({ ...message, t: this.#token });
    } catch {
      this.#closed = true;
    }
  }

  /** The child gate's approver: the parent's person decides, and anything but a plain yes is a no. */
  readonly approve = async (card: ApprovalCard): Promise<ApprovalAnswer> => {
    const reply = await this.#request({ kind: 'approve', card });
    return reply?.['kind'] === 'answer' && reply['answer'] === 'once' ? 'once' : 'deny';
  };

  /** The parent's shared bucket, asked over the pipe. With the pipe gone the child goes on unlimited rather than hang. */
  readonly rate: RateGate = {
    acquire: async (tokens) => {
      await this.#request({ kind: 'rate-acquire', tokens });
    },
    settle: (estimated, actual) => this.#tell({ kind: 'rate-settle', estimated, actual }),
    pause: (ms) => this.#tell({ kind: 'rate-pause', ms }),
  };
}
