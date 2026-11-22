import { readFile } from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { join } from 'node:path';
import { buildExport, type AuditEntry } from '@hn/security';
import { ROSTER_FILE } from './audit-checkpoints.ts';
import { HttpRefusal, header, refusal, sendJson } from './http.ts';
import type { BrokerAuditSink } from './audit-sink.ts';
import type { ApprovalRecord, RowFilter } from './audit-store.ts';
import type { Authenticated } from './tokens.ts';
import type { BrokerContext, Route } from './server.ts';

/**
 * The routes that read the broker's audit (Phase 14). Every one needs a LOGIN token, so a model-driven session (which
 * holds only a session token) cannot read the team's audit, and a person whose policy does not name them as a reader.
 * Every read is itself a row, so who looked is on the record. Filters are compared, never turned into patterns, and every
 * answer is capped.
 */

export const MAX_PAGE = 500;
export const MAX_EXPORT_ROWS = 50_000;
export const MAX_TAIL_SUBSCRIBERS = 8;
const MAX_PAGE_BYTES = 4 * 1024 * 1024;
const TYPE_PREFIX = /^[a-z0-9/_-]{1,64}$/;
const SESSION = /^[A-Za-z0-9_-]{1,100}$/;
const STATES = ['pending', 'approved', 'denied', 'used', 'refused'] as const;

export interface AuditReadOptions {
  readonly heartbeatMs?: number;
  /** A tail reader that is this far behind (bytes waiting to be sent) is dropped, not buffered further. */
  readonly tailBufferBytes?: number;
}

type Params = ReadonlyMap<string, string>;

/**
 * The root-signed audit roster the operator placed in the state folder (Phase 15), served as it is: the broker does not
 * judge it, the auditor checks it against the root they pinned. A missing or unreadable file is "no roster".
 */
async function auditRoster(state: string): Promise<unknown> {
  try {
    const text = await readFile(join(state, ROSTER_FILE), 'utf8');
    return text.length > 1024 * 1024 ? null : (JSON.parse(text) as unknown);
  } catch {
    return null;
  }
}

/** The query string, with only the names this route knows, each at most once and short. */
function params(request: IncomingMessage, allowed: readonly string[]): Params {
  const out = new Map<string, string>();
  const query = new URL(request.url ?? '/', 'http://broker').searchParams;
  for (const [name, value] of query) {
    if (!allowed.includes(name)) throw new HttpRefusal(400, `Unknown parameter "${name.slice(0, 40)}".`);
    if (out.has(name)) throw new HttpRefusal(400, `${name} was given twice.`);
    if (value.length > 200) throw new HttpRefusal(400, `${name} is too long.`);
    out.set(name, value);
  }
  return out;
}

function whole(value: string | undefined, name: string, min: number, max: number): number | undefined {
  if (value === undefined) return undefined;
  if (!/^\d{1,15}$/.test(value)) throw new HttpRefusal(400, `${name} must be a whole number.`);
  const number = Number(value);
  if (number < min || number > max) throw new HttpRefusal(400, `${name} must be from ${min} to ${max}.`);
  return number;
}

function when(value: string | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  const time = Date.parse(value);
  if (!/^\d{4}-\d{2}-\d{2}/.test(value) || Number.isNaN(time)) throw new HttpRefusal(400, `${name} must be a date and time like 2026-11-22T09:00:00Z.`);
  return time;
}

/** The row filter from a query: a user, a session, a type prefix and a time range. */
function filterOf(p: Params): RowFilter {
  const user = p.get('user');
  const session = p.get('session');
  const type = p.get('type');
  if (session !== undefined && !SESSION.test(session)) throw new HttpRefusal(400, 'session must be letters, digits, - and _.');
  if (type !== undefined && !TYPE_PREFIX.test(type)) throw new HttpRefusal(400, 'type must be a short prefix such as broker/model.');
  const since = when(p.get('since'), 'since');
  const until = when(p.get('until'), 'until');
  return { ...(user === undefined ? {} : { user }), ...(session === undefined ? {} : { session }), ...(type === undefined ? {} : { type }), ...(since === undefined ? {} : { since }), ...(until === undefined ? {} : { until }) };
}

const summary = (filter: RowFilter): Record<string, string | number> => Object.fromEntries(Object.entries(filter).map(([key, value]) => [key, value as string | number]));

export function auditReadRoutes(sink: BrokerAuditSink, options: AuditReadOptions = {}): Route[] {
  const { store } = sink;
  let subscribers = 0;

  /** The reader, or null after a refusal has been sent. */
  const reader = (context: BrokerContext, request: IncomingMessage, response: ServerResponse, what: string): Authenticated | null => {
    const who = context.auth(request, response, 'login');
    if (who === null) return null;
    if (!context.policyFor(who.identity).mayReadAudit(who.identity)) {
      context.audit('broker/audit-read-refused', { user: who.identity.user, what });
      refusal(response, 403, `${who.identity.user} is not named as a reader of the audit in the policy.`);
      return null;
    }
    return who;
  };

  const rows: Route = {
    method: 'GET',
    path: '/v1/audit/rows',
    async handle(context, request, response) {
      const who = reader(context, request, response, 'rows');
      if (who === null) return;
      const p = params(request, ['user', 'session', 'type', 'since', 'until', 'after', 'limit']);
      const filter = filterOf(p);
      const after = whole(p.get('after'), 'after', 0, Number.MAX_SAFE_INTEGER) ?? 0;
      const limit = whole(p.get('limit'), 'limit', 1, MAX_PAGE) ?? 100;
      await sink.settle();
      const matched = store.match(filter, after);
      const page = matched.slice(0, limit);
      let found: AuditEntry[] = await store.readMatched(page);
      let bytes = 0;
      const kept: AuditEntry[] = [];
      for (const row of found) {
        bytes += JSON.stringify(row).length;
        if (bytes > MAX_PAGE_BYTES && kept.length > 0) break;
        kept.push(row);
      }
      found = kept;
      const last = found[found.length - 1];
      const more = found.length < matched.length;
      context.audit('broker/audit-read', { user: who.identity.user, what: 'rows', filter: summary(filter), returned: found.length });
      sendJson(response, 200, { rows: found, next: more && last !== undefined ? last.n : null, head: store.head });
    },
  };

  const approvals: Route = {
    method: 'GET',
    path: '/v1/audit/approvals',
    async handle(context, request, response) {
      const who = reader(context, request, response, 'approvals');
      if (who === null) return;
      const p = params(request, ['user', 'state']);
      const state = p.get('state');
      if (state !== undefined && !(STATES as readonly string[]).includes(state)) throw new HttpRefusal(400, `state must be one of ${STATES.join(', ')}.`);
      const user = p.get('user');
      await sink.settle();
      const all = await store.approvals({ ...(user === undefined ? {} : { user }), ...(state === undefined ? {} : { state: state as ApprovalRecord['state'] | 'refused' }) });
      const list = all.slice(-MAX_PAGE);
      context.audit('broker/audit-read', { user: who.identity.user, what: 'approvals', filter: { ...(user === undefined ? {} : { user }), ...(state === undefined ? {} : { state }) }, returned: list.length });
      sendJson(response, 200, { approvals: list, truncated: list.length < all.length, head: store.head });
    },
  };

  const sessions: Route = {
    method: 'GET',
    path: '/v1/audit/sessions',
    async handle(context, request, response) {
      const who = reader(context, request, response, 'sessions');
      if (who === null) return;
      const p = params(request, ['user']);
      const user = p.get('user');
      await sink.settle();
      const anchored = new Map(sink.anchorList().map((item) => [`${item.user}\u0000${item.session}`, item]));
      const all = (await store.sessions(user)).slice(-MAX_PAGE).map((item) => ({ ...item, anchor: anchored.get(`${item.user}\u0000${item.session}`) === undefined ? null : { n: (anchored.get(`${item.user}\u0000${item.session}`) as { n: number }).n, mac: (anchored.get(`${item.user}\u0000${item.session}`) as { mac: string }).mac } }));
      context.audit('broker/audit-read', { user: who.identity.user, what: 'sessions', filter: user === undefined ? {} : { user }, returned: all.length });
      sendJson(response, 200, { sessions: all, head: store.head });
    },
  };

  const anchors: Route = {
    method: 'GET',
    path: '/v1/audit/anchors',
    async handle(context, request, response) {
      const who = reader(context, request, response, 'anchors');
      if (who === null) return;
      const p = params(request, ['user', 'session']);
      const user = p.get('user');
      const session = p.get('session');
      if (session !== undefined && !SESSION.test(session)) throw new HttpRefusal(400, 'session must be letters, digits, - and _.');
      const found = sink.anchorList().filter((item) => (user === undefined || item.user === user) && (session === undefined || item.session === session)).slice(0, MAX_PAGE);
      context.audit('broker/audit-read', { user: who.identity.user, what: 'anchors', filter: { ...(user === undefined ? {} : { user }), ...(session === undefined ? {} : { session }) }, returned: found.length });
      sendJson(response, 200, { anchors: found });
    },
  };

  const checkpoints: Route = {
    method: 'GET',
    path: '/v1/audit/checkpoints',
    async handle(context, request, response) {
      const who = reader(context, request, response, 'checkpoints');
      if (who === null) return;
      const p = params(request, ['after']);
      const after = whole(p.get('after'), 'after', 0, Number.MAX_SAFE_INTEGER) ?? 0;
      await sink.settle();
      // A fresh one at the head, so the auditor always has the broker's current word to keep.
      await sink.checkpoint();
      const list = sink.checkpoints.list().filter((item) => item.n > after).slice(-MAX_PAGE);
      context.audit('broker/audit-read', { user: who.identity.user, what: 'checkpoints', after, returned: list.length });
      sendJson(response, 200, { keyId: sink.checkpoints.keyId, publicKey: sink.checkpoints.publicPem, checkpoints: list, roster: await auditRoster(context.config.state) });
    },
  };

  const exportRoute: Route = {
    method: 'GET',
    path: '/v1/audit/export',
    async handle(context, request, response) {
      const who = reader(context, request, response, 'export');
      if (who === null) return;
      const p = params(request, ['from', 'to']);
      await sink.settle();
      const head = store.head;
      if (head.n === 0) return refusal(response, 404, 'The audit has no rows yet.');
      const to = whole(p.get('to'), 'to', 1, Number.MAX_SAFE_INTEGER) ?? head.n;
      const from = whole(p.get('from'), 'from', 1, Number.MAX_SAFE_INTEGER) ?? Math.max(1, to - MAX_EXPORT_ROWS + 1);
      if (from > to) return refusal(response, 400, 'from must not be after to.');
      if (to > head.n) return refusal(response, 416, `The audit has ${head.n} rows; to=${to} is past the end.`);
      if (to - from + 1 > MAX_EXPORT_ROWS) return refusal(response, 413, `An export holds at most ${MAX_EXPORT_ROWS} rows. Export it in ranges.`);
      // The broker signs the row at `to` now, so the export always ends at something it has said. In the era of a retired
      // key nothing new can be signed, so the range must end at a checkpoint that key already made.
      const boundary = Math.max(-1, ...sink.checkpoints.retired.map((item) => item.toRow));
      if (to <= boundary && !sink.checkpoints.list().some((item) => item.n === to && item.mac === store.macOf(to))) {
        const near = sink.checkpoints.list().filter((item) => item.n <= boundary).map((item) => item.n).sort((a, b) => Math.abs(a - to) - Math.abs(b - to)).slice(0, 4).sort((a, b) => a - b);
        return refusal(response, 409, `Rows up to ${boundary} were signed by a retired audit-signing key, which can no longer sign. End the export at a row it signed: ${near.join(', ')}.`);
      }
      const covering = await sink.checkpoints.sign({ n: to, mac: store.macOf(to) as string }, new Date(context.now()));
      const included = [...sink.checkpoints.list().filter((item) => item.n >= from - 1 && item.n <= to && item !== covering).slice(-1000), covering];
      const exported = buildExport(await store.read(from, to), included, who.identity.user, new Date(context.now()).toISOString(), await auditRoster(context.config.state));
      context.audit('broker/audit-read', { user: who.identity.user, what: 'export', from, to });
      sendJson(response, 200, exported);
    },
  };

  const tail: Route = {
    method: 'GET',
    path: '/v1/audit/tail',
    async handle(context, request, response) {
      const who = reader(context, request, response, 'tail');
      if (who === null) return;
      const p = params(request, ['from']);
      await sink.settle();
      const from = whole(p.get('from'), 'from', 0, Number.MAX_SAFE_INTEGER) ?? store.head.n;
      if (subscribers >= MAX_TAIL_SUBSCRIBERS) return refusal(response, 429, `${MAX_TAIL_SUBSCRIBERS} people are already following the audit.`);
      subscribers += 1;
      context.audit('broker/audit-read', { user: who.identity.user, what: 'tail', from });
      response.writeHead(200, { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      const limit = options.tailBufferBytes ?? 1024 * 1024;
      let next = from + 1;
      let busy = false;
      let closed = false;
      const finish = (last?: Record<string, unknown>): void => {
        if (closed) return;
        closed = true;
        stop();
        clearInterval(beat);
        subscribers -= 1;
        if (last !== undefined && !response.writableEnded) response.write(`${JSON.stringify(last)}\n`);
        response.end();
      };
      const pump = async (): Promise<void> => {
        if (busy || closed) return;
        busy = true;
        try {
          while (!closed && next <= store.head.n) {
            const upto = Math.min(store.head.n, next + 199);
            for (const row of await store.read(next, upto)) {
              if (closed) return;
              response.write(`${JSON.stringify({ type: 'row', row })}\n`);
              next = row.n + 1;
              if (response.writableLength > limit) return finish({ type: 'dropped', reason: 'You are reading more slowly than the audit is written. Resume from the last row you have.', next: next - 1 });
            }
          }
        } catch {
          finish({ type: 'closed', reason: 'The broker could not read the audit.' });
        } finally {
          busy = false;
        }
        if (!closed && next <= store.head.n) void pump();
      };
      const stop = sink.watch(() => void pump());
      const beat = setInterval(() => {
        // A login that was revoked or has expired, or a reader whose policy changed, ends the stream.
        const again = context.tokens.authenticate(header(request, 'authorization'), header(request, 'x-hn-session'), 'login');
        if (!again.ok || !context.policyFor(again.who.identity).mayReadAudit(again.who.identity)) return finish({ type: 'closed', reason: 'The login is no longer valid for reading the audit.' });
        response.write(`${JSON.stringify({ type: 'heartbeat', head: store.head.n })}\n`);
      }, options.heartbeatMs ?? 15_000);
      response.on('close', () => finish());
      await pump();
    },
  };

  return [rows, approvals, sessions, anchors, checkpoints, exportRoute, tail];
}
