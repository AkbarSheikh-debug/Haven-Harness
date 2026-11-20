import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { sanitizeForDisplay } from '@hn/core';
import type { KeyStore } from '@hn/provider';
import type { ApprovalAnswer, ApprovalCard } from '@hn/security';
import { Harness, type HarnessOptions } from './harness.ts';
import { Guard, listenLoopback, readBody, same } from './serve-guard.ts';
import { APP_CSS, APP_JS, APP_PAGE, LOGIN_PAGE, SECURITY_HEADERS, renderMarkdown } from './serve-render.ts';
import { handleReplay, isReplayPath } from './serve-replay.ts';

/**
 * `hn serve` (decision 12, section 8.8.11): one session in a browser, hardened as a local web door must be, and the
 * replay and audit screen for any recorded session. The hardening (loopback only, Host and Origin checks, a token
 * exchanged for an HttpOnly SameSite=Strict cookie, strict headers) is in `serve-guard.ts` and is the same for both.
 * - Every POST also needs the session's CSRF token in a header a cross-site form cannot set.
 * - Approvals come back only as "once" or "deny", from the cookie's holder, with the CSRF token.
 * - The replay screen is GET only and starts nothing. `startReplayServe` runs it alone, with no model session at all.
 */

export interface ServeOptions {
  readonly keys: KeyStore;
  readonly cwd: string;
  readonly defaults: Pick<HarnessOptions, 'model' | 'baseUrl' | 'window' | 'numCtx'>;
  readonly env?: NodeJS.ProcessEnv;
  readonly port?: number;
  /** Tests only: passed to the session. */
  readonly sessionExtras?: Partial<HarnessOptions>;
}

export interface Served {
  readonly url: string;
  readonly port: number;
  readonly token: string;
  readonly server: Server;
  close(): Promise<void>;
}

export interface ReplayServeOptions {
  readonly cwd: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly port?: number;
}

const APPROVAL_TIMEOUT_MS = 10 * 60_000;

export async function startServe(options: ServeOptions): Promise<Served> {
  const guard = new Guard();
  const streams = new Set<ServerResponse>();
  const pending = new Map<string, (answer: ApprovalAnswer) => void>();
  let busy = false;

  const send = (event: string, data: unknown): void => {
    for (const stream of streams) stream.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  const harness = new Harness({
    ...options.defaults,
    ...options.sessionExtras,
    workdir: options.cwd,
    mode: 'safe',
    keys: options.keys,
    ...(options.env === undefined ? {} : { env: options.env }),
    approver: (card: ApprovalCard) =>
      new Promise<ApprovalAnswer>((resolve) => {
        const timer = setTimeout(() => {
          pending.delete(card.approvalId);
          resolve('deny');
        }, APPROVAL_TIMEOUT_MS);
        pending.set(card.approvalId, (answer) => {
          clearTimeout(timer);
          pending.delete(card.approvalId);
          resolve(answer);
        });
        send('card', { approvalId: card.approvalId, tool: sanitizeForDisplay(card.tool), effect: card.effect, summary: sanitizeForDisplay(card.summary), ...(card.target === undefined ? {} : { target: sanitizeForDisplay(card.target) }) });
      }),
    onEvent: (event) => {
      if (event.type === 'text') send('text', { text: sanitizeForDisplay(event.text) });
    },
  });
  const session = await harness.open();

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const refused = guard.refuse(req);
    if (refused !== null) return guard.reply(res, refused[0], 'text/plain; charset=utf-8', refused[1]);
    const url = new URL(req.url ?? '/', `http://127.0.0.1:${guard.port}`);
    const path = url.pathname;
    if (req.method === 'GET' && path === '/app.css') return guard.reply(res, 200, 'text/css; charset=utf-8', APP_CSS);
    if (path === '/login') return guard.login(req, res, LOGIN_PAGE);
    if (!guard.loggedIn(req)) {
      if (req.method === 'GET' && path === '/') return guard.reply(res, 303, 'text/plain', '', { location: '/login' });
      return guard.reply(res, 401, 'text/plain; charset=utf-8', 'Log in first.');
    }
    if (isReplayPath(path)) return handleReplay({ cwd: options.cwd, ...(options.env === undefined ? {} : { env: options.env }), guard }, req, res, path);
    if (req.method === 'GET') {
      if (path === '/') return guard.reply(res, 200, 'text/html; charset=utf-8', APP_PAGE);
      if (path === '/app.js') return guard.reply(res, 200, 'text/javascript; charset=utf-8', APP_JS);
      if (path === '/session') return guard.reply(res, 200, 'application/json', JSON.stringify({ sessionId: session.sessionId, mode: session.gate.mode, tier: session.tier, csrf: guard.csrf }));
      if (path === '/events') {
        res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': 'text/event-stream', connection: 'keep-alive' });
        res.write(': connected\n\n');
        streams.add(res);
        req.on('close', () => streams.delete(res));
        return;
      }
      return guard.reply(res, 404, 'text/plain', 'Not found.');
    }
    if (req.method !== 'POST') return guard.reply(res, 405, 'text/plain', 'Method not allowed.');
    const header = req.headers['x-hn-csrf'];
    if (typeof header !== 'string' || !same(header, guard.csrf)) return guard.reply(res, 403, 'text/plain; charset=utf-8', 'The CSRF token is missing or wrong.');
    if ((req.headers['content-type'] ?? '').split(';')[0] !== 'application/json') return guard.reply(res, 415, 'text/plain', 'Send JSON.');
    const body = await readBody(req);
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body ?? '') as Record<string, unknown>;
    } catch {
      return guard.reply(res, 400, 'text/plain', 'That is not JSON.');
    }
    if (path === '/prompt') {
      if (typeof data['text'] !== 'string' || data['text'].trim() === '') return guard.reply(res, 400, 'text/plain', 'Send some text.');
      if (busy) return guard.reply(res, 409, 'text/plain', 'A turn is running.');
      busy = true;
      try {
        const result = await harness.run(data['text'], { origin: 'user' });
        return guard.reply(res, 200, 'application/json', JSON.stringify({ end: result.end, html: renderMarkdown(result.text) }));
      } finally {
        busy = false;
      }
    }
    if (path === '/approve') {
      const answer = pending.get(String(data['approvalId']));
      if (answer === undefined) return guard.reply(res, 404, 'text/plain', 'No such card is waiting.');
      answer(data['decision'] === 'once' ? 'once' : 'deny');
      return guard.reply(res, 200, 'application/json', '{}');
    }
    return guard.reply(res, 404, 'text/plain', 'Not found.');
  };

  const server = await listenLoopback(handle, guard, options.port ?? 0);
  return {
    url: `http://127.0.0.1:${guard.port}/`,
    port: guard.port,
    token: guard.token,
    server,
    close: async () => {
      for (const stream of streams) stream.end();
      for (const answer of pending.values()) answer('deny');
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await harness.close();
    },
  };
}

/**
 * The replay and audit screen on its own: the same server, the same login and the same checks, and no model session. It needs no
 * key, opens nothing that can act, and answers only GET. `/` goes to the replay page.
 */
export async function startReplayServe(options: ReplayServeOptions): Promise<Served> {
  const guard = new Guard();
  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const refused = guard.refuse(req);
    if (refused !== null) return guard.reply(res, refused[0], 'text/plain; charset=utf-8', refused[1]);
    const path = new URL(req.url ?? '/', `http://127.0.0.1:${guard.port}`).pathname;
    if (req.method === 'GET' && path === '/app.css') return guard.reply(res, 200, 'text/css; charset=utf-8', APP_CSS);
    if (path === '/login') return guard.login(req, res, REPLAY_LOGIN_PAGE);
    if (!guard.loggedIn(req)) {
      if (req.method === 'GET' && (path === '/' || path === '/replay')) return guard.reply(res, 303, 'text/plain', '', { location: '/login' });
      return guard.reply(res, 401, 'text/plain; charset=utf-8', 'Log in first.');
    }
    if (req.method === 'GET' && path === '/') return guard.reply(res, 303, 'text/plain', '', { location: '/replay' });
    if (isReplayPath(path)) return handleReplay({ cwd: options.cwd, ...(options.env === undefined ? {} : { env: options.env }), guard }, req, res, path);
    return guard.reply(res, req.method === 'GET' ? 404 : 405, 'text/plain; charset=utf-8', req.method === 'GET' ? 'Not found.' : 'This server only shows recorded sessions; it cannot be asked to do anything.');
  };
  const server = await listenLoopback(handle, guard, options.port ?? 0);
  return {
    url: `http://127.0.0.1:${guard.port}/`,
    port: guard.port,
    token: guard.token,
    server,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

const REPLAY_LOGIN_PAGE = LOGIN_PAGE.replace('<title>hn</title>', '<title>hn session replay</title>');
