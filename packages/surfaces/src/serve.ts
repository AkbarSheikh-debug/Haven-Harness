import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { sanitizeForDisplay } from '@hn/core';
import type { KeyStore } from '@hn/provider';
import type { ApprovalAnswer, ApprovalCard } from '@hn/security';
import { Harness, type HarnessOptions } from './harness.ts';
import { APP_CSS, APP_JS, APP_PAGE, LOGIN_PAGE, SECURITY_HEADERS, renderMarkdown } from './serve-render.ts';

/**
 * `hn serve`: one session in a browser, hardened as a local web door must be.
 * - Loopback only; there is no option for anything else (remote use would need real authentication).
 * - Every request's Host must be exactly this server's loopback name and port, which stops DNS rebinding; every request
 *   that carries an Origin must be this server's own, and every POST must carry one.
 * - A random token, shown on the terminal, is typed into a login form and exchanged for an HttpOnly, SameSite=Strict
 *   cookie. The token is never accepted in a URL.
 * - Every POST also needs the session's CSRF token in a header a cross-site form cannot set.
 * - Approvals come back only as "once" or "deny", from the cookie's holder, with the CSRF token.
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

const MAX_BODY = 64 * 1024;
const APPROVAL_TIMEOUT_MS = 10 * 60_000;
const digest = (text: string): Buffer => createHash('sha256').update(text).digest();
const same = (a: string, b: string): boolean => timingSafeEqual(digest(a), digest(b));

function readBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        resolve(null);
        req.destroy();
      } else chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(null));
  });
}

export async function startServe(options: ServeOptions): Promise<Served> {
  const token = randomBytes(32).toString('hex');
  const cookieValue = randomBytes(32).toString('hex');
  const csrf = randomBytes(32).toString('hex');
  const streams = new Set<ServerResponse>();
  const pending = new Map<string, (answer: ApprovalAnswer) => void>();
  let port = 0;
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

  const allowedHosts = (): string[] => [`127.0.0.1:${port}`, `localhost:${port}`];
  const allowedOrigins = (): string[] => allowedHosts().map((host) => `http://${host}`);

  /** Why a request is refused before anything else looks at it, or null. */
  const refuse = (req: IncomingMessage): [number, string] | null => {
    const host = req.headers.host ?? '';
    if (!allowedHosts().includes(host)) return [421, 'This server answers only to its own loopback address.'];
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigins().includes(origin)) return [403, 'Requests from another site are refused.'];
    if (req.method === 'POST' && origin === undefined) return [403, 'A request that changes something must say where it came from.'];
    return null;
  };

  const loggedIn = (req: IncomingMessage): boolean => {
    const found = /(?:^|;\s*)hn_session=([0-9a-f]{64})/.exec(req.headers.cookie ?? '');
    return found !== null && same(found[1] as string, cookieValue);
  };

  const reply = (res: ServerResponse, status: number, type: string, body: string, extra: Record<string, string> = {}): void => {
    res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': type, ...extra }).end(body);
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const refused = refuse(req);
    if (refused !== null) return reply(res, refused[0], 'text/plain; charset=utf-8', refused[1]);
    const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
    const path = url.pathname;
    if (req.method === 'GET' && path === '/app.css') return reply(res, 200, 'text/css; charset=utf-8', APP_CSS);
    if (path === '/login') {
      if (req.method === 'GET') return reply(res, 200, 'text/html; charset=utf-8', LOGIN_PAGE);
      if (req.method !== 'POST') return reply(res, 405, 'text/plain', 'Method not allowed.');
      const body = (await readBody(req)) ?? '';
      const given = new URLSearchParams(body).get('token') ?? '';
      if (!same(given, token)) return reply(res, 401, 'text/plain; charset=utf-8', 'That is not the token hn printed.');
      return reply(res, 303, 'text/plain', '', { location: '/', 'set-cookie': `hn_session=${cookieValue}; HttpOnly; SameSite=Strict; Path=/` });
    }
    if (!loggedIn(req)) {
      if (req.method === 'GET' && path === '/') return reply(res, 303, 'text/plain', '', { location: '/login' });
      return reply(res, 401, 'text/plain; charset=utf-8', 'Log in first.');
    }
    if (req.method === 'GET') {
      if (path === '/') return reply(res, 200, 'text/html; charset=utf-8', APP_PAGE);
      if (path === '/app.js') return reply(res, 200, 'text/javascript; charset=utf-8', APP_JS);
      if (path === '/session') return reply(res, 200, 'application/json', JSON.stringify({ sessionId: session.sessionId, mode: session.gate.mode, tier: session.tier, csrf }));
      if (path === '/events') {
        res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': 'text/event-stream', connection: 'keep-alive' });
        res.write(': connected\n\n');
        streams.add(res);
        req.on('close', () => streams.delete(res));
        return;
      }
      return reply(res, 404, 'text/plain', 'Not found.');
    }
    if (req.method !== 'POST') return reply(res, 405, 'text/plain', 'Method not allowed.');
    const header = req.headers['x-hn-csrf'];
    if (typeof header !== 'string' || !same(header, csrf)) return reply(res, 403, 'text/plain; charset=utf-8', 'The CSRF token is missing or wrong.');
    if ((req.headers['content-type'] ?? '').split(';')[0] !== 'application/json') return reply(res, 415, 'text/plain', 'Send JSON.');
    const body = await readBody(req);
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body ?? '') as Record<string, unknown>;
    } catch {
      return reply(res, 400, 'text/plain', 'That is not JSON.');
    }
    if (path === '/prompt') {
      if (typeof data['text'] !== 'string' || data['text'].trim() === '') return reply(res, 400, 'text/plain', 'Send some text.');
      if (busy) return reply(res, 409, 'text/plain', 'A turn is running.');
      busy = true;
      try {
        const result = await harness.run(data['text'], { origin: 'user' });
        return reply(res, 200, 'application/json', JSON.stringify({ end: result.end, html: renderMarkdown(result.text) }));
      } finally {
        busy = false;
      }
    }
    if (path === '/approve') {
      const answer = pending.get(String(data['approvalId']));
      if (answer === undefined) return reply(res, 404, 'text/plain', 'No such card is waiting.');
      answer(data['decision'] === 'once' ? 'once' : 'deny');
      return reply(res, 200, 'application/json', '{}');
    }
    return reply(res, 404, 'text/plain', 'Not found.');
  };

  const server = createServer((req, res) => {
    void handle(req, res).catch(() => {
      if (!res.headersSent) reply(res, 500, 'text/plain', 'Something went wrong.');
    });
  });
  // No WebSockets here; an upgrade is refused whatever it claims.
  server.on('upgrade', (_req: IncomingMessage, socket: Socket) => socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen({ port: options.port ?? 0, host: '127.0.0.1' }, resolve);
  });
  port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}/`,
    port,
    token,
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
