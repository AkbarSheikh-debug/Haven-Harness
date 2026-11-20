import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { SECURITY_HEADERS } from './serve-render.ts';

/**
 * What every page `hn serve` shows has in common, so the live session and the replay screen are hardened the same way
 * and by the same code:
 * - Loopback only; there is no option for anything else.
 * - Every request's Host must be exactly this server's loopback name and port, which stops DNS rebinding; every request
 *   that carries an Origin must be this server's own, and every POST must carry one.
 * - A random token, shown on the terminal, is typed into a login form and exchanged for an HttpOnly, SameSite=Strict
 *   cookie. The token is never accepted in a URL.
 * - Every response carries the strict security headers (a CSP with no inline script or style, no framing, no referrer).
 */

export const MAX_BODY = 64 * 1024;
const digest = (text: string): Buffer => createHash('sha256').update(text).digest();
export const same = (a: string, b: string): boolean => timingSafeEqual(digest(a), digest(b));

export function readBody(req: IncomingMessage): Promise<string | null> {
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

export class Guard {
  readonly token = randomBytes(32).toString('hex');
  readonly csrf = randomBytes(32).toString('hex');
  readonly #cookie = randomBytes(32).toString('hex');
  port = 0;

  allowedHosts(): string[] {
    return [`127.0.0.1:${this.port}`, `localhost:${this.port}`];
  }

  /** Why a request is refused before anything else looks at it, or null. */
  refuse(req: IncomingMessage): [number, string] | null {
    const host = req.headers.host ?? '';
    if (!this.allowedHosts().includes(host)) return [421, 'This server answers only to its own loopback address.'];
    const origin = req.headers.origin;
    if (origin !== undefined && !this.allowedHosts().map((allowed) => `http://${allowed}`).includes(origin)) return [403, 'Requests from another site are refused.'];
    if (req.method === 'POST' && origin === undefined) return [403, 'A request that changes something must say where it came from.'];
    return null;
  }

  loggedIn(req: IncomingMessage): boolean {
    const found = /(?:^|;\s*)hn_session=([0-9a-f]{64})/.exec(req.headers.cookie ?? '');
    return found !== null && same(found[1] as string, this.#cookie);
  }

  reply(res: ServerResponse, status: number, type: string, body: string, extra: Record<string, string> = {}): void {
    res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': type, ...extra }).end(body);
  }

  /** The login form's answer: the token, in a POST body, for the cookie. */
  async login(req: IncomingMessage, res: ServerResponse, page: string): Promise<void> {
    if (req.method === 'GET') return this.reply(res, 200, 'text/html; charset=utf-8', page);
    if (req.method !== 'POST') return this.reply(res, 405, 'text/plain', 'Method not allowed.');
    const body = (await readBody(req)) ?? '';
    const given = new URLSearchParams(body).get('token') ?? '';
    if (!same(given, this.token)) return this.reply(res, 401, 'text/plain; charset=utf-8', 'That is not the token hn printed.');
    return this.reply(res, 303, 'text/plain', '', { location: '/', 'set-cookie': `hn_session=${this.#cookie}; HttpOnly; SameSite=Strict; Path=/` });
  }
}

/** Listens on loopback only, refuses every upgrade, and gives back the port. */
export async function listenLoopback(handle: (req: IncomingMessage, res: ServerResponse) => Promise<void>, guard: Guard, requestedPort = 0): Promise<Server> {
  const server = createServer((req, res) => {
    void handle(req, res).catch(() => {
      if (!res.headersSent) guard.reply(res, 500, 'text/plain', 'Something went wrong.');
    });
  });
  // No WebSockets here; an upgrade is refused whatever it claims.
  server.on('upgrade', (_req: IncomingMessage, socket: Socket) => socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen({ port: requestedPort, host: '127.0.0.1' }, resolve);
  });
  guard.port = (server.address() as { port: number }).port;
  return server;
}
