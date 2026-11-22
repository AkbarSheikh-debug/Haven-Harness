import { createPublicKey, type KeyObject } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { HnError, revealHidden, sanitizeForDisplay } from '@hn/core';
import { checkpointFromValue, checkpointValid, verifyBundle } from '@hn/security';
import { AUDIT_CSS, AUDIT_JS, AUDIT_PAGE } from './audit-page.ts';
import { auditRequest, openAuditLink, queryOf, type AuditLink } from './audit-client.ts';
import { Guard, listenLoopback } from './serve-guard.ts';
import { APP_CSS, LOGIN_PAGE, SECURITY_HEADERS } from './serve-render.ts';
import type { Served } from './serve.ts';

/**
 * The auditor screen (`hn serve --audit`, Phase 14): the team's audit in a browser, on the auditor's own machine. The
 * broker serves no HTML at all; this is the same hardened local door as the replay screen (loopback only, Host and Origin
 * checks, a token exchanged for an HttpOnly cookie, strict headers, GET only), and it reads the broker with the person's
 * own LOGIN token, which never reaches the browser. It starts nothing and changes nothing.
 *
 * What the broker returns is the record of what people did, some of it chosen by them (an approval's action text), so every
 * string is written out with its hidden characters visible and capped before it reaches the page, and the page sets text,
 * never markup. A filter the page sends is rebuilt from a short list of names; it is never forwarded as written.
 */

export interface AuditServeOptions {
  /** Where `hn login` saved the person's login. */
  readonly home: string;
  readonly fetch?: typeof fetch;
  readonly port?: number;
  /** The broker's audit public key, handed over by its operator. Without it, nothing the broker says is checked against a key. */
  readonly publicKeyFile?: string;
  /** The broker's audit key. With it and the public key, the Export tab can check an export here. */
  readonly hmacKeyFile?: string;
}

const MAX_STRING = 2_000;
const FILTERS: Readonly<Record<string, readonly string[]>> = {
  rows: ['user', 'session', 'type', 'since', 'until', 'after', 'limit'],
  approvals: ['user', 'state'],
  sessions: ['user'],
  anchors: ['user', 'session'],
  export: ['from', 'to'],
  tail: ['from'],
};

/** Every string in a value, with hidden characters written out and long ones cut, so nothing reaches the page that hides from the reader. */
function revealDeep(value: unknown): unknown {
  if (typeof value === 'string') {
    const shown = revealHidden(value);
    return shown.length > MAX_STRING ? `${shown.slice(0, MAX_STRING)}...` : shown;
  }
  if (Array.isArray(value)) return value.map(revealDeep);
  if (typeof value === 'object' && value !== null) return Object.fromEntries(Object.entries(value).map(([key, item]) => [revealHidden(key), revealDeep(item)]));
  return value;
}

/** The query as it should go to the broker: only the names this route takes, once each, short. Null when anything else is there. */
function forwardQuery(request: IncomingMessage, names: readonly string[]): string | null {
  const given = new URL(request.url ?? '/', 'http://audit').searchParams;
  const kept: Record<string, string> = {};
  for (const [name, value] of given) {
    if (!names.includes(name) || name in kept || value.length > 200) return null;
    kept[name] = value;
  }
  return queryOf(kept, names);
}

export async function startAuditServe(options: AuditServeOptions): Promise<Served> {
  const link: AuditLink = await openAuditLink(options.home, options.fetch);
  let publicKey: KeyObject | null = null;
  if (options.publicKeyFile !== undefined) {
    try {
      publicKey = createPublicKey(await readFile(options.publicKeyFile));
    } catch {
      throw new HnError('BAD_COMMAND', 'The public key file is not a public key.');
    }
  }
  const hmacKey = options.hmacKeyFile === undefined ? null : await readFile(options.hmacKeyFile).catch(() => {
    throw new HnError('BAD_COMMAND', 'The audit key file cannot be read.');
  });
  const guard = new Guard();
  const streams = new Set<AbortController>();

  const json = (res: ServerResponse, status: number, body: unknown): void => guard.reply(res, status, 'application/json', JSON.stringify(body));

  /** The broker's JSON answer, cleaned, or its refusal as an error the page can show. */
  async function relay(res: ServerResponse, path: string): Promise<void> {
    let response: Response;
    try {
      response = await auditRequest(link, path);
    } catch {
      return json(res, 502, { error: 'The broker could not be reached.' });
    }
    const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (!response.ok) return json(res, response.status === 403 || response.status === 401 ? response.status : 502, { error: sanitizeForDisplay(String(body['error'] ?? `The broker answered ${response.status}.`)) });
    json(res, 200, revealDeep(body));
  }

  async function status(res: ServerResponse): Promise<void> {
    let response: Response;
    try {
      response = await auditRequest(link, '/v1/audit/checkpoints');
    } catch {
      return json(res, 502, { error: 'The broker could not be reached.' });
    }
    const body = (await response.json().catch(() => ({}))) as { keyId?: string; publicKey?: string; checkpoints?: unknown[]; error?: string };
    if (!response.ok) return json(res, response.status === 403 || response.status === 401 ? response.status : 502, { error: sanitizeForDisplay(String(body.error ?? `The broker answered ${response.status}.`)) });
    const newest = checkpointFromValue(body.checkpoints?.[body.checkpoints.length - 1]);
    if (newest === null) return json(res, 502, { error: 'The broker sent no checkpoint.' });
    let keyMatches: boolean | null = null;
    let signatureOk: boolean | null = null;
    if (publicKey !== null) {
      try {
        keyMatches = createPublicKey(String(body.publicKey)).export({ type: 'spki', format: 'pem' }).toString() === publicKey.export({ type: 'spki', format: 'pem' }).toString();
      } catch {
        keyMatches = false;
      }
      signatureOk = checkpointValid(newest, publicKey);
    }
    json(res, 200, { head: newest.n, signedAt: revealHidden(newest.ts), keyId: revealHidden(String(body.keyId ?? '')), pinned: publicKey !== null, keyMatches, signatureOk });
  }

  async function verify(res: ServerResponse): Promise<void> {
    if (publicKey === null || hmacKey === null) return json(res, 200, { ok: null, message: 'To check an export here, start with --pub (the broker\'s audit public key) and --key-file (its audit key). Or download it and run: hn audit verify.' });
    let response: Response;
    try {
      response = await auditRequest(link, '/v1/audit/export');
    } catch {
      return json(res, 502, { error: 'The broker could not be reached.' });
    }
    if (!response.ok) return json(res, 502, { error: 'The broker would not give an export.' });
    const result = verifyBundle(await response.json().catch(() => null), { hmacKey, publicKey });
    json(res, 200, { ...result, reason: result.reason === null ? null : revealHidden(result.reason) });
  }

  /** The broker's live stream, passed through line by line with every string cleaned. */
  async function tail(req: IncomingMessage, res: ServerResponse, query: string): Promise<void> {
    const controller = new AbortController();
    streams.add(controller);
    res.on('close', () => {
      controller.abort();
      streams.delete(controller);
    });
    let upstream: Response;
    try {
      upstream = await link.fetcher(`${link.login.url}/v1/audit/tail${query}`, { method: 'GET', redirect: 'error', signal: controller.signal, headers: { authorization: `Bearer ${link.login.loginToken}`, 'x-hn-session': link.login.sid } });
    } catch {
      return json(res, 502, { error: 'The broker could not be reached.' });
    }
    if (!upstream.ok || upstream.body === null) {
      const body = (await upstream.json().catch(() => ({}))) as Record<string, unknown>;
      return json(res, upstream.status === 403 || upstream.status === 401 || upstream.status === 429 ? upstream.status : 502, { error: sanitizeForDisplay(String(body['error'] ?? `The broker answered ${upstream.status}.`)) });
    }
    res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': 'application/x-ndjson' });
    let pending = '';
    const decoder = new TextDecoder();
    try {
      for await (const chunk of Readable.fromWeb(upstream.body as never) as AsyncIterable<Uint8Array>) {
        pending += decoder.decode(chunk, { stream: true });
        if (pending.length > 8 * 1024 * 1024) break;
        let at = pending.indexOf('\n');
        while (at !== -1) {
          const line = pending.slice(0, at);
          pending = pending.slice(at + 1);
          if (line !== '') {
            try {
              res.write(`${JSON.stringify(revealDeep(JSON.parse(line)))}\n`);
            } catch {
              // A line that is not JSON is dropped, not forwarded.
            }
          }
          at = pending.indexOf('\n');
        }
      }
    } catch {
      // The browser left, or the broker did.
    }
    res.end();
    void req;
  }

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const refused = guard.refuse(req);
    if (refused !== null) return guard.reply(res, refused[0], 'text/plain; charset=utf-8', refused[1]);
    const path = new URL(req.url ?? '/', `http://127.0.0.1:${guard.port}`).pathname;
    if (req.method === 'GET' && path === '/app.css') return guard.reply(res, 200, 'text/css; charset=utf-8', APP_CSS);
    if (path === '/login') return guard.login(req, res, AUDIT_LOGIN_PAGE);
    if (!guard.loggedIn(req)) {
      if (req.method === 'GET' && (path === '/' || path === '/audit')) return guard.reply(res, 303, 'text/plain', '', { location: '/login' });
      return guard.reply(res, 401, 'text/plain; charset=utf-8', 'Log in first.');
    }
    if (req.method !== 'GET') return guard.reply(res, 405, 'text/plain; charset=utf-8', 'This screen is read-only; it cannot be asked to do anything.', { allow: 'GET' });
    if (path === '/') return guard.reply(res, 303, 'text/plain', '', { location: '/audit' });
    if (path === '/audit') return guard.reply(res, 200, 'text/html; charset=utf-8', AUDIT_PAGE);
    if (path === '/audit.js') return guard.reply(res, 200, 'text/javascript; charset=utf-8', AUDIT_JS);
    if (path === '/audit.css') return guard.reply(res, 200, 'text/css; charset=utf-8', AUDIT_CSS);
    if (path === '/audit/api/status') return status(res);
    if (path === '/audit/api/verify') return verify(res);
    const route = /^\/audit\/api\/(rows|approvals|sessions|anchors|export|tail)$/.exec(path)?.[1];
    if (route !== undefined) {
      const query = forwardQuery(req, FILTERS[route] as readonly string[]);
      if (query === null) return guard.reply(res, 400, 'text/plain; charset=utf-8', 'That filter is not one this screen sends.');
      if (route === 'tail') return tail(req, res, query);
      if (route === 'export') {
        let response: Response;
        try {
          response = await auditRequest(link, `/v1/audit/export${query}`);
        } catch {
          return json(res, 502, { error: 'The broker could not be reached.' });
        }
        if (!response.ok) return json(res, 502, { error: 'The broker would not give an export.' });
        // The export is passed on exactly as the broker made it: any change would break the checks it is for.
        return guard.reply(res, 200, 'application/json', await response.text(), { 'content-disposition': 'attachment; filename="audit-export.json"' });
      }
      return relay(res, `/v1/audit/${route}${query}`);
    }
    return guard.reply(res, 404, 'text/plain; charset=utf-8', 'Not found.');
  };

  const server = await listenLoopback(handle, guard, options.port ?? 0);
  return {
    url: `http://127.0.0.1:${guard.port}/`,
    port: guard.port,
    token: guard.token,
    server,
    close: async () => {
      for (const controller of streams) controller.abort();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

const AUDIT_LOGIN_PAGE = LOGIN_PAGE.replace('<title>hn</title>', '<title>hn team audit</title>');
