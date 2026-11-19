import { spawn } from 'node:child_process';
import { lookup as dnsLookup } from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { EgressPolicy, blockedAddress, checkUrl, type UrlOptions } from '@hn/security';

/**
 * `web_fetch` (8.8.5). One hop runs in a separate process that holds no credentials and no state. It checks the
 * URL before resolving anything, refuses if any answer is in a blocked range, and connects to exactly the address
 * it checked, so a name that changes its answer between the check and the connection cannot redirect it. The
 * parent loops over the hops, so every redirect goes back through the full egress policy.
 */

export interface HopRequest {
  readonly url: string;
  readonly maxBytes: number;
  readonly timeoutMs: number;
  readonly allowHttp?: boolean;
  readonly allowedPorts?: readonly number[];
  /** Tests only. Lets 127.0.0.1, localhost and ::1 through, in the URL and after resolving, so a local server can stand in for the internet. */
  readonly unsafeAllowLoopbackForTests?: boolean;
}

export type HopResult =
  | { readonly kind: 'response'; readonly status: number; readonly contentType: string; readonly body: Buffer; readonly truncated: boolean }
  | { readonly kind: 'redirect'; readonly status: number; readonly location: string }
  | { readonly kind: 'refused'; readonly reason: string };

export type Resolver = (host: string) => Promise<string[]>;

const defaultResolver: Resolver = async (host) => (await dnsLookup(host, { all: true, verbatim: true })).map((entry) => entry.address);

const TEXTUAL = /^(text\/|application\/(json|xml|xhtml\+xml|javascript|ecmascript|x-javascript|rss\+xml|atom\+xml|yaml|x-yaml|ld\+json|x-www-form-urlencoded)|image\/svg\+xml)/i;

const isLoopback = (address: string): boolean => address === '::1' || address.startsWith('127.') || address.toLowerCase() === '::ffff:127.0.0.1';

/** One request to one URL, with no redirect followed. */
export async function fetchOnce(request: HopRequest, resolve: Resolver = defaultResolver): Promise<HopResult> {
  const urlOptions: UrlOptions = { allowHttp: request.allowHttp === true, ...(request.allowedPorts === undefined ? {} : { allowedPorts: request.allowedPorts }) };
  let verdict = checkUrl(request.url, urlOptions);
  if (!verdict.ok && request.unsafeAllowLoopbackForTests === true) {
    // Tests only: a loopback URL stands in for the internet. Everything else is still checked.
    try {
      const candidate = new URL(request.url);
      if (['127.0.0.1', 'localhost', '[::1]'].includes(candidate.hostname) && (candidate.protocol === 'http:' || candidate.protocol === 'https:')) verdict = { ok: true, url: candidate };
    } catch {
      // Not a URL: the refusal above stands.
    }
  }
  if (!verdict.ok) return { kind: 'refused', reason: verdict.reason };
  const url = verdict.url;
  const host = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');

  let addresses: string[];
  try {
    addresses = isIP(host) !== 0 ? [host] : await resolve(host);
  } catch {
    return { kind: 'refused', reason: `${host} did not resolve.` };
  }
  if (addresses.length === 0) return { kind: 'refused', reason: `${host} did not resolve.` };
  // Every answer is checked, not just the one used: a name with one public and one private address is refused.
  for (const address of addresses) {
    const blocked = blockedAddress(address);
    if (blocked !== null && !(request.unsafeAllowLoopbackForTests === true && isLoopback(address))) return { kind: 'refused', reason: `${host} resolves to ${blocked}.` };
  }
  const pinned = addresses[0] as string;
  const family = isIP(pinned);

  return new Promise<HopResult>((done) => {
    const client = url.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (result: HopResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      done(result);
    };
    const options: https.RequestOptions = {
      host,
      port: url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port),
      path: `${url.pathname}${url.search}`,
      method: 'GET',
      agent: false,
      // The connection goes to the address that was checked, whatever the name would resolve to now.
      lookup: ((_name: string, lookupOptions: { all?: boolean }, callback: (error: Error | null, address: unknown, family?: number) => void) => {
        if (lookupOptions.all === true) callback(null, [{ address: pinned, family }]);
        else callback(null, pinned, family);
      }) as never,
      ...(url.protocol === 'https:' ? { servername: host } : {}),
      headers: {
        'user-agent': 'hn/0.0.0',
        accept: 'text/html,text/plain,application/json,application/xml;q=0.9,*/*;q=0.1',
        // No decompression, so a small download cannot expand into a large one.
        'accept-encoding': 'identity',
        connection: 'close',
      },
    };
    const outgoing = client.request(options, (response) => {
      const status = response.statusCode ?? 0;
      const location = response.headers.location;
      if (status >= 300 && status < 400 && typeof location === 'string') {
        response.resume();
        return finish({ kind: 'redirect', status, location });
      }
      const contentType = String(response.headers['content-type'] ?? '');
      if (contentType !== '' && !TEXTUAL.test(contentType)) {
        response.destroy();
        return finish({ kind: 'refused', reason: `The content type ${contentType.split(';')[0]} is not text, so it was not downloaded.` });
      }
      const parts: Buffer[] = [];
      let size = 0;
      let truncated = false;
      response.on('data', (chunk: Buffer) => {
        if (truncated) return;
        const room = request.maxBytes - size;
        if (chunk.length > room) {
          parts.push(chunk.subarray(0, Math.max(0, room)));
          size = request.maxBytes;
          truncated = true;
          response.destroy();
          return finish({ kind: 'response', status, contentType, body: Buffer.concat(parts), truncated });
        }
        parts.push(chunk);
        size += chunk.length;
      });
      response.on('end', () => finish({ kind: 'response', status, contentType, body: Buffer.concat(parts), truncated }));
      response.on('error', () => finish({ kind: 'response', status, contentType, body: Buffer.concat(parts), truncated: true }));
    });
    const timer = setTimeout(() => {
      outgoing.destroy();
      finish({ kind: 'refused', reason: `The request took longer than ${request.timeoutMs} ms.` });
    }, request.timeoutMs);
    outgoing.on('error', (error) => finish({ kind: 'refused', reason: `The request failed: ${(error as NodeJS.ErrnoException).code ?? error.message}` }));
    outgoing.end();
  });
}

/** What the child process gets: nothing that holds a key, a token or a path to one. */
export function workerEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  // Windows networking needs these two to find its libraries. Neither is a secret.
  if (process.platform === 'win32') for (const name of ['SystemRoot', 'windir']) if (process.env[name] !== undefined) env[name] = process.env[name];
  return env;
}

/** Runs one hop in a separate process with no credentials. */
export function fetchInChildProcess(request: HopRequest): Promise<HopResult> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--disable-proto=throw', '--no-warnings', fileURLToPath(new URL('./web-worker.ts', import.meta.url))], {
      env: workerEnvironment(),
      stdio: ['pipe', 'pipe', 'ignore'],
      windowsHide: true,
    });
    const out: Buffer[] = [];
    let settled = false;
    const finish = (result: HopResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill();
      resolve(result);
    };
    const timer = setTimeout(() => finish({ kind: 'refused', reason: `The request took longer than ${request.timeoutMs} ms.` }), request.timeoutMs + 5_000);
    child.stdout.on('data', (chunk: Buffer) => out.push(chunk));
    child.on('error', () => finish({ kind: 'refused', reason: 'The fetch process could not start.' }));
    child.on('close', () => {
      try {
        const parsed = JSON.parse(Buffer.concat(out).toString('utf8')) as { kind: HopResult['kind']; body?: string } & Record<string, unknown>;
        finish(parsed.kind === 'response' ? ({ ...parsed, body: Buffer.from(parsed.body ?? '', 'base64') } as HopResult) : (parsed as unknown as HopResult));
      } catch {
        finish({ kind: 'refused', reason: 'The fetch process returned nothing usable.' });
      }
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(JSON.stringify(request));
  });
}

export interface WebFetchDeps {
  readonly policy: EgressPolicy;
  /** One hop. Defaults to a separate no-credential process. */
  readonly runHop?: (request: HopRequest) => Promise<HopResult>;
  readonly allowHttp?: boolean;
  readonly allowedPorts?: readonly number[];
  readonly maxRedirects?: number;
  readonly maxBytes?: number;
  readonly timeoutMs?: number;
  readonly unsafeAllowLoopbackForTests?: boolean;
}

export type WebFetchResult =
  | { readonly ok: true; readonly status: number; readonly url: string; readonly contentType: string; readonly text: string; readonly truncated: boolean; readonly redirects: readonly string[] }
  | { readonly ok: false; readonly reason: string; readonly redirects: readonly string[] };

const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

function decode(body: Buffer, contentType: string): string {
  const charset = /charset=["']?([\w-]+)/i.exec(contentType)?.[1]?.toLowerCase();
  return body.toString(charset === 'iso-8859-1' || charset === 'latin1' || charset === 'windows-1252' ? 'latin1' : 'utf8');
}

/** Fetches a URL, following redirects one hop at a time, each hop checked by the whole egress policy. */
export async function webFetch(rawUrl: string, deps: WebFetchDeps): Promise<WebFetchResult> {
  const runHop = deps.runHop ?? fetchInChildProcess;
  const redirects: string[] = [];
  let current = rawUrl;
  const limit = deps.maxRedirects ?? 5;
  for (let hop = 0; hop <= limit; hop += 1) {
    const loopbackOk = deps.unsafeAllowLoopbackForTests === true;
    let verdict = checkUrl(current, { allowHttp: deps.allowHttp === true, ...(deps.allowedPorts === undefined ? {} : { allowedPorts: deps.allowedPorts }) });
    if (!verdict.ok && loopbackOk) {
      try {
        const candidate = new URL(current);
        if (['127.0.0.1', 'localhost', '[::1]'].includes(candidate.hostname) && (candidate.protocol === 'http:' || candidate.protocol === 'https:')) verdict = { ok: true, url: candidate };
      } catch {
        // Not a URL: the refusal stands.
      }
    }
    if (!verdict.ok) return { ok: false, reason: verdict.reason, redirects };
    const decision = deps.policy.decide(verdict.url);
    if (!decision.ok) return { ok: false, reason: hop === 0 ? decision.reason : `The redirect to ${verdict.url.origin} was refused: ${decision.reason}`, redirects };
    deps.policy.record(verdict.url);

    const result = await runHop({
      url: verdict.url.href,
      maxBytes: deps.maxBytes ?? DEFAULT_MAX_BYTES,
      timeoutMs: deps.timeoutMs ?? 20_000,
      ...(deps.allowHttp === true ? { allowHttp: true } : {}),
      ...(deps.allowedPorts === undefined ? {} : { allowedPorts: deps.allowedPorts }),
      ...(deps.unsafeAllowLoopbackForTests === true ? { unsafeAllowLoopbackForTests: true } : {}),
    });
    if (result.kind === 'refused') return { ok: false, reason: result.reason, redirects };
    if (result.kind === 'response') {
      return { ok: true, status: result.status, url: verdict.url.href, contentType: result.contentType, text: decode(result.body, result.contentType), truncated: result.truncated, redirects };
    }
    try {
      current = new URL(result.location, verdict.url).href;
    } catch {
      return { ok: false, reason: 'The server sent a redirect to something that is not a URL.', redirects };
    }
    redirects.push(current);
  }
  return { ok: false, reason: `More than ${limit} redirects.`, redirects };
}
