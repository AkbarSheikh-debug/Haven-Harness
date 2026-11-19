// The package proxy for `hn prepare` (decision 10). Plain JavaScript with no imports beyond Node, because it is mounted
// read-only into the proxy container and run there as it is.
//
// It is a reverse proxy, not a forward one: the installer is told to use http://<proxy>/npm/ as its registry, and the
// proxy alone decides where a request goes. Only GET and HEAD. Only two upstreams, fixed here: the npm registry and
// PyPI. Nothing from the request (a Host header, an absolute URL, a CONNECT target) chooses a destination, so the
// installer cannot reach the Docker engine, a gateway or any other host through it. Credentials never pass: every
// request header but a few safe ones is dropped. npm's account and publishing endpoints are refused.

import { createServer } from 'node:http';

const ROUTES = [
  { prefix: '/npm/', upstream: 'https://registry.npmjs.org/' },
  { prefix: '/pypi/simple/', upstream: 'https://pypi.org/simple/' },
  { prefix: '/pypi-files/', upstream: 'https://files.pythonhosted.org/' },
];
const SAFE_PATH = /^[A-Za-z0-9@._~+\-/%]*$/;
const FORWARDED_HEADERS = ['accept', 'if-none-match', 'if-modified-since'];
const MAX_BODY = 256 * 1024 * 1024;

/** Why a request is refused, with its status, or null when it may go upstream. */
export function refusal(method, rawUrl) {
  if (method === 'CONNECT') return { status: 405, reason: 'tunnels are not offered' };
  if (method !== 'GET' && method !== 'HEAD') return { status: 405, reason: `${method} is refused: the proxy only reads (no publish, no login)` };
  if (!rawUrl.startsWith('/')) return { status: 403, reason: 'only paths on this proxy are served, never another host' };
  const path = rawUrl.split('?')[0];
  if (!SAFE_PATH.test(path)) return { status: 400, reason: 'the path has characters a package path never has' };
  const decoded = (() => {
    try {
      return decodeURIComponent(path);
    } catch {
      return null;
    }
  })();
  if (decoded === null || decoded.split('/').some((part) => part === '..' || part === '.') || decoded.includes('\\')) return { status: 400, reason: 'the path climbs out of its registry' };
  const route = ROUTES.find((candidate) => path.startsWith(candidate.prefix));
  if (route === undefined) return { status: 404, reason: 'no such registry here' };
  const rest = path.slice(route.prefix.length);
  // npm's own endpoints (login, whoami, tokens, org, audit, publish) all live under /-/ at the top.
  if (route.prefix === '/npm/' && (rest.startsWith('-/') || rest === '-')) return { status: 403, reason: 'npm account and registry endpoints are refused' };
  return null;
}

/** The upstream URL for an allowed path. */
export function upstreamFor(rawUrl) {
  const route = ROUTES.find((candidate) => rawUrl.startsWith(candidate.prefix));
  return route === undefined ? null : route.upstream + rawUrl.slice(route.prefix.length);
}

/** Points download links in registry answers back at this proxy, so the installer never goes around it. */
export function rewrite(text, publicBase) {
  return text
    .replaceAll('https://registry.npmjs.org/', `${publicBase}/npm/`)
    .replaceAll('https://files.pythonhosted.org/', `${publicBase}/pypi-files/`);
}

export function createRegistryProxy({ publicBase, fetch: doFetch = globalThis.fetch, log = () => {} }) {
  const server = createServer((req, res) => {
    const method = req.method ?? 'GET';
    const url = req.url ?? '';
    const refused = refusal(method, url);
    if (refused !== null) {
      log({ method, url, status: refused.status, reason: refused.reason });
      res.writeHead(refused.status, { 'content-type': 'text/plain' }).end(`hn package proxy: ${refused.reason}\n`);
      req.resume();
      return;
    }
    const headers = { 'user-agent': 'hn-prepare', 'accept-encoding': 'identity' };
    for (const name of FORWARDED_HEADERS) if (typeof req.headers[name] === 'string') headers[name] = req.headers[name];
    const target = upstreamFor(url);
    log({ method, url, status: 0, upstream: target });
    doFetch(target, { method, headers, redirect: 'error' })
      .then(async (reply) => {
        const type = reply.headers.get('content-type') ?? 'application/octet-stream';
        const textual = /json|html|text/.test(type);
        const body = Buffer.from(await reply.arrayBuffer());
        if (body.length > MAX_BODY) {
          res.writeHead(502).end('too large');
          return;
        }
        const out = textual ? Buffer.from(rewrite(body.toString('utf8'), publicBase)) : body;
        res.writeHead(reply.status, { 'content-type': type, 'content-length': String(out.length) });
        res.end(method === 'HEAD' ? undefined : out);
      })
      .catch(() => res.writeHead(502, { 'content-type': 'text/plain' }).end('hn package proxy: the registry could not be reached\n'));
  });
  // A tunnel would let the installer choose its own destination, so CONNECT is answered and never opened.
  server.on('connect', (req, socket) => {
    log({ method: 'CONNECT', url: req.url ?? '', status: 405, reason: 'tunnels are not offered' });
    socket.on('error', () => {});
    socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n');
  });
  return server;
}

// Run as a program inside the proxy container: `node registry-proxy.mjs`, configured by environment.
if (process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].replaceAll('\\', '/').split('/').pop() ?? '\0') && process.env['HN_PROXY_PUBLIC'] !== undefined) {
  const port = Number(process.env['HN_PROXY_PORT'] ?? 8080);
  createRegistryProxy({ publicBase: process.env['HN_PROXY_PUBLIC'], log: (entry) => process.stdout.write(`${JSON.stringify(entry)}\n`) }).listen(port, '0.0.0.0');
}
