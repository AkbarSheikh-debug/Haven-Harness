import { lookup } from 'node:dns/promises';
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { connect, isIP, type Socket } from 'node:net';
import { blockedAddress, checkUrl } from '@hn/security';

/**
 * The browser's only way out (decision 8). Every request the browser makes, for the page and for everything the page
 * asks for, comes here first: an https tunnel (CONNECT) or a plain http request. The name is checked before it is
 * resolved, resolved here (not by the browser), every address it resolves to must be public, and the connection goes to
 * the address that was checked, so a name cannot be re-pointed at this machine between the check and the connection.
 */

export type ProxyResolver = (host: string) => Promise<string[]>;

export interface EgressProxyOptions {
  readonly resolve?: ProxyResolver;
  /** Plain http. Off by default, as for `web_fetch`. */
  readonly allowHttp?: boolean;
  readonly allowedPorts?: readonly number[];
  /** Under the Rule of Two only hosts a person approved; otherwise every public host. */
  readonly allowHost?: (host: string) => boolean;
  /** Tests only: one address and port that may be reached although it is not public (the test's own page server). */
  readonly exempt?: { readonly address: string; readonly port: number };
}

export interface ProxyDecision {
  readonly target: string;
  readonly allowed: boolean;
  readonly reason?: string;
}

const defaultResolve: ProxyResolver = async (host) => (await lookup(host, { all: true, verbatim: true })).map((entry) => entry.address);
const MAX_LOG = 500;

export class EgressProxy {
  readonly #options: EgressProxyOptions;
  readonly #server: Server;
  readonly #sockets = new Set<Socket>();
  readonly decisions: ProxyDecision[] = [];
  port = 0;

  private constructor(options: EgressProxyOptions) {
    this.#options = options;
    this.#server = createServer((req, res) => void this.#http(req, res));
    this.#server.on('connect', (req: IncomingMessage, socket: Socket, head: Buffer) => void this.#connect(req, socket, head));
    this.#server.on('connection', (socket: Socket) => {
      this.#sockets.add(socket);
      socket.on('close', () => this.#sockets.delete(socket));
    });
  }

  /** Listens on loopback only. */
  static async start(options: EgressProxyOptions = {}): Promise<EgressProxy> {
    const proxy = new EgressProxy(options);
    await new Promise<void>((resolve, reject) => {
      proxy.#server.once('error', reject);
      proxy.#server.listen({ port: 0, host: '127.0.0.1' }, resolve);
    });
    proxy.port = (proxy.#server.address() as { port: number }).port;
    return proxy;
  }

  #note(target: string, allowed: boolean, reason?: string): void {
    if (this.decisions.length < MAX_LOG) this.decisions.push({ target, allowed, ...(reason === undefined ? {} : { reason }) });
  }

  /** Where a request may go: the address to connect to, or why not. */
  async #route(url: string): Promise<{ address: string; port: number; host: string } | { reason: string }> {
    const verdict = checkUrl(url, { allowHttp: this.#options.allowHttp === true, ...(this.#options.allowedPorts === undefined ? {} : { allowedPorts: this.#options.allowedPorts }) });
    const parsed = (() => {
      try {
        return new URL(url);
      } catch {
        return null;
      }
    })();
    if (parsed === null) return { reason: 'not a valid URL' };
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const port = parsed.port === '' ? (parsed.protocol === 'https:' ? 443 : 80) : Number(parsed.port);
    const exempt = this.#options.exempt;
    if (exempt !== undefined && host === exempt.address && port === exempt.port) return { address: host, port, host };
    if (!verdict.ok) return { reason: verdict.reason };
    if (this.#options.allowHost !== undefined && !this.#options.allowHost(host)) return { reason: `${host} was not approved for this session, so the page may not reach it.` };
    let addresses: string[];
    try {
      addresses = isIP(host) === 0 ? await (this.#options.resolve ?? defaultResolve)(host) : [host];
    } catch {
      return { reason: `${host} could not be resolved.` };
    }
    if (addresses.length === 0) return { reason: `${host} has no address.` };
    for (const address of addresses) {
      if (exempt !== undefined && address === exempt.address && port === exempt.port) continue;
      const blocked = blockedAddress(address);
      // Every address must be public, so the browser cannot be steered to a private one by DNS order.
      if (blocked !== null) return { reason: `Blocked: ${blocked}.` };
    }
    return { address: addresses[0] as string, port, host };
  }

  async #connect(req: IncomingMessage, socket: Socket, head: Buffer): Promise<void> {
    socket.on('error', () => undefined);
    const target = req.url ?? '';
    const route = /^[^/\s]+:\d+$/.test(target) ? await this.#route(`https://${target}/`) : { reason: 'a tunnel needs host:port' };
    if ('reason' in route) {
      this.#note(`CONNECT ${target}`, false, route.reason);
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }
    this.#note(`CONNECT ${target}`, true);
    const upstream = connect({ host: route.address, port: route.port });
    upstream.on('error', () => socket.destroy());
    upstream.on('connect', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    socket.on('close', () => upstream.destroy());
  }

  async #http(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const target = req.url ?? '';
    const route = /^http:\/\//i.test(target) ? await this.#route(target) : { reason: 'only proxy requests with a full http URL are served' };
    if ('reason' in route) {
      this.#note(`${req.method ?? 'GET'} ${target}`, false, route.reason);
      res.writeHead(403, { 'content-type': 'text/plain' }).end('Blocked by the hn egress proxy.');
      return;
    }
    this.#note(`${req.method ?? 'GET'} ${target}`, true);
    const url = new URL(target);
    const headers: Record<string, string | string[] | undefined> = { ...req.headers, host: url.host };
    for (const name of Object.keys(headers)) if (/^proxy-/i.test(name)) delete headers[name];
    const upstream = httpRequest({ host: route.address, port: route.port, method: req.method, path: `${url.pathname}${url.search}`, headers }, (reply) => {
      res.writeHead(reply.statusCode ?? 502, reply.headers);
      reply.pipe(res);
    });
    upstream.on('error', () => res.destroy());
    req.pipe(upstream);
  }

  async close(): Promise<void> {
    for (const socket of this.#sockets) socket.destroy();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
  }
}
