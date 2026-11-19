import { BlockList, isIP } from 'node:net';
import { networkInterfaces } from 'node:os';

/**
 * Egress policy (8.8.5). `web_fetch`, `web_search` and MCP are external: they run outside the box, so "network
 * off" does not remove them as a way out. This is the part that needs no network: the checks made before a
 * name is resolved, the ranges an address may never be in, and the limits that apply once untrusted text is in
 * the session. The checks after resolving, and the connection itself, are in `operations/src/web.ts`.
 */

const BLOCKED = new BlockList();
const v4 = (net: string, prefix: number): void => BLOCKED.addSubnet(net, prefix, 'ipv4');
const v6 = (net: string, prefix: number): void => BLOCKED.addSubnet(net, prefix, 'ipv6');
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  v4(net, prefix);
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  v6(net, prefix);
}

/** The IPv4 address hidden inside an IPv6 one (`::ffff:127.0.0.1`, `64:ff9b::7f00:1`), or null. */
function embeddedV4(address: string): string | null {
  const text = address.toLowerCase();
  const dotted = /^(?:::ffff:|::)(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (dotted !== null) return dotted[1] ?? null;
  const hex = /^(?:::ffff:|64:ff9b::|::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(text);
  if (hex === null) return null;
  const high = Number.parseInt(hex[1] as string, 16);
  const low = Number.parseInt(hex[2] as string, 16);
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
}

let localCache: { readonly at: number; readonly addresses: ReadonlySet<string> } | null = null;

/**
 * Every address this machine holds, public ones included. A public IPv6 address of this machine (or one a VPN gives it)
 * is not in any private range, yet a connection to it reaches every server here that listens on all interfaces.
 */
function localAddresses(): ReadonlySet<string> {
  const now = Date.now();
  if (localCache !== null && now - localCache.at < 5_000) return localCache.addresses;
  const addresses = new Set<string>();
  for (const list of Object.values(networkInterfaces())) {
    for (const entry of list ?? []) addresses.add(entry.address.toLowerCase().replace(/%.*$/, ''));
  }
  localCache = { at: now, addresses };
  return addresses;
}

/** Why an address may never be connected to, or null if it is an ordinary public address. */
export function blockedAddress(address: string): string | null {
  const kind = isIP(address);
  if (kind === 0) return `${address} is not an address`;
  if (kind === 6) {
    const inner = embeddedV4(address);
    if (inner !== null && BLOCKED.check(inner, 'ipv4')) return `${address} wraps the private address ${inner}`;
  }
  if (BLOCKED.check(address, kind === 4 ? 'ipv4' : 'ipv6')) {
    if (address === '169.254.169.254' || address.toLowerCase() === 'fd00:ec2::254') return `${address} is a cloud metadata address`;
    return `${address} is a private, loopback, link-local or reserved address`;
  }
  // Checked after the ranges, so a loopback address is still named as one.
  if (localAddresses().has(address.toLowerCase())) return `${address} is an address of this machine`;
  return null;
}

export interface UrlOptions {
  /** `http` is refused unless this is set. Off by default. */
  readonly allowHttp?: boolean;
  readonly allowedPorts?: readonly number[];
  /** Hosts or suffixes that are never reachable. */
  readonly denyHosts?: readonly string[];
  /** When set, only these hosts or suffixes are reachable. */
  readonly allowHosts?: readonly string[];
}

export type UrlVerdict = { readonly ok: true; readonly url: URL } | { readonly ok: false; readonly reason: string };

const LOCAL_SUFFIXES = ['.localhost', '.local', '.internal', '.lan', '.home', '.home.arpa', '.corp', '.intranet', '.private', '.localdomain', '.svc'];
const MAX_HOST_CHARS = 100;
const MAX_LABEL_CHARS = 40;
const MAX_URL_CHARS = 2_048;

const deny = (reason: string): UrlVerdict => ({ ok: false, reason });
const matches = (host: string, entry: string): boolean => host === entry || host.endsWith(`.${entry}`);

/**
 * Everything that can be decided about a URL before any name is looked up, so a hostname that carries
 * stolen data (`<secret>.evil.com`) never reaches a resolver.
 */
export function checkUrl(raw: string, options: UrlOptions = {}): UrlVerdict {
  if (raw.length > MAX_URL_CHARS) return deny(`The URL is longer than ${MAX_URL_CHARS} characters.`);
  if (/[\u0000-\u001f\u007f\s]/.test(raw)) return deny('The URL contains spaces or control characters.');
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return deny('That is not a valid URL.');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && options.allowHttp === true)) {
    return deny(url.protocol === 'http:' ? 'Plain http is not allowed. Use https.' : `The scheme ${url.protocol} is not allowed. Only https is.`);
  }
  if (url.username !== '' || url.password !== '') return deny('URLs with a username or password are not allowed.');
  const port = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port);
  const ports = options.allowedPorts ?? (options.allowHttp === true ? [80, 443] : [443]);
  if (!ports.includes(port)) return deny(`Port ${port} is not allowed.`);

  // The URL parser has already turned 2130706433, 0x7f.1 and [::ffff:7f00:1] into their canonical forms.
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (host === '') return deny('The URL has no host.');
  const ip = isIP(host);
  if (ip !== 0) {
    const blocked = blockedAddress(host);
    return blocked === null ? checkAllowList(url, host, options) : deny(`Blocked: ${blocked}.`);
  }
  if (!host.includes('.')) return deny(`${host} has no dot, so it would be looked up on the local network.`);
  if (host === 'localhost' || LOCAL_SUFFIXES.some((suffix) => host.endsWith(suffix))) return deny(`${host} is a local-network name.`);
  if (host.length > MAX_HOST_CHARS) return deny('The host name is far longer than any real site, which is how data is smuggled out in a name.');
  if (host.split('.').some((label) => label.length > MAX_LABEL_CHARS)) return deny('A part of the host name is far longer than any real site uses, which is how data is smuggled out in a name.');
  if (options.denyHosts?.some((entry) => matches(host, entry.toLowerCase())) === true) return deny(`${host} is on the deny list.`);
  return checkAllowList(url, host, options);
}

function checkAllowList(url: URL, host: string, options: UrlOptions): UrlVerdict {
  if (options.allowHosts !== undefined && !options.allowHosts.some((entry) => matches(host, entry.toLowerCase()))) return deny(`${host} is not on the allow list.`);
  return { ok: true, url };
}

/** The same URL spelt the same way, so "exact" means exact. Fragments never reach a server, so they are dropped. */
export function canonicalUrl(url: URL): string {
  const copy = new URL(url.href);
  copy.hash = '';
  return copy.href;
}

const URLS_IN_TEXT = /https?:\/\/[^\s<>"'`)\]}]+/gi;

export interface EgressOptions extends UrlOptions {
  /** True once all three legs of the Rule of Two hold: untrusted text, private data, and a way out. */
  readonly tainted?: () => boolean;
  readonly perHostPerDay?: number;
  /** How many URLs that did not come from the user may be fetched in one session while tainted. */
  readonly maxDerived?: number;
  readonly now?: () => number;
}

export type EgressDecision = { readonly ok: true } | { readonly ok: false; readonly reason: string };

/**
 * The limits that apply on top of the URL checks. Under taint a fetch may only reach a URL the user typed,
 * exactly as typed, with nothing appended, because a path or query is where stolen data goes. Every host has a
 * daily budget, and fetches of URLs taken from earlier responses are capped.
 */
export class EgressPolicy {
  readonly #options: EgressOptions;
  readonly #userUrls = new Set<string>();
  readonly #hosts = new Map<string, number[]>();
  #derived = 0;

  constructor(options: EgressOptions = {}) {
    this.#options = options;
  }

  /** Call with text a human typed. Only URLs found here count as the user's. */
  noteUserText(text: string): void {
    for (const match of text.matchAll(URLS_IN_TEXT)) {
      const cleaned = match[0].replace(/[.,;:!?]+$/, '');
      // A URL the user typed is held to the same ports as any other. It is only exempt from the https-only rule here,
      // because that rule is applied again when the request is made.
      const verdict = checkUrl(cleaned, { ...this.#options, allowHttp: true, allowedPorts: this.#options.allowedPorts ?? [80, 443] });
      if (verdict.ok) this.#userUrls.add(canonicalUrl(verdict.url));
    }
  }

  /** A URL a person approved, shown in full on a card. It counts as the user's for the rest of the session. */
  grant(url: URL): void {
    this.#userUrls.add(canonicalUrl(url));
  }

  /** Whether this URL may be requested now. `redirect` hops are held to the same rules as the first request. */
  decide(url: URL): EgressDecision {
    const exact = this.#userUrls.has(canonicalUrl(url));
    const tainted = this.#options.tainted?.() === true;
    if (tainted && !exact) {
      return { ok: false, reason: 'This session has read untrusted text and holds private data, so it may only fetch a URL you typed, exactly as typed. Ask the user for the URL.' };
    }
    const now = (this.#options.now ?? Date.now)();
    const recent = (this.#hosts.get(url.hostname) ?? []).filter((time) => now - time < 24 * 60 * 60 * 1000);
    const budget = this.#options.perHostPerDay ?? 20;
    if (recent.length >= budget) return { ok: false, reason: `${url.hostname} has been fetched ${budget} times in the last day, which is the daily limit.` };
    if (!exact && this.#derived >= (this.#options.maxDerived ?? 20)) {
      return { ok: false, reason: 'Too many URLs taken from earlier responses have been fetched in this session. Ask the user for the next one.' };
    }
    return { ok: true };
  }

  /** Call once a request is actually made, so refused requests do not use the budget. */
  record(url: URL): void {
    const now = (this.#options.now ?? Date.now)();
    const recent = (this.#hosts.get(url.hostname) ?? []).filter((time) => now - time < 24 * 60 * 60 * 1000);
    recent.push(now);
    this.#hosts.set(url.hostname, recent);
    if (!this.#userUrls.has(canonicalUrl(url))) this.#derived += 1;
  }
}
