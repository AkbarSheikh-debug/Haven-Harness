import { HnError } from '@hn/core';
import { OidcError, identityFromClaims, tokenHeader, selectKey, verifyIdToken, type ClaimMapping, type Identity, type Jwk } from '@hn/security';

/**
 * The broker's side of OpenID Connect: it reads the issuer's discovery document, keeps its key set, runs the device
 * flow (RFC 8628) and checks the ID token it gets back. The issuer is configured by the operator, never by a
 * client, and every endpoint the discovery document names must be https on the issuer's own origin (plain http is
 * accepted only for a loopback issuer, which is how tests run).
 */

export interface OidcConfig {
  readonly issuer: string;
  readonly clientId: string;
  /** Only for a confidential client. Held by the broker; sent only to the issuer's token endpoint. */
  readonly clientSecret?: string;
  readonly claims: ClaimMapping;
  readonly scope?: string;
}

interface Discovery {
  readonly jwksUri: string;
  readonly deviceEndpoint: string;
  readonly tokenEndpoint: string;
}

export interface DeviceStart {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly expiresAt: number;
  readonly interval: number;
}

export type DevicePoll =
  | { readonly state: 'pending'; readonly interval: number }
  | { readonly state: 'done'; readonly identity: Identity; readonly subject: string }
  | { readonly state: 'failed'; readonly reason: string };

const MAX_BODY = 256 * 1024;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

const loopback = (url: URL): boolean => url.hostname === '127.0.0.1' || url.hostname === '[::1]' || url.hostname === 'localhost';

/** An endpoint must sit on the issuer's own origin, over https unless the issuer itself is a loopback test server. */
function checkEndpoint(value: unknown, issuer: URL, name: string): string {
  if (typeof value !== 'string') throw new OidcError(`The issuer's discovery document has no ${name}.`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OidcError(`The issuer's ${name} is not a URL.`);
  }
  if (url.origin !== issuer.origin) throw new OidcError(`The issuer's ${name} is on another origin (${url.origin}).`);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback(url))) throw new OidcError(`The issuer's ${name} is not https.`);
  return url.href;
}

async function readJson(response: Response, what: string): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (Buffer.byteLength(text) > MAX_BODY) throw new OidcError(`The issuer's ${what} answer is too large.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new OidcError(`The issuer's ${what} answer is not JSON.`);
  }
  if (!isRecord(parsed)) throw new OidcError(`The issuer's ${what} answer is not an object.`);
  return parsed;
}

export class OidcClient {
  readonly #config: OidcConfig;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  #discovery: Discovery | null = null;
  #keys: readonly Jwk[] = [];
  #keysFetchedAt = 0;

  constructor(config: OidcConfig, options: { fetch?: typeof fetch; now?: () => number } = {}) {
    const issuer = new URL(config.issuer);
    if (issuer.protocol !== 'https:' && !(issuer.protocol === 'http:' && loopback(issuer))) throw new OidcError('The issuer must be https.');
    this.#config = config;
    this.#fetch = options.fetch ?? fetch;
    this.#now = options.now ?? Date.now;
  }

  async #discover(): Promise<Discovery> {
    if (this.#discovery !== null) return this.#discovery;
    const issuer = new URL(this.#config.issuer);
    const base = this.#config.issuer.endsWith('/') ? this.#config.issuer.slice(0, -1) : this.#config.issuer;
    const response = await this.#fetch(`${base}/.well-known/openid-configuration`, { redirect: 'error' });
    if (!response.ok) throw new OidcError(`The issuer's discovery document answered ${response.status}.`);
    const doc = await readJson(response, 'discovery');
    // The document must name exactly the issuer configured, or tokens could be checked against the wrong one.
    if (doc['issuer'] !== this.#config.issuer) throw new OidcError('The discovery document names a different issuer.');
    this.#discovery = {
      jwksUri: checkEndpoint(doc['jwks_uri'], issuer, 'jwks_uri'),
      deviceEndpoint: checkEndpoint(doc['device_authorization_endpoint'], issuer, 'device_authorization_endpoint'),
      tokenEndpoint: checkEndpoint(doc['token_endpoint'], issuer, 'token_endpoint'),
    };
    return this.#discovery;
  }

  /** The key set, fetched again when a token names a key we do not hold, but at most once a minute. */
  async #keysFor(kid: string | undefined): Promise<readonly Jwk[]> {
    const stale = selectKey(this.#keys, kid) === null && this.#now() - this.#keysFetchedAt > 60_000;
    if (this.#keys.length > 0 && !stale) return this.#keys;
    const response = await this.#fetch((await this.#discover()).jwksUri, { redirect: 'error' });
    if (!response.ok) throw new OidcError(`The issuer's key set answered ${response.status}.`);
    const doc = await readJson(response, 'key set');
    const keys = doc['keys'];
    if (!Array.isArray(keys) || keys.length > 64 || !keys.every((key) => isRecord(key) && typeof key['kty'] === 'string')) throw new OidcError('The issuer published no usable key set.');
    this.#keys = keys as Jwk[];
    this.#keysFetchedAt = this.#now();
    return this.#keys;
  }

  /** Checks an ID token and returns the identity it speaks for. */
  async verify(idToken: string): Promise<{ identity: Identity; subject: string }> {
    const keys = await this.#keysFor(tokenHeader(idToken).kid);
    const claims = verifyIdToken(idToken, keys, { issuer: this.#config.issuer, audience: this.#config.clientId, now: this.#now() });
    return { identity: identityFromClaims(claims, this.#config.claims), subject: claims.sub };
  }

  #form(extra: Record<string, string>): URLSearchParams {
    return new URLSearchParams({ client_id: this.#config.clientId, ...(this.#config.clientSecret === undefined ? {} : { client_secret: this.#config.clientSecret }), ...extra });
  }

  /** Starts a device login. The user code and address are shown to the person; the device code stays on the broker. */
  async startDevice(): Promise<DeviceStart> {
    const { deviceEndpoint } = await this.#discover();
    const response = await this.#fetch(deviceEndpoint, { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: this.#form({ scope: this.#config.scope ?? 'openid profile email' }) });
    const doc = await readJson(response, 'device authorization');
    if (!response.ok) throw new OidcError(`The issuer refused the device login: ${String(doc['error'] ?? response.status)}.`);
    const { device_code: deviceCode, user_code: userCode, verification_uri: verificationUri, expires_in: expiresIn, interval } = doc;
    if (typeof deviceCode !== 'string' || typeof userCode !== 'string' || typeof verificationUri !== 'string' || typeof expiresIn !== 'number') throw new OidcError('The device authorization answer is missing a field.');
    if (!/^[A-Za-z0-9-]{4,32}$/.test(userCode)) throw new OidcError('The user code has characters a person should not be asked to type.');
    const where = new URL(verificationUri);
    if (where.protocol !== 'https:' && !(where.protocol === 'http:' && loopback(where))) throw new OidcError('The verification address is not https.');
    return { deviceCode, userCode, verificationUri: where.href, expiresAt: this.#now() + Math.min(expiresIn, 1800) * 1000, interval: typeof interval === 'number' && interval >= 1 ? Math.min(interval, 60) : 5 };
  }

  /** One poll of the token endpoint. `slow_down` adds five seconds, as the RFC says. */
  async pollDevice(start: DeviceStart, interval = start.interval): Promise<DevicePoll> {
    if (this.#now() > start.expiresAt) return { state: 'failed', reason: 'The login code expired.' };
    const { tokenEndpoint } = await this.#discover();
    const response = await this.#fetch(tokenEndpoint, { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: this.#form({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: start.deviceCode }) });
    const doc = await readJson(response, 'token');
    if (!response.ok) {
      const error = doc['error'];
      if (error === 'authorization_pending') return { state: 'pending', interval };
      if (error === 'slow_down') return { state: 'pending', interval: interval + 5 };
      return { state: 'failed', reason: error === 'access_denied' ? 'The login was refused.' : error === 'expired_token' ? 'The login code expired.' : 'The issuer refused the login.' };
    }
    if (typeof doc['id_token'] !== 'string') return { state: 'failed', reason: 'The issuer sent no ID token.' };
    try {
      return { state: 'done', ...(await this.verify(doc['id_token'])) };
    } catch (error) {
      return { state: 'failed', reason: error instanceof HnError ? error.message : 'The ID token could not be checked.' };
    }
  }
}
