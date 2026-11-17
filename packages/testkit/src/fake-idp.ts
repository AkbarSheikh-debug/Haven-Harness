import { generateKeyPairSync, randomBytes, sign, constants, type KeyObject } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * A small OpenID provider for tests: discovery, a key set, device authorization (RFC 8628) and a token endpoint.
 * It signs real tokens with real keys, so the broker's checks run exactly as they would against a real issuer.
 * A test decides when a device code is approved, and can mint any token it likes, forged ones included.
 */

export type FakeAlg = 'RS256' | 'ES256' | 'EdDSA';

export interface SigningKey {
  readonly kid: string;
  readonly alg: FakeAlg;
  readonly privateKey: KeyObject;
  readonly jwk: Record<string, unknown>;
}

export function makeSigningKey(alg: FakeAlg, kid: string): SigningKey {
  const pair = alg === 'RS256' ? generateKeyPairSync('rsa', { modulusLength: 2048 }) : alg === 'ES256' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('ed25519');
  return { kid, alg, privateKey: pair.privateKey, jwk: { ...pair.publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg } };
}

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

/** A compact JWS over any header and claims, signed with the given key. */
export function signJwt(key: SigningKey, claims: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  const head = b64({ alg: key.alg, typ: 'JWT', kid: key.kid, ...header });
  const body = b64(claims);
  const data = Buffer.from(`${head}.${body}`);
  const signature =
    key.alg === 'RS256'
      ? sign('sha256', data, { key: key.privateKey, padding: constants.RSA_PKCS1_PADDING })
      : key.alg === 'ES256'
        ? sign('sha256', data, { key: key.privateKey, dsaEncoding: 'ieee-p1363' })
        : sign(null, data, key.privateKey);
  return `${head}.${body}.${signature.toString('base64url')}`;
}

export interface FakeIdp {
  readonly issuer: string;
  readonly clientId: string;
  readonly keys: SigningKey[];
  /** Claims for the next approved device code. */
  user: Record<string, unknown>;
  /** A fresh token for `user`, as the token endpoint would issue it. */
  idToken(extra?: Record<string, unknown>): string;
  /** Marks the pending device code with this user code as approved (or denied). */
  decide(userCode: string, approved: boolean): void;
  /** Every request the provider saw, as `METHOD path`. */
  readonly seen: string[];
  close(): Promise<void>;
}

interface Pending {
  readonly deviceCode: string;
  state: 'pending' | 'approved' | 'denied';
}

async function form(request: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(chunk as Buffer);
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

export async function startFakeIdp(options: { alg?: FakeAlg; clientId?: string } = {}): Promise<FakeIdp> {
  const keys = [makeSigningKey(options.alg ?? 'RS256', 'k1')];
  const clientId = options.clientId ?? 'hn-broker';
  const pending = new Map<string, Pending>();
  const seen: string[] = [];
  let issuer = '';
  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? '/', issuer);
    seen.push(`${request.method} ${url.pathname}`);
    const json = (status: number, body: unknown): void => {
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    void (async () => {
      if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
        return json(200, { issuer, jwks_uri: `${issuer}/jwks`, device_authorization_endpoint: `${issuer}/device`, token_endpoint: `${issuer}/token`, id_token_signing_alg_values_supported: [keys[0]?.alg] });
      }
      if (request.method === 'GET' && url.pathname === '/jwks') return json(200, { keys: keys.map((key) => key.jwk) });
      if (request.method === 'POST' && url.pathname === '/device') {
        const body = await form(request);
        if (body.get('client_id') !== clientId) return json(400, { error: 'invalid_client' });
        const userCode = randomBytes(4).toString('hex').toUpperCase();
        const deviceCode = randomBytes(16).toString('hex');
        pending.set(userCode, { deviceCode, state: 'pending' });
        return json(200, { device_code: deviceCode, user_code: userCode, verification_uri: `${issuer}/activate`, expires_in: 600, interval: 1 });
      }
      if (request.method === 'POST' && url.pathname === '/token') {
        const body = await form(request);
        if (body.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:device_code' || body.get('client_id') !== clientId) return json(400, { error: 'invalid_grant' });
        const found = [...pending.entries()].find(([, item]) => item.deviceCode === body.get('device_code'));
        if (found === undefined) return json(400, { error: 'expired_token' });
        const [userCode, entry] = found;
        if (entry.state === 'denied') return json(400, { error: 'access_denied' });
        if (entry.state === 'pending') return json(400, { error: 'authorization_pending' });
        pending.delete(userCode);
        return json(200, { access_token: 'opaque', token_type: 'Bearer', id_token: idp.idToken() });
      }
      json(404, { error: 'not_found' });
    })();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const idp: FakeIdp = {
    issuer,
    clientId,
    keys,
    user: { sub: 'u-1', email: 'ana@example.com', department: 'eng/platform', groups: ['dev'] },
    idToken(extra = {}) {
      const now = Math.floor(Date.now() / 1000);
      return signJwt(keys[0] as SigningKey, { iss: issuer, aud: clientId, iat: now, exp: now + 600, ...idp.user, ...extra });
    },
    decide(userCode, approved) {
      const entry = pending.get(userCode);
      if (entry !== undefined) entry.state = approved ? 'approved' : 'denied';
    },
    seen,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
  return idp;
}
