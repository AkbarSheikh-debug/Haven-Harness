import { createPublicKey, verify, constants, type KeyObject } from 'node:crypto';
import { HnError } from '@hn/core';
import type { Identity } from './policy.ts';

/**
 * Checking an OpenID Connect ID token. Only the broker calls this: it is the relying party,
 * and the token never reaches the laptop. Everything a token says about itself is distrusted until its signature is
 * checked against a key the issuer published, so the header can name an algorithm but cannot choose one: only the
 * three on the list are accepted, each only with the key type it needs, and `none` or a shared-secret algorithm
 * (the classic swap of RS256 for HS256 keyed with the public key) is refused before anything else is read.
 */

export class OidcError extends HnError {
  constructor(message: string) {
    super('OIDC_INVALID', message);
  }
}

export const OIDC_ALGORITHMS = ['RS256', 'ES256', 'EdDSA'] as const;
export type OidcAlgorithm = (typeof OIDC_ALGORITHMS)[number];

/** One published key, as JSON Web Key Set entries are written. Only the fields the check reads. */
export interface Jwk {
  readonly kty: string;
  readonly kid?: string;
  readonly use?: string;
  readonly alg?: string;
  readonly [field: string]: unknown;
}

export interface IdTokenExpectations {
  /** The issuer exactly as configured: no trailing-slash or case games. */
  readonly issuer: string;
  /** This broker's client id at the issuer. */
  readonly audience: string;
  readonly now: number;
  /** Clock difference allowed either way, in seconds. */
  readonly skewSeconds?: number;
  /** A token that claims to live longer than this is refused, whatever its signature. */
  readonly maxLifetimeSeconds?: number;
}

export interface IdTokenClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string | readonly string[];
  readonly exp: number;
  readonly iat: number;
  readonly [claim: string]: unknown;
}

const MAX_TOKEN_BYTES = 16 * 1024;
const PART = /^[A-Za-z0-9_-]+$/;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

function decodeJson(part: string, what: string): Record<string, unknown> {
  if (!PART.test(part)) throw new OidcError(`The token's ${what} is not base64url.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    throw new OidcError(`The token's ${what} is not JSON.`);
  }
  if (!isRecord(parsed)) throw new OidcError(`The token's ${what} is not an object.`);
  return parsed;
}

/** The key object for one JWK, refused unless its type fits the algorithm. A small RSA key is refused too. */
function keyFor(jwk: Jwk, alg: OidcAlgorithm): KeyObject {
  if (jwk.use !== undefined && jwk.use !== 'sig') throw new OidcError('The issuer marked this key for something other than signatures.');
  if (jwk.alg !== undefined && jwk.alg !== alg) throw new OidcError(`The key is for ${String(jwk.alg)}, but the token says ${alg}.`);
  const wanted = alg === 'RS256' ? 'RSA' : alg === 'ES256' ? 'EC' : 'OKP';
  if (jwk.kty !== wanted) throw new OidcError(`${alg} needs a ${wanted} key, and this one is ${String(jwk.kty)}.`);
  if (alg === 'ES256' && jwk['crv'] !== 'P-256') throw new OidcError('ES256 needs a P-256 key.');
  if (alg === 'EdDSA' && jwk['crv'] !== 'Ed25519') throw new OidcError('EdDSA is accepted only with Ed25519.');
  // Only the public parts go in, so a set that carries a private part by mistake is not turned into a private key.
  const pick = (names: readonly string[]): Record<string, unknown> => Object.fromEntries(names.map((name) => [name, jwk[name]]));
  const fields = wanted === 'RSA' ? pick(['kty', 'n', 'e']) : pick(['kty', 'crv', 'x', ...(wanted === 'EC' ? ['y'] : [])]);
  let key: KeyObject;
  try {
    key = createPublicKey({ key: fields as never, format: 'jwk' });
  } catch {
    throw new OidcError('The issuer published a key that cannot be read.');
  }
  if (alg === 'RS256' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new OidcError('The RSA key is shorter than 2048 bits.');
  return key;
}

/** Picks the key the header names. Without a `kid` a single key is used only when the set holds exactly one. */
export function selectKey(keys: readonly Jwk[], kid: string | undefined): Jwk | null {
  if (kid === undefined) return keys.length === 1 ? (keys[0] ?? null) : null;
  const matches = keys.filter((key) => key.kid === kid);
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

/** What the header says, read before the signature only to choose the key. Nothing in it is trusted. */
export function tokenHeader(token: string): { readonly alg: OidcAlgorithm; readonly kid?: string } {
  if (Buffer.byteLength(token) > MAX_TOKEN_BYTES) throw new OidcError('The token is too large.');
  const parts = token.split('.');
  if (parts.length !== 3) throw new OidcError('A signed token has exactly three parts.');
  const header = decodeJson(parts[0] as string, 'header');
  const alg = header['alg'];
  if (typeof alg !== 'string' || !(OIDC_ALGORITHMS as readonly string[]).includes(alg)) throw new OidcError(`The algorithm ${JSON.stringify(alg)} is not accepted. Only ${OIDC_ALGORITHMS.join(', ')}.`);
  if (header['crit'] !== undefined) throw new OidcError('The token marks header fields as critical, and none are understood.');
  const kid = header['kid'];
  if (kid !== undefined && typeof kid !== 'string') throw new OidcError('The key id is not a string.');
  return { alg: alg as OidcAlgorithm, ...(kid === undefined ? {} : { kid }) };
}

/**
 * Checks the signature with the issuer's keys, then the claims: issuer, audience (and `azp` when there are several
 * audiences), expiry, issue time, not-before, and a lifetime cap. Returns the claims only when every check passed.
 */
export function verifyIdToken(token: string, keys: readonly Jwk[], expect: IdTokenExpectations): IdTokenClaims {
  const { alg, kid } = tokenHeader(token);
  const [headerPart, payloadPart, signaturePart] = token.split('.') as [string, string, string];
  const jwk = selectKey(keys, kid);
  if (jwk === null) throw new OidcError(kid === undefined ? 'The token names no key, and the issuer has more than one.' : `The issuer has no single key with id ${JSON.stringify(kid)}.`);
  const key = keyFor(jwk, alg);
  if (!PART.test(signaturePart)) throw new OidcError('The signature is not base64url.');
  const data = Buffer.from(`${headerPart}.${payloadPart}`);
  const signature = Buffer.from(signaturePart, 'base64url');
  const good =
    alg === 'RS256'
      ? verify('sha256', data, { key, padding: constants.RSA_PKCS1_PADDING }, signature)
      : alg === 'ES256'
        ? verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature)
        : verify(null, data, key, signature);
  if (!good) throw new OidcError('The signature does not match, so the token was changed or not signed by the issuer.');

  const claims = decodeJson(payloadPart, 'payload');
  const skew = expect.skewSeconds ?? 60;
  const now = Math.floor(expect.now / 1000);
  if (claims['iss'] !== expect.issuer) throw new OidcError('The token was issued by someone else.');
  const aud = claims['aud'];
  const audiences = typeof aud === 'string' ? [aud] : Array.isArray(aud) && aud.every((item) => typeof item === 'string') ? (aud as string[]) : null;
  if (audiences === null || !audiences.includes(expect.audience)) throw new OidcError('The token was issued for a different client.');
  if (audiences.length > 1 && claims['azp'] !== expect.audience) throw new OidcError('The token has several audiences and was not issued to this client.');
  if (claims['azp'] !== undefined && claims['azp'] !== expect.audience) throw new OidcError('The token was issued to a different client.');
  for (const name of ['exp', 'iat'] as const) if (typeof claims[name] !== 'number' || !Number.isFinite(claims[name])) throw new OidcError(`The token has no ${name}.`);
  const exp = claims['exp'] as number;
  const iat = claims['iat'] as number;
  if (exp <= now - skew) throw new OidcError('The token has expired.');
  if (iat > now + skew) throw new OidcError('The token says it was issued in the future.');
  if (claims['nbf'] !== undefined && (typeof claims['nbf'] !== 'number' || claims['nbf'] > now + skew)) throw new OidcError('The token is not valid yet.');
  if (exp - iat > (expect.maxLifetimeSeconds ?? 24 * 3600)) throw new OidcError('The token claims a longer life than this broker accepts.');
  if (typeof claims['sub'] !== 'string' || claims['sub'] === '') throw new OidcError('The token names no subject.');
  return claims as IdTokenClaims;
}

/** Which claims hold the person's name, team path and roles. Configured by the operator, never by the token. */
export interface ClaimMapping {
  /** Usually `email`, `preferred_username` or `sub`. */
  readonly user: string;
  /** A claim holding `a/b/c` or `["a","b","c"]`. Missing means no OU. */
  readonly ou?: string;
  /** A claim holding a list of role or group names. Missing means no roles. */
  readonly roles?: string;
}

const NAME = /^[^\u0000-\u001f\u007f-\u009f/\\]{1,200}$/;
const ROLE = /^[^\u0000-\u001f\u007f-\u009f]{1,200}$/;

/** The identity a verified token speaks for. A value with control characters or slashes is refused, not cleaned. */
export function identityFromClaims(claims: IdTokenClaims, mapping: ClaimMapping): Identity {
  const user = claims[mapping.user];
  if (typeof user !== 'string' || !ROLE.test(user)) throw new OidcError(`The token has no usable ${mapping.user} claim for the user name.`);
  let ou: string[] = [];
  if (mapping.ou !== undefined && claims[mapping.ou] !== undefined) {
    const raw = claims[mapping.ou];
    const parts = typeof raw === 'string' ? raw.split('/').filter((part) => part !== '') : Array.isArray(raw) ? raw : null;
    if (parts === null || parts.length > 16 || !parts.every((part) => typeof part === 'string' && NAME.test(part))) throw new OidcError(`The ${mapping.ou} claim is not an OU path.`);
    ou = parts as string[];
  }
  let roles: string[] = [];
  if (mapping.roles !== undefined && claims[mapping.roles] !== undefined) {
    const raw = claims[mapping.roles];
    if (!Array.isArray(raw) || raw.length > 256 || !raw.every((role) => typeof role === 'string' && ROLE.test(role))) throw new OidcError(`The ${mapping.roles} claim is not a list of names.`);
    roles = [...new Set(raw as string[])].sort();
  }
  return { user, ou, roles };
}
