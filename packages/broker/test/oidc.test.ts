import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { OidcClient } from '@hn/broker';
import { OidcError, identityFromClaims, verifyIdToken, type Jwk } from '@hn/security';
import { makeSigningKey, signJwt, startFakeIdp, type FakeIdp } from '@hn/testkit';

const ISSUER = 'https://idp.example';
const AUD = 'hn-broker';
const now = Date.now();
const secs = Math.floor(now / 1000);
const claims = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({ iss: ISSUER, aud: AUD, sub: 'u-1', iat: secs, exp: secs + 600, email: 'ana@example.com', department: 'eng/platform', groups: ['dev', 'dev', 'lead'], ...extra });
const expect = { issuer: ISSUER, audience: AUD, now };
const refuses = (token: string, keys: readonly Jwk[], pattern: RegExp): void => assert.throws(() => verifyIdToken(token, keys, expect), (error: unknown) => error instanceof OidcError && pattern.test(error.message));
const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

describe('ID token checks', () => {
  for (const alg of ['RS256', 'ES256', 'EdDSA'] as const) {
    it(`accepts a good ${alg} token and maps the identity`, () => {
      const key = makeSigningKey(alg, 'k1');
      const verified = verifyIdToken(signJwt(key, claims()), [key.jwk as Jwk], expect);
      assert.deepEqual(identityFromClaims(verified, { user: 'email', ou: 'department', roles: 'groups' }), { user: 'ana@example.com', ou: ['eng', 'platform'], roles: ['dev', 'lead'] });
    });
  }

  const key = makeSigningKey('RS256', 'k1');
  const keys = [key.jwk as Jwk];

  it('refuses alg none and an empty signature', () => {
    refuses(`${b64({ alg: 'none', kid: 'k1' })}.${b64(claims())}.`, keys, /algorithm/);
  });

  it('refuses HS256 keyed with the public key (algorithm confusion)', () => {
    const head = b64({ alg: 'HS256', kid: 'k1' });
    const body = b64(claims());
    const sig = createHmac('sha256', JSON.stringify(key.jwk)).update(`${head}.${body}`).digest('base64url');
    refuses(`${head}.${body}.${sig}`, keys, /algorithm/);
  });

  it('refuses a token whose kid points at a key of another type', () => {
    const ec = makeSigningKey('ES256', 'k1');
    refuses(signJwt(ec, claims()), keys, /key is for RS256, but the token says ES256/);
    // A key set that leaves `alg` out is still held to the key type the algorithm needs.
    refuses(signJwt(ec, claims()), [{ ...key.jwk, alg: undefined } as unknown as Jwk], /needs a EC key/);
  });

  it('refuses a token signed by another key under the same kid', () => {
    refuses(signJwt(makeSigningKey('RS256', 'k1'), claims()), keys, /signature does not match/);
  });

  it('refuses claims edited after signing', () => {
    const [head, , sig] = signJwt(key, claims()).split('.');
    refuses(`${head}.${b64(claims({ groups: ['admin'] }))}.${sig}`, keys, /signature does not match/);
  });

  it('refuses expired, future, wrong-issuer, wrong-audience, long-lived and subjectless tokens', () => {
    refuses(signJwt(key, claims({ exp: secs - 120, iat: secs - 700 })), keys, /expired/);
    refuses(signJwt(key, claims({ iat: secs + 600, exp: secs + 1200 })), keys, /future/);
    refuses(signJwt(key, claims({ nbf: secs + 600 })), keys, /not valid yet/);
    refuses(signJwt(key, claims({ iss: 'https://idp.example/' })), keys, /someone else/);
    refuses(signJwt(key, claims({ aud: 'other-app' })), keys, /different client/);
    refuses(signJwt(key, claims({ aud: [AUD, 'other-app'] })), keys, /several audiences/);
    refuses(signJwt(key, claims({ azp: 'other-app' })), keys, /different client/);
    refuses(signJwt(key, claims({ exp: secs + 7 * 24 * 3600 })), keys, /longer life/);
    refuses(signJwt(key, claims({ sub: '' })), keys, /no subject/);
  });

  it('refuses a critical header, an unknown kid, an ambiguous key set and an oversized token', () => {
    refuses(signJwt(key, claims(), { crit: ['exp'] }), keys, /critical/);
    refuses(signJwt(key, claims(), { kid: 'nope' }), keys, /no single key/);
    refuses(signJwt(key, claims(), { kid: undefined }), [...keys, makeSigningKey('RS256', 'k2').jwk as Jwk], /names no key/);
    refuses(signJwt(key, claims({ pad: 'x'.repeat(20_000) })), keys, /too large/);
  });

  it('refuses an RSA key shorter than 2048 bits and a key marked for encryption', () => {
    const small = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const weak = { kid: 'k1', alg: 'RS256' as const, privateKey: small.privateKey, jwk: { ...small.publicKey.export({ format: 'jwk' }), kid: 'k1' } };
    refuses(signJwt(weak, claims()), [weak.jwk as Jwk], /2048/);
    refuses(signJwt(key, claims()), [{ ...key.jwk, use: 'enc' } as Jwk], /other than signatures/);
  });

  it('refuses identity claims with control characters or a bad OU path', () => {
    const map = { user: 'email', ou: 'department', roles: 'groups' };
    const check = (extra: Record<string, unknown>): void => assert.throws(() => identityFromClaims(verifyIdToken(signJwt(key, claims(extra)), keys, expect), map), OidcError);
    check({ email: 'ana\u001b[2J@example.com' });
    check({ department: ['eng', 'a/b'] });
    check({ groups: 'dev' });
    check({ email: 42 });
  });
});

describe('the device flow against a provider', () => {
  let idp: FakeIdp;
  before(async () => {
    idp = await startFakeIdp({ alg: 'ES256' });
  });
  after(() => idp.close());

  const client = (): OidcClient => new OidcClient({ issuer: idp.issuer, clientId: idp.clientId, claims: { user: 'email', ou: 'department', roles: 'groups' } });

  it('waits while pending, then returns the identity once the person approves', async () => {
    const oidc = client();
    const start = await oidc.startDevice();
    assert.match(start.userCode, /^[A-F0-9]{8}$/);
    assert.deepEqual(await oidc.pollDevice(start), { state: 'pending', interval: 1 });
    idp.decide(start.userCode, true);
    const done = await oidc.pollDevice(start);
    assert.deepEqual(done, { state: 'done', subject: 'u-1', identity: { user: 'ana@example.com', ou: ['eng', 'platform'], roles: ['dev'] } });
  });

  it('fails when the person refuses', async () => {
    const oidc = client();
    const start = await oidc.startDevice();
    idp.decide(start.userCode, false);
    assert.deepEqual(await oidc.pollDevice(start), { state: 'failed', reason: 'The login was refused.' });
  });

  it('refuses a discovery document that names another issuer or sends keys elsewhere', async () => {
    const lying = (doc: Record<string, unknown>): typeof fetch => (async () => new Response(JSON.stringify(doc))) as typeof fetch;
    const base = { issuer: idp.issuer, jwks_uri: `${idp.issuer}/jwks`, device_authorization_endpoint: `${idp.issuer}/device`, token_endpoint: `${idp.issuer}/token` };
    const config = { issuer: idp.issuer, clientId: idp.clientId, claims: { user: 'email' } };
    await assert.rejects(new OidcClient(config, { fetch: lying({ ...base, issuer: 'https://evil.example' }) }).startDevice(), /different issuer/);
    await assert.rejects(new OidcClient(config, { fetch: lying({ ...base, jwks_uri: 'https://evil.example/jwks' }) }).startDevice(), /another origin/);
    assert.throws(() => new OidcClient({ ...config, issuer: 'http://idp.example' }), /https/);
  });

  it('checks a token signed by the provider and refuses one signed by anyone else', async () => {
    const oidc = client();
    assert.equal((await oidc.verify(idp.idToken())).identity.user, 'ana@example.com');
    const forged = signJwt(makeSigningKey('ES256', 'k1'), { iss: idp.issuer, aud: idp.clientId, sub: 'u-1', iat: secs, exp: secs + 600, email: 'boss@example.com' });
    await assert.rejects(oidc.verify(forged), /signature does not match/);
  });
});
