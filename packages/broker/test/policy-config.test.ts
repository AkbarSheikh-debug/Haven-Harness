import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import { BrokerConfigError, parseBrokerConfig } from '@hn/broker';

const pem = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
const base = (policy: Record<string, unknown>): Record<string, unknown> => ({
  url: 'http://127.0.0.1:7777',
  listen: { host: '127.0.0.1', port: 0 },
  state: process.platform === 'win32' ? 'C:/hn-state' : '/tmp/hn-state',
  oidc: { issuer: 'https://idp.example.com', clientId: 'c', claims: { user: 'email' } },
  policy: { bundle: 'policy.json', keys: { 'org-1': pem }, ...policy },
  upstreams: [{ name: 'u', kind: 'anthropic', models: ['claude-*'] }],
});

describe('the broker config for a policy root', () => {
  it('takes a root and defaults the roster file into the state folder', () => {
    const config = parseBrokerConfig(base({ root: { keyId: 'root-1', publicKey: pem } }), {});
    assert.equal(config.policy.root?.keyId, 'root-1');
    assert.match(config.policy.roster ?? '', /policy-roster\.json$/);
  });

  it('has no root and no roster by default', () => {
    const config = parseBrokerConfig(base({}), {});
    assert.equal(config.policy.root, undefined);
    assert.equal(config.policy.roster, undefined);
  });

  it('refuses a roster without a root, and a root with extra or missing fields', () => {
    assert.throws(() => parseBrokerConfig(base({ roster: 'r.json' }), {}), BrokerConfigError);
    assert.throws(() => parseBrokerConfig(base({ root: { keyId: 'r' } }), {}), BrokerConfigError);
    assert.throws(() => parseBrokerConfig(base({ root: { keyId: 'r', publicKey: pem, extra: 1 } }), {}), BrokerConfigError);
  });
});
