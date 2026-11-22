import assert from 'node:assert/strict';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { signPolicyTree, signRoster } from '@hn/security';
import { loadTeamLogin, runLoginCommand, runTrustCommand, sessionPolicy } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';
import { baseTree, startTeam, type Team } from '../../broker/test/fixture.ts';

/** The policy key rotates, leaks and is revoked while a broker and a laptop run (Phase 15, task 5). */

const pair = (): { priv: KeyObject; pem: string } => {
  const made = generateKeyPairSync('ed25519');
  return { priv: made.privateKey, pem: made.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};
const root = pair();
const rootInfo = { keyId: 'root-1', publicKey: root.pem };

const pol = (team: Team): string => join(team.dir, 'policy.json');
const roster = (serial: number, keys: Record<string, string>, revoked: string[] = [], by = root.priv, id = 'root-1') =>
  signRoster({ format: 1, purpose: 'policy', serial, issued: '2026-11-22T00:00:00Z', keys: Object.entries(keys).map(([keyId, publicKey]) => ({ keyId, publicKey })), revoked: revoked.map((keyId) => ({ keyId, reason: 'leaked' })) }, id, by);

async function login(team: Team, home: string): Promise<void> {
  team.idp.user = { sub: 'sub-ana', email: 'ana@example.com', department: 'eng', groups: ['dev'] };
  const code = await runLoginCommand({
    positionals: ['login', team.broker.url],
    home,
    out: (text) => {
      const match = /enter the code ([A-F0-9]+)/.exec(text);
      if (match !== null) team.idp.decide(match[1] as string, true);
    },
    wait: async () => undefined,
  });
  assert.equal(code, 0);
}

const policyFor = async (home: string): Promise<string> => {
  const result = await sessionPolicy({ team: await loadTeamLogin(home) }, home, `s-${Math.random().toString(16).slice(2)}`);
  return result.policy.layers.map((layer) => layer.name).join(',');
};

describe('a team policy key rotates and is revoked', () => {
  it('a key added by roster reaches a laptop that was already logged in', { timeout: 60_000 }, async () => {
    const team = await startTeam({ policyRoot: rootInfo });
    try {
      await withTempDir(async (home) => {
        await login(team, home);
        assert.deepEqual((JSON.parse(await readFile(join(home, 'team.json'), 'utf8')) as { policyRoot: unknown }).policyRoot, rootInfo);
        assert.match(await policyFor(home), /org/);
        const second = pair();
        const org1 = (await (await team.raw('/v1/trust/policy', {})).json()) as Record<string, unknown>;
        assert.deepEqual(org1, {}, 'no roster yet');
        // The operator signs the next policy with a new key. Without a roster nobody trusts it.
        await team.setPolicyWith(baseTree({ serial: 2 }), 'org-2', second.priv).then(() => assert.fail('the broker must refuse a key it does not trust'), (error: unknown) => assert.match(String(error), /not one this machine trusts/));
        await team.setRoster(roster(1, { 'org-1': orgPem(team), 'org-2': second.pem }));
        await team.setPolicyWith(baseTree({ serial: 2 }), 'org-2', second.priv);
        // The laptop has never been told about org-2 except through the broker's roster.
        const saved = JSON.parse(await readFile(join(home, 'team.json'), 'utf8')) as { policyKeys: Record<string, string> };
        assert.deepEqual(Object.keys(saved.policyKeys), ['org-1']);
        assert.match(await policyFor(home), /org/);
      });
    } finally {
      await team.close();
    }
  });

  it('attack: revoked_policy_key_refused - a leaked key signs a looser policy: accepted before the revoke, refused by the broker and the laptop after', { timeout: 60_000 }, async () => {
    const team = await startTeam({ policyRoot: rootInfo });
    try {
      await withTempDir(async (home) => {
        await login(team, home);
        const second = pair();
        await team.setRoster(roster(1, { 'org-1': orgPem(team), 'org-2': second.pem }));
        await team.setPolicyWith(baseTree({ serial: 2 }), 'org-2', second.priv);
        assert.match(await policyFor(home), /org/);
        // org-1 leaks. The attacker signs a policy with a high serial and drops the restrictions.
        const loose = baseTree({ serial: 99, org: { version: 1, name: 'attacker' } });
        await writeFile(pol(team), JSON.stringify(signPolicyTree(loose, 'org-1', team.signer)));
        assert.match(await policyFor(home), /attacker/, 'before the revoke the laptop would follow it');
        // The owner revokes org-1 with the root key and puts a good policy back.
        await team.setPolicyWith(baseTree({ serial: 100 }), 'org-2', second.priv);
        await team.setRoster(roster(2, { 'org-2': second.pem }, ['org-1']));
        await writeFile(pol(team), JSON.stringify(signPolicyTree(loose, 'org-1', team.signer)));
        await assert.rejects(policyFor(home), /revoked/);
        // The broker refuses to load it too, and keeps the policy it had.
        await assert.rejects(team.broker.reloadPolicy(), /revoked/);
      });
    } finally {
      await team.close();
    }
  });

  it('attack: policy_roster_other_root_refused - refuses a roster that is older, signed by a signing key, or signed by a root the laptop did not pin', { timeout: 60_000 }, async () => {
    const team = await startTeam({ policyRoot: rootInfo });
    try {
      await withTempDir(async (home) => {
        await login(team, home);
        const second = pair();
        await team.setRoster(roster(5, { 'org-1': orgPem(team), 'org-2': second.pem }));
        await assert.rejects(team.setRoster(roster(4, { 'org-1': orgPem(team) })), /older than serial 5/);
        await assert.rejects(team.setRoster(roster(6, { 'org-1': orgPem(team), 'org-2': second.pem }, [], team.signer, 'org-1')), /not the root this machine pins/);
        // The laptop pinned a different root than the one this broker now signs with.
        const file = join(home, 'team.json');
        const saved = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
        await writeFile(file, JSON.stringify({ ...saved, policyRoot: { keyId: 'root-9', publicKey: pair().pem } }));
        await assert.rejects(policyFor(home), /key roster was refused.*not the root this machine pins/);
      });
    } finally {
      await team.close();
    }
  });

  it('attack: policy_root_not_taken_from_known_broker - does not take a root from a broker it is already logged in to, and a broker with no root changes nothing', { timeout: 60_000 }, async () => {
    const withRoot = await startTeam({ policyRoot: rootInfo });
    const without = await startTeam();
    try {
      await withTempDir(async (home) => {
        await login(without, home);
        assert.equal((JSON.parse(await readFile(join(home, 'team.json'), 'utf8')) as { policyRoot?: unknown }).policyRoot, undefined);
        assert.match(await policyFor(home), /org/);
        assert.deepEqual(await (await without.raw('/v1/trust/policy', {})).json(), {});
        // Logging in again to the same broker never adds a root: the first login is the only moment one is taken.
        await login(without, home);
        assert.equal((JSON.parse(await readFile(join(home, 'team.json'), 'utf8')) as { policyRoot?: unknown }).policyRoot, undefined);
      });
      await withTempDir(async (home) => {
        await login(withRoot, home);
        await login(withRoot, home);
        assert.deepEqual((JSON.parse(await readFile(join(home, 'team.json'), 'utf8')) as { policyRoot: unknown }).policyRoot, rootInfo);
        // A laptop that pinned no root cannot be given one by logging in again to the same broker.
        const file = join(home, 'team.json');
        const saved = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
        delete saved['policyRoot'];
        await writeFile(file, JSON.stringify(saved));
        await login(withRoot, home);
        assert.equal((JSON.parse(await readFile(file, 'utf8')) as { policyRoot?: unknown }).policyRoot, undefined);
      });
    } finally {
      await withRoot.close();
      await without.close();
    }
  });

  it('hn trust shows the policy keys and applies a roster for them', { timeout: 60_000 }, async () => {
    const team = await startTeam({ policyRoot: rootInfo });
    try {
      await withTempDir(async (home) => {
        await login(team, home);
        const second = pair();
        let text = '';
        const env = { HN_HOME: home };
        await writeFile(join(home, 'r.json'), JSON.stringify(roster(1, { 'org-1': orgPem(team), 'org-2': second.pem })));
        await runTrustCommand({ positionals: ['trust', 'update', join(home, 'r.json')], env, out: (chunk) => void (text += chunk) });
        assert.match(text, /Applied the policy roster \(serial 1\)/);
        assert.match(text, /trusted: org-2/);
        text = '';
        await runTrustCommand({ positionals: ['trust', 'show'], purpose: 'policy', env, out: (chunk) => void (text += chunk) });
        assert.match(text, /policy: roster serial 1/);
      });
    } finally {
      await team.close();
    }
  });
});

function orgPem(team: Team): string {
  const config = (team.broker.context.config.policy.keys as Record<string, string>)['org-1'];
  return config as string;
}
