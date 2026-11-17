import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { withTempDir } from '@hn/testkit';
import { BLOCKED_IN_CHILDREN, childTools, narrowMode, newNonce, nonceStore, signGrant, verifyGrant, type GrantBody } from '@hn/delegate';
import { MODES, type Mode } from '@hn/security';

const key = randomBytes(32);
const body = (over: Partial<GrantBody> = {}): GrantBody => ({
  v: 1,
  parent: 'parent-1',
  child: 'child-1',
  mode: 'safe',
  allow: [],
  tools: ['read_file', 'edit_file'],
  maxIterations: 40,
  tokenBudget: 100_000,
  role: { name: 'worker', hash: 'h', body: 'You are a worker.' },
  channel: true,
  expires: Date.now() + 60_000,
  nonce: newNonce(),
  ...over,
});

const fresh = () => {
  const used = new Set<string>();
  return async (nonce: string) => (used.has(nonce) ? false : (used.add(nonce), true));
};

describe('capability grants', () => {
  it('verifies a grant signed with the log key, once', async () => {
    const useNonce = fresh();
    const text = signGrant(body(), key);
    const first = await verifyGrant(text, { key, parent: 'parent-1', useNonce });
    assert.equal(first.ok, true);
    const replay = await verifyGrant(text, { key, parent: 'parent-1', useNonce });
    assert.deepEqual(replay, { ok: false, why: 'it was already used' });
  });

  it('refuses a forged, tampered, expired or mis-addressed grant, before believing anything in it', async () => {
    const good = signGrant(body(), key);
    const [payload, signature] = good.split('.') as [string, string];
    const widened = Buffer.from(JSON.stringify({ ...body(), mode: 'yolo' })).toString('base64url');
    const cases: [string, string, RegExp][] = [
      [signGrant(body(), randomBytes(32)), 'parent-1', /signature does not verify/],
      [`${widened}.${signature}`, 'parent-1', /signature does not verify/],
      [`${payload}.${signature}.x`, 'parent-1', /not a grant/],
      [signGrant(body({ expires: Date.now() - 1 }), key), 'parent-1', /expired/],
      [good, 'parent-2', /different parent/],
      [signGrant({ ...body(), extra: 1 } as unknown as GrantBody, key), 'parent-1', /malformed \(unknown field\)/],
      [signGrant(body({ mode: 'godmode' as Mode }), key), 'parent-1', /malformed \(bad mode\)/],
      ['', 'parent-1', /not a grant/],
    ];
    for (const [text, parent, why] of cases) {
      let nonceAsked = false;
      const check = await verifyGrant(text, { key, parent, useNonce: async () => ((nonceAsked = true), true) });
      assert.equal(check.ok, false, String(why));
      assert.match(check.ok ? '' : check.why, why);
      assert.equal(nonceAsked, false, 'a bad grant never spends a nonce');
    }
  });

  it('keeps used nonces on disk, created exclusively, so two children racing with one grant cannot both win', async () => {
    await withTempDir(async (dir) => {
      const store = nonceStore(join(dir, 'used'));
      const nonce = newNonce();
      const results = await Promise.all([store(nonce), store(nonce), store(nonce)]);
      assert.deepEqual(results.filter(Boolean).length, 1);
      assert.equal(await nonceStore(join(dir, 'used'))(nonce), false, 'a new process sees it as used too');
      assert.equal(await store('../escape'), false);
    });
  });
});

describe('narrowing', () => {
  const rank: Record<Mode, number> = { 'read-only': 0, plan: 0, safe: 1, smart: 1, 'accept-edits': 2, 'dont-ask': 3, yolo: 4 };
  const options = { tier: 2, parentAllow: ['write_file', 'bash'], roleTools: null };

  it('never gives a child more than its parent or its role, for every pair of modes', () => {
    for (const parent of MODES) {
      for (const ceiling of MODES) {
        const { mode, allow } = narrowMode(parent, ceiling, options);
        assert.ok(mode !== 'plan' && mode !== 'smart', `${parent}/${ceiling} -> ${mode}`);
        if (parent !== 'yolo' && parent !== 'dont-ask') assert.ok(rank[mode] <= rank[parent], `${parent}/${ceiling} -> ${mode}`);
        assert.ok(rank[mode] <= rank[ceiling], `${parent}/${ceiling} -> ${mode} is above the role`);
        if (mode === 'yolo') assert.fail('no yolo below tier 3');
        if (mode === 'dont-ask') assert.ok(parent === 'dont-ask' || parent === 'yolo', 'only an unattended parent has unattended children');
        if (parent === 'dont-ask') assert.ok(allow.every((name) => options.parentAllow.includes(name)), 'the allowlist only shrinks');
      }
    }
  });

  it('turns plan into read-only, smart into safe, and yolo below tier 3 into edits only', () => {
    assert.equal(narrowMode('plan', 'yolo', options).mode, 'read-only');
    assert.equal(narrowMode('smart', 'yolo', options).mode, 'safe');
    assert.equal(narrowMode('safe', 'yolo', options).mode, 'safe');
    assert.equal(narrowMode('accept-edits', 'yolo', options).mode, 'accept-edits');
    assert.equal(narrowMode('accept-edits', 'safe', options).mode, 'safe');
    assert.deepEqual(narrowMode('yolo', 'yolo', options), { mode: 'dont-ask', allow: ['write_file', 'edit_file'] });
    assert.deepEqual(narrowMode('yolo', 'yolo', { ...options, tier: 3 }), { mode: 'yolo', allow: [] });
    assert.deepEqual(narrowMode('dont-ask', 'yolo', { ...options, roleTools: ['bash', 'read_file'] }), { mode: 'dont-ask', allow: ['bash'] });
    assert.deepEqual(narrowMode('dont-ask', 'safe', options), { mode: 'safe', allow: [] });
  });

  it('gives a child only the parent tools its role lists, and never memory, delegation or asking the user', () => {
    const parent = ['read_file', 'edit_file', 'bash', 'memory', 'subagent', 'ask_user_question', 'workflow', 'grep'];
    assert.deepEqual(childTools(parent, null), ['read_file', 'edit_file', 'bash', 'grep']);
    assert.deepEqual(childTools(parent, ['read_file', 'memory', 'grep', 'nonexistent']), ['read_file', 'grep']);
    for (const name of ['memory', 'subagent', 'ask_user_question', 'workflow', 'run_code']) assert.ok(BLOCKED_IN_CHILDREN.has(name));
  });
});
