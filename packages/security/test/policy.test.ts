import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import {
  Gate,
  Jail,
  PolicyError,
  PolicySet,
  attenuateCapability,
  loadLocalPolicy,
  mintCapability,
  parsePolicy,
  signPolicy,
  verifyCapability,
  verifySignedPolicy,
  type GateCall,
  type Identity,
  type Policy,
} from '@hn/security';
import { withTempDir } from '@hn/testkit';

const layer = (extra: Record<string, unknown>): Policy => parsePolicy({ version: 1, ...extra });

describe('reading a policy', () => {
  it('accepts a full layer', () => {
    const policy = layer({ name: 'team', tools: { allow: ['read_*'], deny: ['bash'] }, paths: { deny: ['secrets/**'] }, mcp: { allow: ['docs'] }, models: { allow: ['claude-*'] }, maxMode: 'safe', budget: { maxCostUsd: 5, maxTokens: 100000 }, approvers: { roles: ['lead'] } });
    assert.equal(policy.maxMode, 'safe');
    assert.deepEqual(policy.tools?.deny, ['bash']);
  });

  it('refuses anything odd instead of ignoring it, so a typo cannot quietly leave a rule off', () => {
    for (const bad of [null, [], 'x', {}, { version: 2 }, { version: 1, tool: {} }, { version: 1, tools: { alow: [] } }, { version: 1, tools: { allow: 'bash' } }, { version: 1, tools: { allow: [''] } }, { version: 1, maxMode: 'god' }, { version: 1, budget: { maxCostUsd: -1 } }, { version: 1, budget: { maxCostUsd: 'x' } }, { version: 1, paths: { deny: [1] } }, JSON.parse('{"version":1,"__proto__":{"x":1}}'), { version: 1, approvers: { users: ['a'], extra: 1 } }]) {
      assert.throws(() => parsePolicy(bad), PolicyError, JSON.stringify(bad));
    }
  });
});

describe('layers only narrow', () => {
  const tools = ['read_file', 'write_file', 'edit_file', 'bash', 'grep', 'web_fetch', 'mcp__docs__search', 'mcp__evil__run'];

  it('allows a tool only when every layer does, and a deny anywhere wins', () => {
    const set = new PolicySet([layer({ tools: { allow: ['read_*', 'grep', 'bash', 'write_file'] } }), layer({ tools: { deny: ['bash'] } }), layer({ tools: { allow: ['read_*', 'write_file', 'bash'] } })]);
    assert.equal(set.toolReason('read_file'), null);
    assert.equal(set.toolReason('write_file'), null);
    assert.match(set.toolReason('bash') ?? '', /denied by policy/);
    assert.match(set.toolReason('grep') ?? '', /not on the tool list/, 'the third layer does not list grep');
    assert.match(set.toolReason('web_fetch') ?? '', /not on the tool list/);
  });

  it('property: adding a layer never newly allows anything, and the set never allows what one of its layers refuses', () => {
    let seed = 12345;
    const next = (): number => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    const pick = <T>(list: readonly T[]): T => list[Math.floor(next() * list.length)] as T;
    const patterns = ['*', 'read_*', 'write_*', 'bash', 'mcp__*', 'mcp__docs__*', '*_file', 'grep', 'web_*'];
    const randomLayer = (): Policy => {
      const allow = next() < 0.6 ? Array.from({ length: 1 + Math.floor(next() * 3) }, () => pick(patterns)) : undefined;
      const deny = next() < 0.4 ? [pick(patterns)] : undefined;
      return layer({ tools: { ...(allow === undefined ? {} : { allow }), ...(deny === undefined ? {} : { deny }) } });
    };
    for (let round = 0; round < 300; round += 1) {
      const layers = Array.from({ length: 1 + Math.floor(next() * 4) }, randomLayer);
      const extra = randomLayer();
      const base = new PolicySet(layers);
      const more = new PolicySet([...layers, extra]);
      for (const tool of tools) {
        if (base.toolReason(tool) !== null) assert.notEqual(more.toolReason(tool), null, `a layer allowed what the layers above refused: ${tool}`);
        for (const single of layers) if (new PolicySet([single]).toolReason(tool) !== null) assert.notEqual(base.toolReason(tool), null, `the set allowed what one layer refuses: ${tool}`);
      }
    }
  });

  it('treats a pattern as a pattern: no regular expression syntax gets through, and case is ignored', () => {
    const set = new PolicySet([layer({ tools: { allow: ['read_file', 'a.c+'] } })]);
    assert.equal(set.toolReason('READ_FILE'), null);
    assert.notEqual(set.toolReason('read_fileX'), null);
    assert.notEqual(set.toolReason('abc'), null, '"." must not match any character');
    assert.equal(set.toolReason('a.c+'), null);
    // A pattern that looks like a catastrophic regular expression is only literal text, so it is fast and matches only itself.
    const started = Date.now();
    const trap = new PolicySet([layer({ tools: { allow: ['(a+)+$'] } })]);
    assert.notEqual(trap.toolReason(`${'a'.repeat(5000)}!`), null);
    assert.equal(trap.toolReason('(a+)+$'), null);
    assert.ok(Date.now() - started < 500);
  });

  it('denies paths in the way the rules see them: slashes, case and trailing dots', () => {
    const set = new PolicySet([layer({ name: 'org', paths: { deny: ['secrets/**', 'config/prod.*', '*.pem'] } })]);
    for (const path of ['secrets/a.txt', 'Secrets\\deep\\b', './secrets/x', 'secrets./x', 'config/prod.json', 'key.PEM', 'secrets/']) assert.notEqual(set.pathReason(path), null, path);
    for (const path of ['src/secrets.ts', 'config/dev.json', 'docs/readme.md']) assert.equal(set.pathReason(path), null, path);
    assert.match(set.pathReason('secrets/a') ?? '', /denied by policy \(org\)/);
  });

  it('takes the lowest mode, the smallest budget, and needs every layer to list an MCP server or model', () => {
    const set = new PolicySet([layer({ maxMode: 'yolo', budget: { maxCostUsd: 10 }, mcp: { allow: ['docs', 'wiki'] }, models: { allow: ['claude-*'] } }), layer({ maxMode: 'accept-edits', budget: { maxCostUsd: 3, maxTokens: 50 }, mcp: { allow: ['docs'] } }), layer({ budget: { maxCostUsd: 7 } })]);
    assert.equal(set.maxMode(), 'accept-edits');
    assert.equal(set.modeAllowed('safe'), true);
    assert.equal(set.modeAllowed('yolo'), false);
    assert.equal(set.modeAllowed('dont-ask'), false);
    assert.deepEqual(set.budget(), { maxCostUsd: 3, maxTokens: 50 });
    assert.equal(set.mcpAllowed('docs'), true);
    assert.equal(set.mcpAllowed('wiki'), false);
    assert.equal(set.modelAllowed('claude-opus-5-5'), true);
    assert.equal(set.modelAllowed('gpt-5'), false);
    assert.equal(new PolicySet([]).modeAllowed('yolo'), true, 'no policy means no limit');
  });

  it('counts an approval only from someone every layer lets approve, and the requester need not be the approver', () => {
    const set = new PolicySet([layer({ approvers: { roles: ['lead', 'security'] } }), layer({ approvers: { users: ['dana'], roles: ['security'] } })]);
    const person = (user: string, roles: string[]): Identity => ({ user, ou: ['eng'], roles });
    assert.equal(set.mayApprove(person('dana', [])), false, 'dana is named in one layer but is not a lead or security in the other');
    assert.equal(set.mayApprove(person('sam', ['security'])), true);
    assert.equal(set.mayApprove(person('lee', ['lead'])), false);
    assert.equal(new PolicySet([]).mayApprove(person('anyone', [])), true);
  });

  it('lets someone read the audit only when a layer names readers and every layer that does includes them', () => {
    const person = (user: string, roles: string[]): Identity => ({ user, ou: ['eng'], roles });
    assert.equal(new PolicySet([]).mayReadAudit(person('anyone', ['auditor'])), false, 'silence means no, unlike approvers');
    assert.equal(new PolicySet([layer({ approvers: { roles: ['lead'] } })]).mayReadAudit(person('lee', ['lead'])), false, 'being an approver is not being a reader');
    const set = new PolicySet([layer({ audit: { readers: { roles: ['auditor'], users: ['dana'] } } }), layer({ name: 'ou' })]);
    assert.equal(set.mayReadAudit(person('sam', ['auditor'])), true);
    assert.equal(set.mayReadAudit(person('dana', [])), true);
    assert.equal(set.mayReadAudit(person('lee', ['lead'])), false);
    const narrowed = new PolicySet([layer({ audit: { readers: { roles: ['auditor'] } } }), layer({ audit: { readers: { users: ['dana'] } } })]);
    assert.equal(narrowed.mayReadAudit(person('sam', ['auditor'])), false, 'a lower layer can only narrow');
    assert.equal(narrowed.mayReadAudit(person('dana', ['auditor'])), true);
  });

  it('rejects a misspelt or malformed audit field instead of leaving it off', () => {
    assert.deepEqual(parsePolicy({ version: 1, audit: { readers: { roles: ['auditor'] } } }).audit, { readers: { roles: ['auditor'] } });
    for (const bad of [{ audit: { reader: {} } }, { audit: { readers: { role: ['a'] } } }, { audit: { readers: { roles: 'auditor' } } }, { audit: { readers: { users: [''] } } }, { audit: [] }]) assert.throws(() => parsePolicy({ version: 1, ...bad }), PolicyError);
  });
});

describe('the gate step for policy', () => {
  const call = (over: Partial<GateCall>): GateCall => ({ id: 'c', tool: 'read_file', args: {}, effect: 'observe', paths: [], summary: 's', ...over });
  const gateFor = (set: PolicySet, mode = 'yolo', rows: [string, Record<string, unknown>][] = []): Gate =>
    new Gate({ mode, tier: 4, workdir: '/repo', jail: new Jail({ root: '/repo', platform: 'linux', realpath: async (path) => path }), audit: (type, data) => rows.push([type, data]), policy: set.guard() });

  it('denies a tool the policy denies, even in yolo, and says which step did it', async () => {
    const rows: [string, Record<string, unknown>][] = [];
    const gate = gateFor(new PolicySet([layer({ name: 'org', tools: { deny: ['web_fetch'] } })]), 'yolo', rows);
    const decision = await gate.check(call({ tool: 'web_fetch', effect: 'external' }));
    assert.equal(decision.kind, 'rejected');
    assert.match(decision.kind === 'rejected' ? decision.reason : '', /Blocked by policy: web_fetch is denied by policy \(org\)/);
    assert.equal(rows[0]?.[1]['step'], 'org-policy');
  });

  it('denies a path the policy denies, before the jail is asked', async () => {
    const gate = gateFor(new PolicySet([layer({ paths: { deny: ['secrets/**'] } })]));
    assert.equal((await gate.check(call({ tool: 'read_file', paths: [{ path: 'secrets/db.txt', write: false }] }))).kind, 'rejected');
    assert.equal((await gate.check(call({ tool: 'read_file', paths: [{ path: 'src/a.ts', write: false }] }))).kind, 'allowed-once');
  });

  it('can only deny: a policy that lists a tool does not make a refused call allowed', async () => {
    const gate = gateFor(new PolicySet([layer({ tools: { allow: ['bash'] } })]), 'read-only');
    assert.equal((await gate.check(call({ tool: 'bash', effect: 'execution', command: 'ls' }))).kind, 'rejected');
    const hardline = gateFor(new PolicySet([layer({ tools: { allow: ['bash'] } })]));
    assert.equal((await hardline.check(call({ tool: 'bash', effect: 'execution', command: 'rm -rf /' }))).kind, 'rejected');
  });
});

describe('the local policy file', () => {
  it('means no policy when the file is missing, reads one layer or a list, and refuses what is wrong', async () => {
    await withTempDir(async (dir) => {
      assert.deepEqual((await loadLocalPolicy(dir)).layers, []);
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, 'policy.json'), JSON.stringify({ version: 1, tools: { deny: ['bash'] } }));
      assert.equal((await loadLocalPolicy(dir)).layers.length, 1);
      await writeFile(join(dir, 'policy.json'), JSON.stringify({ layers: [{ version: 1 }, { version: 1, maxMode: 'safe' }] }));
      assert.equal((await loadLocalPolicy(dir)).maxMode(), 'safe');
      for (const bad of ['not json', JSON.stringify({ layers: 'x' }), JSON.stringify({ layers: [], other: 1 }), JSON.stringify({ version: 1, surprise: true }), 'x'.repeat(300_000)]) {
        await writeFile(join(dir, 'policy.json'), bad);
        await assert.rejects(loadLocalPolicy(dir), PolicyError);
      }
    });
  });
});

describe('signed policies', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const other = generateKeyPairSync('ed25519');
  const policy = layer({ name: 'org', tools: { deny: ['bash'] }, maxMode: 'safe' });
  const pinned = new Map([['org-2026', publicKey]]);

  it('verifies a bundle signed by a pinned key, whatever the key order inside it', () => {
    const bundle = signPolicy(policy, 'org-2026', privateKey);
    assert.deepEqual(verifySignedPolicy(bundle, pinned), policy);
    assert.deepEqual(verifySignedPolicy({ ...bundle, policy: { maxMode: 'safe', tools: { deny: ['bash'] }, name: 'org', version: 1 } }, pinned), policy);
  });

  it('refuses a changed policy, a bad signature, a key nobody pinned, another key, and junk', () => {
    const bundle = signPolicy(policy, 'org-2026', privateKey);
    assert.throws(() => verifySignedPolicy({ ...bundle, policy: { ...policy, maxMode: 'yolo' } }, pinned), /does not match the policy/);
    assert.throws(() => verifySignedPolicy({ ...bundle, signature: Buffer.from('nope').toString('base64') }, pinned), PolicyError);
    assert.throws(() => verifySignedPolicy({ ...bundle, keyId: 'unknown' }, pinned), /not one this machine trusts/);
    assert.throws(() => verifySignedPolicy(signPolicy(policy, 'org-2026', other.privateKey), pinned), /does not match the policy/);
    for (const junk of [null, 'x', {}, { policy: {}, keyId: 1, signature: 's' }]) assert.throws(() => verifySignedPolicy(junk, pinned), PolicyError);
  });
});

describe('capability tokens', () => {
  const key = Buffer.from('k'.repeat(32));
  const now = 1_000_000;
  const base = (): ReturnType<typeof mintCapability> => mintCapability(key, 'tok-1', ['aud=broker.example', 'sid=session-A', `exp=${now + 60_000}`]);
  const ctx = (over: Record<string, unknown> = {}) => ({ audience: 'broker.example', session: 'session-A', now, ...over });

  it('is accepted for the right audience and session before it expires', () => {
    assert.deepEqual(verifyCapability(key, base(), ctx()), { ok: true });
  });

  it('can only be narrowed by whoever holds it, never widened', () => {
    const narrowed = attenuateCapability(attenuateCapability(base(), 'tool=read_file,grep'), 'path=src');
    assert.deepEqual(verifyCapability(key, narrowed, ctx({ tool: 'read_file', path: 'src/a.ts' })), { ok: true });
    assert.equal(verifyCapability(key, narrowed, ctx({ tool: 'bash' })).ok, false);
    assert.equal(verifyCapability(key, narrowed, ctx({ tool: 'read_file', path: 'src2/a.ts' })).ok, false, 'src2 is not under src');
    assert.equal(verifyCapability(key, narrowed, ctx({ tool: 'read_file', path: 'docs/a.md' })).ok, false);
    // Adding a broader caveat does not cancel the narrower one.
    const tryWiden = attenuateCapability(narrowed, 'tool=*');
    assert.equal(verifyCapability(key, tryWiden, ctx({ tool: 'bash' })).ok, false);
  });

  it('cannot have a restriction removed or edited, or be forged without the key', () => {
    const narrowed = attenuateCapability(base(), 'tool=read_file');
    assert.equal(verifyCapability(key, { ...narrowed, caveats: narrowed.caveats.slice(0, -1) }, ctx()).ok, false, 'a caveat was stripped');
    assert.equal(verifyCapability(key, { ...narrowed, caveats: narrowed.caveats.map((caveat) => caveat.replace('read_file', '*')) }, ctx()).ok, false);
    assert.equal(verifyCapability(key, { ...base(), sig: 'ab'.repeat(32) }, ctx()).ok, false);
    assert.equal(verifyCapability(Buffer.from('z'.repeat(32)), base(), ctx()).ok, false);
    assert.equal(verifyCapability(key, { ...base(), id: 'tok-2' }, ctx()).ok, false);
    assert.equal(verifyCapability(key, { ...base(), sig: 'not hex' }, ctx()).ok, false);
  });

  it('attack: parent_session_grant_not_inherited (a stolen token is useless for another audience or session)', () => {
    assert.match((verifyCapability(key, base(), ctx({ session: 'session-B' })) as { reason: string }).reason, /different session/);
    assert.match((verifyCapability(key, base(), ctx({ audience: 'attacker.example' })) as { reason: string }).reason, /different audience/);
  });

  it('expires', () => {
    assert.match((verifyCapability(key, base(), ctx({ now: now + 60_000 })) as { reason: string }).reason, /expired/);
    assert.equal(verifyCapability(key, base(), ctx({ now: now + 59_999 })).ok, true);
  });

  it('is refused unless it names an audience, a session and an expiry', () => {
    for (const missing of ['aud', 'sid', 'exp']) {
      const caveats = ['aud=broker.example', 'sid=session-A', `exp=${now + 1000}`].filter((caveat) => !caveat.startsWith(missing));
      const verdict = verifyCapability(key, mintCapability(key, 'tok', caveats), ctx());
      assert.equal(verdict.ok, false, missing);
      assert.match((verdict as { reason: string }).reason, new RegExp(`no ${missing} restriction`));
    }
  });

  it('is refused if a nonce was seen before, so it cannot be replayed', () => {
    const seen = new Set<string>();
    assert.equal(verifyCapability(key, base(), ctx({ seen })).ok, true);
    assert.match((verifyCapability(key, base(), ctx({ seen })) as { reason: string }).reason, /already used/);
  });

  it('is refused if it carries a restriction this version does not understand, rather than ignoring it', () => {
    const verdict = verifyCapability(key, attenuateCapability(base(), 'region=eu'), ctx());
    assert.equal(verdict.ok, false);
    assert.match((verdict as { reason: string }).reason, /does not understand \(region\)/);
  });
});
