import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import { PolicyError, layersFor, parsePolicyTree, signPolicyTree, verifyPolicyTree, type Identity } from '@hn/security';

const signer = generateKeyPairSync('ed25519');
const other = generateKeyPairSync('ed25519');
const pinned = new Map([['org-2026', signer.publicKey]]);

const tree = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  format: 1,
  serial: 7,
  issued: '2026-11-17T00:00:00Z',
  org: { version: 1, name: 'org', tools: { deny: ['mcp__evil__*'] }, models: { allow: ['claude-*', 'qwen*'] }, approvers: { roles: ['lead'] } },
  ou: { eng: { version: 1, name: 'eng', maxMode: 'dont-ask' }, 'eng/platform': { version: 1, name: 'platform', tools: { deny: ['web_*'] } }, hr: { version: 1, name: 'hr', maxMode: 'safe' } },
  roles: { intern: { version: 1, name: 'intern', maxMode: 'plan', models: { allow: ['qwen*'] } }, lead: { version: 1, name: 'lead' } },
  users: { 'ana@example.com': { version: 1, name: 'ana', paths: { deny: ['payroll/**'] } } },
  ...extra,
});

const ana: Identity = { user: 'ana@example.com', ou: ['eng', 'platform'], roles: ['lead'] };

describe('the signed policy tree', () => {
  it('picks org, each OU from the top, each role and the person, in that order', () => {
    const set = layersFor(parsePolicyTree(tree()), ana);
    assert.deepEqual(set.layers.map((layer) => layer.name), ['org', 'eng', 'platform', 'lead', 'ana']);
    assert.match(set.toolReason('web_fetch') ?? '', /platform/);
    assert.match(set.pathReason('payroll/2026.csv') ?? '', /ana/);
    assert.equal(set.maxMode(), 'dont-ask');
    assert.equal(set.mayApprove(ana), true);
    const intern = layersFor(parsePolicyTree(tree()), { user: 'bo', ou: ['hr'], roles: ['intern'] });
    assert.equal(intern.maxMode(), 'plan');
    assert.equal(intern.modelAllowed('claude-opus-5-5'), false);
    assert.equal(intern.mayApprove({ user: 'bo', ou: ['hr'], roles: ['intern'] }), false);
  });

  it('does not match an OU by a prefix of its name', () => {
    const set = layersFor(parsePolicyTree(tree()), { user: 'x', ou: ['engineering'], roles: [] });
    assert.deepEqual(set.layers.map((layer) => layer.name), ['org']);
  });

  it('accepts a bundle signed by a pinned key and refuses an unsigned, edited or foreign one', () => {
    const bundle = signPolicyTree(tree(), 'org-2026', signer.privateKey);
    assert.equal(verifyPolicyTree(bundle, pinned, null).tree.serial, 7);
    assert.throws(() => verifyPolicyTree({ tree: tree() }, pinned, null), /Not a signed policy tree/);
    const edited = { ...bundle, tree: tree({ org: { version: 1, name: 'org' } }) };
    assert.throws(() => verifyPolicyTree(edited, pinned, null), /changed or signed by someone else/);
    assert.throws(() => verifyPolicyTree(signPolicyTree(tree(), 'org-2026', other.privateKey), pinned, null), /changed or signed by someone else/);
    assert.throws(() => verifyPolicyTree(signPolicyTree(tree(), 'rogue', other.privateKey), pinned, null), /not one this machine trusts/);
    assert.throws(() => verifyPolicyTree({ ...bundle, extra: 1 }, pinned, null), /Not a signed policy tree/);
  });

  it('refuses an older serial, and a different bundle with the same serial', () => {
    const v7 = verifyPolicyTree(signPolicyTree(tree(), 'org-2026', signer.privateKey), pinned, null);
    const v8 = verifyPolicyTree(signPolicyTree(tree({ serial: 8 }), 'org-2026', signer.privateKey), pinned, v7.seen);
    assert.throws(() => verifyPolicyTree(signPolicyTree(tree(), 'org-2026', signer.privateKey), pinned, v8.seen), (error: unknown) => error instanceof PolicyError && /older than serial 8/.test(error.message));
    assert.throws(() => verifyPolicyTree(signPolicyTree(tree({ serial: 8, ou: {} }), 'org-2026', signer.privateKey), pinned, v8.seen), /same serial 8/);
    assert.equal(verifyPolicyTree(signPolicyTree(tree({ serial: 8 }), 'org-2026', signer.privateKey), pinned, v8.seen).tree.serial, 8, 'the same bundle fetched again is fine');
  });

  it('refuses unknown fields, bad names and a missing org layer, whether signed or not', () => {
    assert.throws(() => parsePolicyTree(tree({ admins: {} })), /unknown field "admins"/);
    assert.throws(() => parsePolicyTree(tree({ ou: { 'eng\u001b': { version: 1 } } })), /not allowed/);
    assert.throws(() => parsePolicyTree(tree({ ou: { 'eng//x\\y': { version: 1 } } })), /not allowed/);
    assert.throws(() => parsePolicyTree({ ...tree(), org: undefined }), /org layer/);
    assert.throws(() => parsePolicyTree(tree({ users: { bo: { version: 1, superuser: true } } })), /users\.bo: .*unknown field "superuser"/);
    assert.throws(() => signPolicyTree(tree({ serial: 0 }), 'org-2026', signer.privateKey), /serial/);
  });

  it('property: more OU depth, more roles or a personal layer never newly allows anything', () => {
    let seed = 99;
    const next = (): number => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
    const pick = <T>(list: readonly T[]): T => list[Math.floor(next() * list.length)] as T;
    const patterns = ['*', 'read_*', 'bash', 'web_*', '*_file', 'grep'];
    const modes = ['read-only', 'plan', 'safe', 'accept-edits', 'smart', 'dont-ask', 'yolo'];
    const layer = (): Record<string, unknown> => ({ version: 1, ...(next() < 0.5 ? { tools: next() < 0.5 ? { allow: [pick(patterns), pick(patterns)] } : { deny: [pick(patterns)] } } : {}), ...(next() < 0.4 ? { maxMode: pick(modes) } : {}), ...(next() < 0.3 ? { models: { allow: [pick(['claude-*', 'qwen*', '*'])] } } : {}) });
    const tools = ['read_file', 'write_file', 'bash', 'web_fetch', 'grep'];
    for (let round = 0; round < 200; round += 1) {
      const parsed = parsePolicyTree({ format: 1, serial: 1, issued: '2026-11-17T00:00:00Z', org: layer(), ou: { a: layer(), 'a/b': layer(), 'a/b/c': layer() }, roles: { r1: layer(), r2: layer() }, users: { u: layer() } });
      const shallow: Identity = { user: 'v', ou: ['a'], roles: ['r1'] };
      const deeper: Identity = { user: 'u', ou: ['a', 'b', pick(['c', 'z'])], roles: ['r1', 'r2'] };
      const base = layersFor(parsed, shallow);
      const more = layersFor(parsed, deeper);
      for (const tool of tools) if (base.toolReason(tool) !== null) assert.notEqual(more.toolReason(tool), null, `deeper allowed ${tool}`);
      for (const model of ['claude-opus-5-5', 'qwen3:14b', 'gpt-x']) if (!base.modelAllowed(model)) assert.equal(more.modelAllowed(model), false, `deeper allowed ${model}`);
      assert.ok(modes.indexOf(more.maxMode()) <= modes.indexOf(base.maxMode()), 'deeper raised the mode ceiling');
    }
  });
});
