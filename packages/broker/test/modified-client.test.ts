import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, it } from 'node:test';
import { git } from '@hn/operations';
import { verifyAudit } from '@hn/security';
import { makeSigningKey, signJwt, type FakeOpenAIReply } from '@hn/testkit';
import { UPSTREAM_KEY, baseTree, startTeam, type Team } from './fixture.ts';

/**
 * The Phase 8 exit gate: model access, credentials and server-side tools are governed against a modified client.
 * Every attack here is a client that ignores every local rule and speaks raw HTTP to the broker, so the only thing
 * that can stop it is the broker. Pass means the effect did not happen, checked on the far side (upstream request
 * counts, the remote repository, the audit chain), never by the broker's own word.
 */

const GIT_TOKEN = 'ghp-held-by-broker-only-31';
const tree = baseTree({
  org: { version: 1, name: 'org', models: { allow: ['team-*'] }, budget: { maxTokens: 150 }, git: { repos: ['acme/app'], protect: ['refs/heads/main'] }, approvers: { roles: ['lead'], separate: true }, memory: { share: ['user', 'ou'] } },
  roles: { intern: { version: 1, name: 'intern', models: { allow: ['team-small'] }, tools: { deny: ['bash', 'git_push'] } } },
});
const body = (extra: Record<string, unknown> = {}) => ({ model: 'team-large', system: 's', tools: [{ name: 'bash', description: 'b', parameters: { type: 'object' } }], messages: [{ role: 'user', parts: [{ type: 'text', text: 'hi' }] }], maxOutputTokens: 64, ...extra });

async function withTeam(run: (team: Team, remote: string) => Promise<void>, decide?: () => FakeOpenAIReply): Promise<void> {
  const remote = await mkdtemp(join(tmpdir(), 'hn-gate-remote-'));
  await git(['init', '--bare', '--quiet'], { cwd: remote });
  const team = await startTeam({ tree, env: { GH_TOKEN: GIT_TOKEN }, tools: { git: [{ repo: 'acme/app', remote: pathToFileURL(remote).href, tokenEnv: 'GH_TOKEN' }] }, ...(decide === undefined ? {} : { decide }) });
  try {
    await run(team, remote);
  } finally {
    await team.close();
    await rm(remote, { recursive: true, force: true });
  }
}

async function bundleOf(dir: string): Promise<string> {
  await git(['init', '--quiet', dir], { cwd: tmpdir() });
  await writeFile(join(dir, 'f.txt'), 'x');
  await git(['add', 'f.txt'], { cwd: dir });
  await git(['commit', '--quiet', '-m', 'x'], { cwd: dir });
  await git(['bundle', 'create', '--quiet', join(dir, 'gate.bundle'), 'HEAD'], { cwd: dir });
  return (await readFile(join(dir, 'gate.bundle'))).toString('base64');
}

const requestId = (text: string): string => {
  const id = /Request ([0-9a-f]{12})/.exec(text)?.[1];
  assert.ok(id !== undefined, text);
  return id;
};

describe('Phase 8 exit gate: a modified client against the broker', () => {
  it('attack: modified_client_cannot_reach_denied_model (an intern asks for a model the policy denies them; upstream is never called)', async () => {
    await withTeam(async (team) => {
      const intern = await team.login({ email: 'in@example.com', department: 'eng', groups: ['intern'] });
      const token = await intern.session('g-1');
      for (const model of ['team-large', 'TEAM-LARGE', 'team-large ', 'other-model']) assert.notEqual((await team.raw('/v1/model', { token, session: 'g-1', body: body({ model }) })).status, 200, model);
      assert.equal(team.upstream.requests.length, 0);
    });
  });

  it('attack: modified_client_never_receives_broker_key (no route, with good or bad input, answers with a credential the broker holds)', async () => {
    await withTeam(async (team) => {
      const ana = await team.login({ email: 'ana@example.com', department: 'eng', groups: [] });
      const token = await ana.session('g-2');
      const secrets = [UPSTREAM_KEY, GIT_TOKEN, (await readFile(join(team.dir, 'state', 'token.key'))).toString('hex'), (await readFile(join(team.dir, 'state', 'audit.key'))).toString('hex')];
      const probes: [string, unknown][] = [['/v1/whoami', undefined], ['/v1/policy', undefined], ['/v1/tools', undefined], ['/v1/approvals', undefined], ['/v1/memory', undefined], ['/v1/audit/anchor', undefined], ['/v1/model', body()], ['/v1/model', { junk: true }], ['/v1/tools/call', { name: 'git_push', args: { repo: 'acme/app', branch: 'x', bundle: 'bm90IGEgYnVuZGxl' } }], ['/v1/tools/call', { name: '../../etc', args: {} }], ['/v1/session', { session: 'x' }], ['/v1/nope', undefined]];
      for (const [path, sent] of probes) {
        const answer = await (await team.raw(path, { token, session: 'g-2', ...(sent === undefined ? {} : { body: sent }) })).text();
        for (const secret of secrets) assert.ok(!answer.includes(secret), `${path} answered with a broker secret`);
      }
      assert.ok(team.upstream.headers.length > 0 && team.upstream.headers.every((headers) => headers['authorization'] === `Bearer ${UPSTREAM_KEY}`), 'the key went only upstream');
    });
  });

  it('attack: denied_tool_call_stripped_from_reply (the model asks for bash for an intern; the client never receives the call)', async () => {
    await withTeam(
      async (team) => {
        const intern = await team.login({ email: 'in@example.com', department: 'eng', groups: ['intern'] });
        const token = await intern.session('g-3');
        const text = await (await team.raw('/v1/model', { token, session: 'g-3', body: body({ model: 'team-small' }) })).text();
        assert.ok(!text.includes('"tool_call"'), text);
        assert.ok(!text.includes('rm -rf'));
        assert.equal(team.upstream.requests[0]?.tools?.length ?? 0, 0, 'bash was not even offered upstream');
      },
      () => ({ calls: [{ id: 'c', name: 'bash', args: { command: 'rm -rf /' } }] }),
    );
  });

  it('attack: modified_client_cannot_call_denied_server_tool (an intern calls git_push directly; nothing reaches the remote)', async () => {
    await withTeam(async (team, remote) => {
      const intern = await team.login({ email: 'in@example.com', department: 'eng', groups: ['intern'] });
      const token = await intern.session('g-4');
      const bundle = await bundleOf(join(team.dir, 'w1'));
      const call = await team.raw('/v1/tools/call', { token, session: 'g-4', body: { name: 'git_push', args: { repo: 'acme/app', branch: 'feature', bundle } } });
      assert.equal(call.status, 403);
      assert.equal((await git(['for-each-ref'], { cwd: remote })).stdout.trim(), '', 'the remote has no refs');
    });
  });

  it('attack: modified_client_cannot_push_protected_ref_without_approval (pushing again does not wear the broker down)', async () => {
    await withTeam(async (team, remote) => {
      const ana = await team.login({ email: 'ana@example.com', department: 'eng', groups: ['lead'] });
      const token = await ana.session('g-5');
      const bundle = await bundleOf(join(team.dir, 'w2'));
      const push = async (): Promise<string> => JSON.stringify(await (await team.raw('/v1/tools/call', { token, session: 'g-5', body: { name: 'git_push', args: { repo: 'acme/app', branch: 'main', bundle } } })).json());
      requestId(await push());
      for (let attempt = 0; attempt < 3; attempt += 1) assert.match(await push(), /needs an approval/);
      assert.equal((await git(['for-each-ref'], { cwd: remote })).stdout.trim(), '', 'main never reached the remote');
    });
  });

  it('attack: requester_cannot_approve_own_request (not from the same session, another session, or a second login)', async () => {
    await withTeam(async (team, remote) => {
      const ana = await team.login({ email: 'ana@example.com', department: 'eng', groups: ['lead'] });
      const token = await ana.session('g-6');
      const bundle = await bundleOf(join(team.dir, 'w3'));
      const id = requestId(JSON.stringify(await (await team.raw('/v1/tools/call', { token, session: 'g-6', body: { name: 'git_push', args: { repo: 'acme/app', branch: 'main', bundle } } })).json()));
      assert.equal((await team.raw('/v1/approvals/decide', { token, session: 'g-6', body: { id, decision: 'approve' } })).status, 403);
      const again = await team.login({ email: 'ana@example.com', department: 'eng', groups: ['lead'] });
      const other = await again.session('g-6b');
      assert.equal((await team.raw('/v1/approvals/decide', { token: other, session: 'g-6b', body: { id, decision: 'approve' } })).status, 403);
      const pushed = JSON.stringify(await (await team.raw('/v1/tools/call', { token, session: 'g-6', body: { name: 'git_push', args: { repo: 'acme/app', branch: 'main', bundle } } })).json());
      assert.match(pushed, /needs an approval/);
      assert.equal((await git(['for-each-ref'], { cwd: remote })).stdout.trim(), '');
    });
  });

  it('attack: stolen_token_refused_for_other_session_and_after_revoke (a session token used elsewhere, edited, or after its login is revoked)', async () => {
    await withTeam(async (team) => {
      const ana = await team.login({ email: 'ana@example.com', department: 'eng', groups: [] });
      const token = await ana.session('g-7');
      assert.equal((await team.raw('/v1/whoami', { token, session: 'someone-elses' })).status, 401);
      const capability = JSON.parse(Buffer.from(token, 'base64url').toString('utf8')) as { id: string; caveats: string[]; sig: string };
      const forged = Buffer.from(JSON.stringify({ ...capability, caveats: capability.caveats.map((caveat) => (caveat.startsWith('aud=') ? 'aud=http://other-broker' : caveat)) })).toString('base64url');
      assert.equal((await team.raw('/v1/whoami', { token: forged, session: 'g-7' })).status, 401);
      await team.broker.context.tokens.revoke((JSON.parse(Buffer.from(ana.loginToken, 'base64url').toString('utf8')) as { id: string }).id);
      assert.equal((await team.raw('/v1/whoami', { token, session: 'g-7' })).status, 401);
    });
  });

  it('attack: forged_id_token_refused (an ID token signed by an attacker key never becomes a login)', async () => {
    await withTeam(async (team) => {
      const start = (await (await team.raw('/v1/login/start', { body: {} })).json()) as { loginId: string; userCode: string };
      // The provider hands back a token the attacker signed: the broker must check it against the provider's keys.
      const real = team.idp.idToken.bind(team.idp);
      const now = Math.floor(Date.now() / 1000);
      team.idp.idToken = () => signJwt(makeSigningKey('RS256', 'k1'), { iss: team.idp.issuer, aud: team.idp.clientId, sub: 'boss', email: 'ceo@example.com', iat: now, exp: now + 600 });
      team.idp.decide(start.userCode, true);
      const poll = await team.raw('/v1/login/poll', { body: { loginId: start.loginId } });
      team.idp.idToken = real;
      assert.equal(poll.status, 401);
      assert.ok(!(await poll.text()).includes('"token"'));
    });
  });

  it('attack: old_policy_bundle_cannot_be_replayed (a looser older bundle is refused and the newer one stays in force)', async () => {
    await withTeam(async (team) => {
      await team.setPolicy({ ...tree, serial: 2 });
      await assert.rejects(team.setPolicy({ ...tree, serial: 1, roles: {} }), /older than serial 2/);
      const intern = await team.login({ email: 'in@example.com', department: 'eng', groups: ['intern'] });
      const token = await intern.session('g-8');
      assert.equal((await team.raw('/v1/model', { token, session: 'g-8', body: body() })).status, 403, 'the intern rule still holds');
    });
  });

  it('attack: budget_cannot_be_reset_by_client (new sessions and new logins do not reset the day budget)', async () => {
    await withTeam(async (team) => {
      for (const [index, session] of ['g-9a', 'g-9b', 'g-9c'].entries()) {
        const ana = await team.login({ email: 'ana@example.com', department: 'eng', groups: [] });
        const token = await ana.session(session);
        const status = (await team.raw('/v1/model', { token, session, body: body({ tools: [] }) })).status;
        assert.equal(status, index < 2 ? 200 : 402, session);
      }
      assert.equal(team.upstream.requests.length, 2);
    });
  });

  it('attack: memory_from_other_ou_never_returned (and nobody writes into an OU they are not in)', async () => {
    await withTeam(async (team) => {
      const hr = await team.login({ email: 'cy@example.com', department: 'hr', groups: [] });
      const hrToken = await hr.session('g-10');
      assert.equal((await team.raw('/v1/memory', { token: hrToken, session: 'g-10', body: { text: 'Salary bands', why: 'w', taint: 'clean', visibility: { kind: 'ou', value: 'hr' } } })).status, 200);
      assert.equal((await team.raw('/v1/memory', { token: hrToken, session: 'g-10', body: { text: 'x', why: 'w', taint: 'clean', visibility: { kind: 'ou', value: 'eng' } } })).status, 403);
      const eng = await team.login({ email: 'ana@example.com', department: 'eng', groups: [] });
      const engToken = await eng.session('g-11');
      const seen = await (await team.raw('/v1/memory?q=salary', { token: engToken, session: 'g-11' })).text();
      assert.ok(!seen.includes('Salary'), seen);
    });
  });

  it('attack: cut_audit_tail_caught_by_anchor (an anchor cannot go back, and the broker chain holds every refusal)', async () => {
    await withTeam(async (team) => {
      const intern = await team.login({ email: 'in@example.com', department: 'eng', groups: ['intern'] });
      const token = await intern.session('g-12');
      await team.raw('/v1/model', { token, session: 'g-12', body: body() });
      assert.equal((await team.raw('/v1/audit/anchor', { token, session: 'g-12', body: { n: 5, mac: 'c'.repeat(64) } })).status, 200);
      assert.equal((await team.raw('/v1/audit/anchor', { token, session: 'g-12', body: { n: 4, mac: 'c'.repeat(64) } })).status, 409, 'a head that goes back is refused');
      await team.broker.audit.flush();
      const chain = verifyAudit(await readFile(team.broker.audit.path, 'utf8'), team.broker.audit.key);
      assert.equal(chain.ok, true);
      assert.ok(chain.entries.some((entry) => entry.type === 'broker/model-refused' && entry.data['user'] === 'in@example.com'));
      assert.ok(chain.entries.some((entry) => entry.type === 'broker/anchor-refused'));
    });
  });
});
