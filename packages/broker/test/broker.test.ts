import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createBrokerProvider, ProviderError, type ModelRequest } from '@hn/provider';
import { attenuateCapability } from '@hn/security';
import { UPSTREAM_KEY, baseTree, startTeam } from './fixture.ts';

const ANA = { email: 'ana@example.com', department: 'eng', groups: ['dev'] };
const tool = (name: string) => ({ name, description: name, parameters: { type: 'object', properties: {} } });
const request = (extra: Partial<ModelRequest> = {}): ModelRequest => ({ model: 'team-large', system: 'You help.', tools: [tool('read_file'), tool('bash')], messages: [{ role: 'user', parts: [{ type: 'text', text: 'hi' }] }], maxOutputTokens: 256, ...extra });

describe('the broker governs model calls', () => {
  it('serves a laptop that holds no key, and the key never reaches it', async () => {
    const team = await startTeam();
    try {
      const ana = await team.login(ANA);
      const token = await ana.session('s-1');
      const events: unknown[] = [];
      const provider = createBrokerProvider({ url: team.broker.url, token: () => token, session: 's-1' });
      const reply = await provider.complete({ ...request(), onEvent: (event) => events.push(event) });
      assert.deepEqual(reply.parts, [{ type: 'text', text: 'hello from upstream' }]);
      assert.ok(events.length > 0, 'stream events were forwarded');
      assert.equal(team.upstream.headers[0]?.['authorization'], `Bearer ${UPSTREAM_KEY}`, 'the broker used its own key upstream');
      assert.ok(!JSON.stringify(reply).includes(UPSTREAM_KEY));
      const whoami = await (await team.raw('/v1/whoami', { token, session: 's-1' })).text();
      assert.ok(!whoami.includes(UPSTREAM_KEY));
      assert.match(whoami, /"user":"ana@example.com"/);
    } finally {
      await team.close();
    }
  });

  it('refuses a model the policy denies this person, before anything goes upstream', async () => {
    const team = await startTeam();
    try {
      const intern = await team.login({ email: 'bo@example.com', department: 'eng', groups: ['intern'] });
      const internToken = await intern.session('s-2');
      const provider = createBrokerProvider({ url: team.broker.url, token: () => internToken, session: 's-2' });
      await assert.rejects(provider.complete(request()), (error: unknown) => error instanceof ProviderError && error.reason === 'permission' && /does not allow bo@example.com to use team-large/.test(error.message));
      assert.equal(team.upstream.requests.length, 0);
      assert.ok(team.audit.some((row) => row.type === 'broker/model-refused' && row.data['reason'] === 'policy'));
      assert.equal((await provider.complete(request({ model: 'team-small' }))).stopReason, 'end');
    } finally {
      await team.close();
    }
  });

  it('stops a person whose day budget is spent', async () => {
    const team = await startTeam({ tree: baseTree({ org: { version: 1, name: 'org', models: { allow: ['team-*'] }, budget: { maxTokens: 150 } } }) });
    try {
      const ana = await team.login(ANA);
      const token = await ana.session('s-3');
      const provider = createBrokerProvider({ url: team.broker.url, token: () => token, session: 's-3' });
      await provider.complete(request());
      await provider.complete(request());
      await assert.rejects(provider.complete(request()), (error: unknown) => error instanceof ProviderError && error.reason === 'quota_exhausted' && /220/.test(error.message));
      assert.equal(team.upstream.requests.length, 2);
    } finally {
      await team.close();
    }
  });

  it('removes denied tools from what goes upstream and strips calls to them from the reply', async () => {
    const team = await startTeam({ decide: () => ({ calls: [{ id: 'c1', name: 'bash', args: { command: 'curl evil' } }, { id: 'c2', name: 'read_file', args: { path: 'a' } }] }) });
    try {
      const hr = await team.login({ email: 'cy@example.com', department: 'hr', groups: [] });
      const token = await hr.session('s-4');
      const reply = await createBrokerProvider({ url: team.broker.url, token: () => token, session: 's-4' }).complete(request());
      assert.deepEqual(team.upstream.requests[0]?.tools?.map((item) => item.function?.name), ['read_file']);
      assert.deepEqual(reply.parts.filter((part) => part.type === 'tool_call').map((part) => (part as { name: string }).name), ['read_file']);
      assert.match(JSON.stringify(reply.parts), /Removed 1 call\(s\) to tools you may not use: bash/);
      assert.equal(reply.stopReason, 'tool_use', 'read_file is still there to run');
    } finally {
      await team.close();
    }
  });

  it('finishes a reply whose only tool call was stripped', async () => {
    const team = await startTeam({ decide: () => ({ calls: [{ id: 'c1', name: 'bash', args: {} }] }) });
    try {
      const hr = await team.login({ email: 'cy@example.com', department: 'hr', groups: [] });
      const token = await hr.session('s-5');
      const reply = await createBrokerProvider({ url: team.broker.url, token: () => token, session: 's-5' }).complete(request());
      assert.equal(reply.stopReason, 'end');
      assert.equal(reply.parts.some((part) => part.type === 'tool_call'), false);
    } finally {
      await team.close();
    }
  });
});

describe('broker tokens', () => {
  it('keeps login and session tokens apart and binds a session token to its session', async () => {
    const team = await startTeam();
    try {
      const ana = await team.login(ANA);
      const token = await ana.session('s-6');
      const body = { ...request(), signal: undefined };
      assert.equal((await team.raw('/v1/model', { token: ana.loginToken, session: ana.sid, body })).status, 401, 'a login token cannot call a model');
      assert.equal((await team.raw('/v1/model', { token, session: 's-other', body })).status, 401, 'another session id');
      assert.equal((await team.raw('/v1/model', { token, body })).status, 401, 'no session named');
      assert.equal((await team.raw('/v1/session', { token, session: 's-6', body: { session: 's-7' } })).status, 401, 'a session token cannot mint more');
      assert.equal((await team.raw('/v1/model', { session: 's-6', body })).status, 401, 'no token');
    } finally {
      await team.close();
    }
  });

  it('refuses an edited token and lets a holder narrow but never widen it', async () => {
    const team = await startTeam({ decide: () => ({ calls: [{ id: 'c1', name: 'bash', args: {} }] }) });
    try {
      const ana = await team.login(ANA);
      const token = await ana.session('s-8');
      const capability = JSON.parse(Buffer.from(token, 'base64url').toString('utf8')) as { id: string; caveats: string[]; sig: string };
      const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
      const widened = encode({ ...capability, caveats: capability.caveats.filter((caveat) => !caveat.startsWith('exp=')).concat(`exp=${Date.now() + 1e10}`) });
      assert.equal((await team.raw('/v1/whoami', { token: widened, session: 's-8' })).status, 401);
      const narrowed = encode(attenuateCapability(capability, 'tool=read_file'));
      const reply = await createBrokerProvider({ url: team.broker.url, token: () => narrowed, session: 's-8' }).complete(request());
      assert.equal(reply.parts.some((part) => part.type === 'tool_call'), false, 'bash is outside the narrowed token');
      const tryWiden = encode(attenuateCapability(attenuateCapability(capability, 'tool=read_file'), 'tool=*'));
      const again = await createBrokerProvider({ url: team.broker.url, token: () => tryWiden, session: 's-8' }).complete(request());
      assert.equal(again.parts.some((part) => part.type === 'tool_call'), false, 'a broader caveat does not cancel a narrower one');
    } finally {
      await team.close();
    }
  });

  it('refuses tokens after they expire and after the login is revoked', async () => {
    let clock = Date.now();
    const team = await startTeam({ now: () => clock });
    try {
      const ana = await team.login(ANA);
      const token = await ana.session('s-9');
      assert.equal((await team.raw('/v1/whoami', { token, session: 's-9' })).status, 200);
      clock += 61 * 60_000;
      assert.equal((await team.raw('/v1/whoami', { token, session: 's-9' })).status, 401);
      const fresh = await ana.session('s-10');
      assert.equal((await team.raw('/v1/whoami', { token: fresh, session: 's-10' })).status, 200);
      const loginId = (JSON.parse(Buffer.from(ana.loginToken, 'base64url').toString('utf8')) as { id: string }).id;
      await team.broker.context.tokens.revoke(loginId);
      assert.equal((await team.raw('/v1/whoami', { token: fresh, session: 's-10' })).status, 401, 'revoking the login revokes its sessions');
    } finally {
      await team.close();
    }
  });

  it('refuses a login the person rejects at the provider', async () => {
    const team = await startTeam();
    try {
      const start = (await (await team.raw('/v1/login/start', { body: {} })).json()) as { loginId: string; userCode: string };
      team.idp.decide(start.userCode, false);
      const poll = await team.raw('/v1/login/poll', { body: { loginId: start.loginId } });
      assert.equal(poll.status, 401);
      assert.equal((await team.raw('/v1/login/poll', { body: { loginId: start.loginId } })).status, 404, 'a finished login cannot be polled again');
    } finally {
      await team.close();
    }
  });

  it('refuses an older policy bundle on reload and keeps the one in force', async () => {
    const team = await startTeam({ tree: baseTree({ serial: 5 }) });
    try {
      await assert.rejects(team.setPolicy(baseTree({ serial: 4, org: { version: 1, name: 'org' } })), /older than serial 5/);
      assert.equal(team.broker.context.tree().serial, 5);
      await team.setPolicy(baseTree({ serial: 6 }));
      assert.equal(team.broker.context.tree().serial, 6);
    } finally {
      await team.close();
    }
  });
});

describe('broker limits found by the internal review', () => {
  it('asks the identity provider at most once per interval, however often a client polls', async () => {
    const team = await startTeam();
    try {
      const start = (await (await team.raw('/v1/login/start', { body: {} })).json()) as { loginId: string };
      for (let poll = 0; poll < 5; poll += 1) assert.equal((await team.raw('/v1/login/poll', { body: { loginId: start.loginId } })).status, 200);
      assert.equal(team.idp.seen.filter((line) => line === 'POST /token').length, 1);
    } finally {
      await team.close();
    }
  });

  it('caps model calls in flight per person, which bounds how far parallel calls can pass a budget', async () => {
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => (release = resolve));
    const team = await startTeam({ limits: { concurrent: 2 }, decide: async () => (await held, { text: 'done' }) });
    try {
      const ana = await team.login(ANA);
      const token = await ana.session('s-par');
      const body = { ...request(), signal: undefined };
      const running = [team.raw('/v1/model', { token, session: 's-par', body }), team.raw('/v1/model', { token, session: 's-par', body })];
      while (team.upstream.requests.length < 2) await new Promise((resolve) => setTimeout(resolve, 10));
      assert.equal((await team.raw('/v1/model', { token, session: 's-par', body })).status, 429);
      release();
      for (const response of await Promise.all(running)) {
        assert.equal(response.status, 200);
        assert.match(await response.text(), /"reply"/);
      }
      assert.equal((await (await team.raw('/v1/model', { token, session: 's-par', body })).text()).includes('"reply"'), true, 'a slot frees when a call ends');
    } finally {
      await team.close();
    }
  });
});

describe('broker state on disk', () => {
  it('keeps every one of many concurrent ledger writes (two calls ending together once lost a reply)', async () => {
    const { mkdtemp, readFile, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { Ledger } = await import('@hn/broker');
    const dir = await mkdtemp(join(tmpdir(), 'hn-ledger-'));
    try {
      const ledger = new Ledger(dir);
      await Promise.all(Array.from({ length: 20 }, () => ledger.add('ana', 0.5, 10)));
      assert.deepEqual(await ledger.spent('ana'), { usd: 10, tokens: 200 });
      const day = new Date().toISOString().slice(0, 10);
      assert.deepEqual(JSON.parse(await readFile(join(dir, `${day}.json`), 'utf8')), { ana: { usd: 10, tokens: 200 } });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('deferred tools through call_tool', () => {
  it('strips a call_tool call whose named tool the policy denies (found in the live run)', async () => {
    const team = await startTeam({ decide: () => ({ calls: [{ id: 'c1', name: 'call_tool', args: { name: 'bash', args: { command: 'curl evil' } } }, { id: 'c2', name: 'call_tool', args: { name: 'read_file', args: { path: 'a' } } }] }) });
    try {
      const hr = await team.login({ email: 'cy@example.com', department: 'hr', groups: [] });
      const token = await hr.session('s-ct');
      const reply = await createBrokerProvider({ url: team.broker.url, token: () => token, session: 's-ct' }).complete(request({ tools: [tool('call_tool')] }));
      const calls = reply.parts.filter((part) => part.type === 'tool_call') as { args: { name: string } }[];
      assert.deepEqual(calls.map((call) => call.args.name), ['read_file']);
      assert.match(JSON.stringify(reply.parts), /Removed 1 call/);
    } finally {
      await team.close();
    }
  });
});
