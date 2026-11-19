import assert from 'node:assert/strict';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { BUILT_IN_ROLES, DelegationRefused } from '@hn/delegate';
import { HnError } from '@hn/core';
import { KeyStore, resolveCaps } from '@hn/provider';
import { NO_ROUTING, checkRouting, loadRouting, modelResolver, openRoles, openSession, parseRouting, type RoutingContext } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir } from '@hn/testkit';

const ROLES = BUILT_IN_ROLES.map((role) => role.name);
const everything = (): boolean => true;
const hosted: RoutingContext = { model: 'claude-opus-5-5', team: false, allowed: everything };
const local: RoutingContext = { model: 'ollama/qwen3:14b', team: false, allowed: everything };
const compatible: RoutingContext = { model: 'fake', baseUrl: 'http://127.0.0.1:1/v1', team: false, allowed: everything };
const text = (value: unknown): string => JSON.stringify(value);
const roleNamed = (name: string) => BUILT_IN_ROLES.find((role) => role.name === name) as (typeof BUILT_IN_ROLES)[number];

describe('parsing routing.json', () => {
  it('reads cheap and roles, and nothing else', () => {
    const parsed = parseRouting(text({ cheap: 'ollama/qwen3:4b', roles: { planner: 'claude-opus-5-5', worker: 'main', scout: 'cheap' } }));
    assert.deepEqual(parsed.problems, []);
    assert.equal(parsed.routing.cheap, 'ollama/qwen3:4b');
    assert.deepEqual([...parsed.routing.roles], [['planner', 'claude-opus-5-5'], ['worker', 'main'], ['scout', 'cheap']]);
    assert.equal(parseRouting('{}').routing.cheap, null);
  });

  it('refuses a misspelled setting instead of ignoring it, and every other malformed thing, naming each', () => {
    assert.match(parseRouting(text({ cheep: 'x' })).problems.join(), /"cheep" is not a setting/);
    assert.match(parseRouting('nope').problems.join(), /not JSON/);
    assert.match(parseRouting('[]').problems.join(), /not an object/);
    assert.match(parseRouting(text({ cheap: 5 })).problems.join(), /"cheap" must be a model name/);
    assert.match(parseRouting(text({ cheap: 'main' })).problems.join(), /not "main" or "cheap"/);
    assert.match(parseRouting(text({ cheap: 'cheap' })).problems.join(), /not "main" or "cheap"/);
    assert.match(parseRouting(text({ cheap: 'two words' })).problems.join(), /"cheap" must be a model name/);
    assert.match(parseRouting(text({ cheap: '' })).problems.join(), /"cheap" must be a model name/);
    assert.match(parseRouting(text({ roles: [] })).problems.join(), /"roles" must be an object/);
    assert.match(parseRouting(text({ roles: { planner: 3 } })).problems.join(), /role planner: the model must be/);
    assert.match(parseRouting(text({ roles: { planner: 'bad\u0007name' } })).problems.join(), /role planner: the model must be/);
  });

  it('keeps a role called __proto__ as an ordinary entry that then fails as a role that does not exist', () => {
    const parsed = parseRouting('{"roles": {"__proto__": "main"}}');
    assert.deepEqual(parsed.problems, []);
    assert.deepEqual([...parsed.routing.roles], [['__proto__', 'main']]);
    assert.match(checkRouting(parsed.routing, ROLES, hosted).join(), /role __proto__ does not exist/);
  });
});

describe('checking routing when the session opens', () => {
  it('refuses a role that does not exist, and lists the ones that do', () => {
    const problems = checkRouting(parseRouting(text({ roles: { scuot: 'main' } })).routing, ROLES, hosted);
    assert.equal(problems.length, 1);
    assert.match(problems[0] as string, /role scuot does not exist \(there are: scout, planner, worker, reviewer\)/);
  });

  it('refuses a model the policy does not allow, for cheap and for a role, but not the keywords main and cheap', () => {
    const only = { ...hosted, allowed: (model: string) => model === 'claude-opus-5-5' };
    const routing = parseRouting(text({ cheap: 'claude-haiku-5-5', roles: { planner: 'gpt-x', worker: 'main', reviewer: 'cheap', scout: 'claude-opus-5-5' } })).routing;
    assert.deepEqual(checkRouting(routing, ROLES, only), ['the policy does not allow the model claude-haiku-5-5', 'the policy does not allow the model gpt-x']);
  });

  it('refuses a model the session could not reach, because a child inherits its parent\'s address', () => {
    const asks = (model: string, context: RoutingContext): string[] => checkRouting(parseRouting(text({ roles: { scout: model } })).routing, ROLES, context);
    // A hosted session can start a local child (no address is inherited), and any Claude model.
    assert.deepEqual(asks('ollama/qwen3:4b', hosted), []);
    assert.deepEqual(asks('claude-haiku-5-5', hosted), []);
    // A local session can name another local model, with or without the prefix, but not a hosted one.
    assert.deepEqual(asks('qwen3:4b', local), []);
    assert.deepEqual(asks('ollama/qwen3:4b', local), []);
    assert.match(asks('claude-haiku-5-5', local).join(), /Anthropic model, but this session runs on a local Ollama model/);
    // A session on an OpenAI-compatible address cannot reach Claude or Ollama models through it.
    assert.deepEqual(asks('fake-small', compatible), []);
    assert.match(asks('claude-haiku-5-5', compatible).join(), /not served by the address this session talks to/);
    assert.match(asks('ollama/qwen3:4b', compatible).join(), /not served by the address this session talks to/);
    // In team mode the broker decides; only the policy applies here.
    assert.deepEqual(asks('claude-haiku-5-5', { ...compatible, team: true }), []);
  });

  it('reports every problem at once, not the first', () => {
    const routing = parseRouting(text({ cheap: 'claude-haiku-5-5', roles: { scuot: 'main', planner: 'claude-opus-5-5' } })).routing;
    const problems = checkRouting(routing, ROLES, { ...local, allowed: () => false });
    assert.ok(problems.length >= 4, problems.join('\n'));
  });
});

describe('loading routing.json', () => {
  it('is nothing at all when there is no file', async () => {
    await withTempDir(async (home) => {
      const loaded = await loadRouting(home, ROLES, hosted);
      assert.equal(loaded.routing, NO_ROUTING);
      assert.deepEqual(loaded.notes, []);
    });
  });

  it('says what it routed, in one line, and stops the session on a bad file with every problem listed', async () => {
    await withTempDir(async (home) => {
      await writeFile(join(home, 'routing.json'), text({ cheap: 'ollama/qwen3:4b', roles: { planner: 'claude-opus-5-5' } }));
      const loaded = await loadRouting(home, ROLES, hosted);
      assert.deepEqual(loaded.notes, ['Model routing from routing.json: cheap = ollama/qwen3:4b, planner = claude-opus-5-5.']);
      await writeFile(join(home, 'routing.json'), text({ cheap: 'claude-haiku-5-5', roles: { scuot: 'main' } }));
      await assert.rejects(loadRouting(home, ROLES, local), (error: unknown) => {
        assert.ok(error instanceof HnError);
        assert.equal(error.code, 'ROUTING_REFUSED');
        assert.match(error.message, /did not start:\n  - role scuot does not exist/);
        assert.match(error.message, /  - claude-haiku-5-5 is an Anthropic model/);
        assert.match(error.message, /Fix or remove /);
        return true;
      });
      await writeFile(join(home, 'routing.json'), ' '.repeat(70 * 1024));
      await assert.rejects(loadRouting(home, ROLES, hosted), /larger than 65536 bytes/);
    });
  });

  it('is not loaded for a session that delegates nothing, so a child never refuses to start over its parent\'s routing', async () => {
    await withTempDir(async (home) => {
      await writeFile(join(home, 'routing.json'), 'this is not json');
      const set = await openRoles({ files: null, hnHome: home, projectRoot: home, trust: null as never });
      assert.equal(set.routing, NO_ROUTING);
      await assert.rejects(openRoles({ files: null, hnHome: home, projectRoot: home, trust: null as never, routing: hosted }), /ROUTING|routing\.json was not used/);
    });
  });
});

describe('the model a role runs on', () => {
  const resolver = (routing = NO_ROUTING, over: Partial<Parameters<typeof modelResolver>[0]> = {}) => modelResolver({ cheap: 'claude-haiku-5-5', model: 'claude-opus-5-5', cli: 'claude-opus-5-5', caps: resolveCaps('claude-opus-5-5'), local: false, allowed: everything, routing, ...over });

  it('is unchanged without routing: the scout on the cheap tier, the rest on the main model', () => {
    assert.equal(resolver()(roleNamed('scout')).model, 'claude-haiku-5-5');
    for (const name of ['planner', 'worker', 'reviewer']) assert.equal(resolver()(roleNamed(name)).model, 'claude-opus-5-5', name);
  });

  it('puts the cheap model where the person said, for the scout and for anything else that means cheap', () => {
    const routing = parseRouting(text({ cheap: 'ollama/qwen3:4b', roles: { reviewer: 'cheap' } })).routing;
    assert.equal(resolver(routing)(roleNamed('scout')).model, 'ollama/qwen3:4b');
    assert.equal(resolver(routing)(roleNamed('reviewer')).model, 'ollama/qwen3:4b');
    assert.equal(resolver(routing)(roleNamed('planner')).model, 'claude-opus-5-5', 'the others stay on the main model');
  });

  it('lets a role name its own model or go back to main, and puts a local model on the local route', () => {
    const routing = parseRouting(text({ roles: { scout: 'main', planner: 'claude-sonnet-5-5' } })).routing;
    assert.equal(resolver(routing)(roleNamed('scout')).model, 'claude-opus-5-5');
    assert.equal(resolver(routing)(roleNamed('planner')).model, 'claude-sonnet-5-5');
    const onOllama = resolver(parseRouting(text({ roles: { planner: 'qwen3:4b' } })).routing, { cli: 'ollama/qwen3:14b', model: 'qwen3:14b', local: true });
    assert.equal(onOllama(roleNamed('planner')).model, 'ollama/qwen3:4b');
    const cheapOnOllama = resolver(parseRouting(text({ cheap: 'qwen3:4b' })).routing, { cli: 'ollama/qwen3:14b', model: 'qwen3:14b', local: true });
    assert.equal(cheapOnOllama(roleNamed('scout')).model, 'ollama/qwen3:4b', 'a cheap model named without the prefix still takes the local route');
  });

  it('refuses, never falls back, when the policy does not allow the routed model, and says which role and model', () => {
    const routing = parseRouting(text({ roles: { planner: 'claude-sonnet-5-5' }, cheap: 'claude-haiku-5-5' })).routing;
    const strict = resolver(routing, { allowed: (model) => model === 'claude-opus-5-5' });
    assert.throws(() => strict(roleNamed('planner')), (error: unknown) => error instanceof DelegationRefused && /does not allow the model claude-sonnet-5-5, which the planner role is routed to/.test(error.message));
    assert.throws(() => strict(roleNamed('scout')), /does not allow the model claude-haiku-5-5, which the scout role is routed to/);
    assert.equal(strict(roleNamed('worker')).model, 'claude-opus-5-5', 'a role that is not routed is untouched');
  });

  it('routing does not widen what a role may do: its tools and mode are the role\'s own', () => {
    const routing = parseRouting(text({ roles: { scout: 'main' } })).routing;
    const resolved = resolver(routing)(roleNamed('scout'));
    assert.deepEqual(Object.keys(resolved).sort(), ['caps', 'model'], 'the resolver answers only which model');
    assert.equal(roleNamed('scout').mode, 'read-only');
  });
});

describe('through the real stack', () => {
  it('runs each role on the model the person routed it to, as the fake provider\'s request log shows', { timeout: 180_000 }, async () => {
    const model = await startFakeOpenAI((request) => {
      const system = String(request.messages[0]?.content ?? '');
      const tools = request.messages.filter((message) => message.role === 'tool').length;
      if (system.includes('You are a scout')) return { text: 'scout report' };
      if (system.includes('You are a planner')) return { text: 'the plan' };
      if (system.includes('You are a reviewer')) return { text: 'no problems found' };
      if (tools === 0) return { calls: [{ id: 's1', name: 'subagent', args: { agent: 'scout', task: 'Look around.' } }] };
      if (tools === 1) return { calls: [{ id: 'p1', name: 'subagent', args: { agent: 'planner', task: 'Plan it.' } }] };
      if (tools === 2) return { calls: [{ id: 'r1', name: 'subagent', args: { agent: 'reviewer', task: 'Review it.' } }] };
      return { text: 'all done' };
    });
    const before = process.env['HN_PARENT_SESSION'];
    try {
      await withTempDir(async (dir) => {
        const root = await realpath(dir);
        const home = join(root, '.home');
        await mkdir(home, { recursive: true });
        await writeFile(join(home, 'routing.json'), text({ cheap: 'fake-small', roles: { planner: 'fake-strong', reviewer: 'main' } }));
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: home }, verify: 'off' }, KeyStore.capture({}));
        assert.ok(session.notes.some((note) => /Model routing from routing\.json: cheap = fake-small, planner = fake-strong, reviewer = main\./.test(note)), session.notes.join('\n'));
        await session.agent.run('Scout, plan and review.');
        const modelOf = (role: string | null): string[] =>
          [...new Set(model.requests.filter((request) => (role === null ? !String(request.messages[0]?.content ?? '').includes('You are a ') : String(request.messages[0]?.content ?? '').includes(`You are a ${role}`))).map((request) => String(request.model)))];
        assert.deepEqual(modelOf('scout'), ['fake-small'], 'the scout runs on the cheap model');
        assert.deepEqual(modelOf('planner'), ['fake-strong'], 'the planner runs on the model named for it');
        assert.deepEqual(modelOf('reviewer'), ['fake'], 'the reviewer was sent back to the main model');
        assert.deepEqual(modelOf(null), ['fake'], 'the session itself is untouched');
        const spawned = session.agent.events.filter((event) => event.type === 'subagent/catalog' && event.data['kind'] === 'spawned').map((event) => `${String(event.data['role'])}:${String(event.data['model'])}`);
        assert.deepEqual(spawned, ['scout:fake-small', 'planner:fake-strong', 'reviewer:fake'], 'and the log records what each role ran on');
        await session.agent.close();
        await session.close();
      });
    } finally {
      if (before === undefined) delete process.env['HN_PARENT_SESSION'];
      else process.env['HN_PARENT_SESSION'] = before;
      await model.close();
    }
  });

  it('refuses to start when the policy denies a routed model, before a single model call, and falls back to nothing', { timeout: 120_000 }, async () => {
    const model = await startFakeOpenAI(() => ({ text: 'never' }));
    try {
      await withTempDir(async (dir) => {
        const root = await realpath(dir);
        const home = join(root, '.home');
        await mkdir(home, { recursive: true });
        await writeFile(join(home, 'policy.json'), text({ version: 1, name: 'org', models: { allow: ['fake', 'fake-small'] } }));
        await writeFile(join(home, 'routing.json'), text({ cheap: 'fake-small', roles: { planner: 'fake-strong' } }));
        await assert.rejects(openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: home }, verify: 'off' }, KeyStore.capture({})), (error: unknown) => error instanceof HnError && error.code === 'ROUTING_REFUSED' && /the policy does not allow the model fake-strong/.test(error.message));
        assert.equal(model.requests.length, 0, 'nothing was sent anywhere');
      });
    } finally {
      await model.close();
    }
  });

  it('ignores a routing.json inside the project: only the person\'s own home can route their models', { timeout: 120_000 }, async () => {
    const model = await startFakeOpenAI((request) => {
      const system = String(request.messages[0]?.content ?? '');
      if (system.includes('You are a planner')) return { text: 'the plan' };
      return request.messages.filter((message) => message.role === 'tool').length === 0 ? { calls: [{ id: 'p1', name: 'subagent', args: { agent: 'planner', task: 'Plan it.' } }] } : { text: 'done' };
    });
    const before = process.env['HN_PARENT_SESSION'];
    try {
      await withTempDir(async (dir) => {
        const root = await realpath(dir);
        await mkdir(join(root, '.hn'), { recursive: true });
        await writeFile(join(root, '.hn', 'routing.json'), text({ roles: { planner: 'attacker-model' } }));
        await writeFile(join(root, 'routing.json'), text({ roles: { planner: 'attacker-model' } }));
        const session = await openSession({ workdir: root, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, env: { HN_HOME: join(root, '.home') }, verify: 'off' }, KeyStore.capture({}));
        await session.agent.run('Plan.');
        assert.ok(model.requests.every((request) => request.model === 'fake'), [...new Set(model.requests.map((request) => request.model))].join());
        await session.agent.close();
        await session.close();
      });
    } finally {
      if (before === undefined) delete process.env['HN_PARENT_SESSION'];
      else process.env['HN_PARENT_SESSION'] = before;
      await model.close();
    }
  });
});
