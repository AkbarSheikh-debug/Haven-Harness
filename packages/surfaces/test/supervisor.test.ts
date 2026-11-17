import assert from 'node:assert/strict';
import { mkdir, readFile, realpath } from 'node:fs/promises';
import { connect } from 'node:net';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { MAX_INSTANCES, Supervisor, type InstanceRecord } from '@hn/orchestrate';
import { KeyStore } from '@hn/provider';
import { Harness, JsonRpcPeer, openSupervisorEndpoint, rpcInstanceStarter } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

describe('the supervisor (experimental)', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const users = request.messages.filter((message) => message.role === 'user').map((message) => String(message.content)).filter((text) => !text.startsWith('<'));
      return { text: `heard: ${users.join(' / ')}` };
    });
  });
  after(async () => {
    await model.close();
  });

  it('starts instances, prompts as ipc, forks and clones, reports state, marks a killed one lost, refuses past its limit, and closes', { timeout: 180_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const [a, b] = [join(root, 'a'), join(root, 'b')];
      await mkdir(a);
      await mkdir(b);
      const home = join(root, '.home');
      const env = { ...process.env, HN_HOME: home };
      const file = join(home, 'supervisor', 'instances.json');
      const supervisor = new Supervisor({ start: rpcInstanceStarter({ keys: KeyStore.capture({}), env, args: ['--model', 'fake', '--base-url', model.url, '--window', '64000'] }), file, maxInstances: 4, heartbeatTimeoutMs: 5_000 });
      let first: InstanceRecord | undefined;
      try {
        assert.equal(MAX_INSTANCES, 100);
        first = await supervisor.newSession({ workdir: a, verify: 'off' });
        const second = await supervisor.newSession({ workdir: b, verify: 'off' });
        assert.equal(first.status, 'running');
        assert.notEqual(first.sessionId, second.sessionId);
        const turn = (await supervisor.prompt(first.id, 'remember the colour blue')) as { text: string };
        assert.match(turn.text, /heard: remember the colour blue/);

        const fork = await supervisor.fork(first.id);
        assert.equal(fork.from, first.id);
        assert.match(((await supervisor.prompt(fork.id, 'what colour?')) as { text: string }).text, /remember the colour blue \/ what colour\?/, 'the fork holds the finished turns');
        const clone = await supervisor.clone(first.id);
        const fresh = ((await supervisor.prompt(clone.id, 'what colour?')) as { text: string }).text;
        assert.doesNotMatch(fresh, /blue/, 'a clone starts empty');
        await assert.rejects(supervisor.newSession({ workdir: a }), /4 instances are already running/);

        const state = await supervisor.getState();
        assert.equal(state.instances.filter((instance) => instance.status === 'running').length, 4);
        assert.equal(((state.instances.find((instance) => instance.id === first?.id) as { state: { turns: number } }).state).turns, 1);

        process.kill(second.pid as number);
        await new Promise((resolve) => setTimeout(resolve, 500));
        await supervisor.heartbeat();
        await supervisor.flush();
        const saved = JSON.parse(await readFile(file, 'utf8')) as { instances: InstanceRecord[] };
        assert.equal(saved.instances.find((instance) => instance.id === second.id)?.status, 'lost');
        assert.equal(saved.instances.find((instance) => instance.id === first?.id)?.status, 'running');
        await supervisor.stop(clone.id);
        assert.equal((await supervisor.getState(clone.id)).instances[0]?.status, 'stopped');
      } finally {
        await supervisor.close();
      }
      const closed = JSON.parse(await readFile(file, 'utf8')) as { instances: InstanceRecord[] };
      assert.ok(closed.instances.every((instance) => instance.status !== 'running'));
      // What the supervisor forwarded is ipc in the session's own log, never the user's words.
      const reopened = new Harness({ workdir: a, sessionId: first?.sessionId as string, model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: home } });
      try {
        const session = await reopened.open();
        const row = session.agent.events.find((event) => event.type === 'user/message' && event.data['text'] === 'remember the colour blue');
        assert.equal(row?.origin, 'ipc');
      } finally {
        await reopened.close();
      }
    });
  });

  it('its endpoint drops a request without the token and answers one with it', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const home = join(await realpath(dir), '.home');
      const supervisor = new Supervisor({ start: () => { throw new Error('no instances in this test'); }, file: join(home, 'supervisor', 'instances.json') });
      const refused: string[] = [];
      const endpoint = await openSupervisorEndpoint(home, supervisor, (why) => refused.push(why));
      const call = async (params: Record<string, unknown>) => {
        const socket = connect(endpoint.path);
        await new Promise((resolve) => socket.once('connect', resolve));
        const peer = new JsonRpcPeer(socket, socket);
        try {
          return await peer.request('get_state', params, 5_000);
        } finally {
          socket.destroy();
        }
      };
      try {
        await assert.rejects(call({}), /closed/);
        await assert.rejects(call({ token: 'guess' }), /closed/);
        assert.equal(refused.length, 2);
        assert.deepEqual(await call({ token: endpoint.token }), { instances: [] });
        const saved = JSON.parse(await readFile(endpoint.file, 'utf8')) as Record<string, unknown>;
        assert.equal(saved['token'], endpoint.token);
      } finally {
        await endpoint.close();
      }
    });
  });
});
