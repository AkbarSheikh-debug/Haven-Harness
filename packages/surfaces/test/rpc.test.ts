import assert from 'node:assert/strict';
import { access, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { after, before, describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import { serveRpc, startRpcClient, type RpcCard } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const exists = (path: string): Promise<boolean> => access(path).then(() => true, () => false);
const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);

describe('the JSON-RPC door', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const users = request.messages.filter((message) => message.role === 'user').map((message) => String(message.content));
      const last = users.at(-1) ?? '';
      const start = request.messages.findLastIndex((message) => message.role === 'user' && !String(message.content).startsWith('<'));
      const tools = request.messages.slice(start).filter((message) => message.role === 'tool').length;
      if (last.includes('WRITE') && tools === 0) return { calls: [{ id: 'w1', name: 'write_file', args: { path: 'out.txt', content: 'from rpc\n' } }] };
      if (last.includes('WRITE')) return { text: `wrote: ${String(request.messages.at(-1)?.content).slice(0, 60)}` };
      if (last.includes('COLOUR')) return { text: `red ${ESC}[31mtext${ESC}[0m and ${ESC}]52;c;ZXZpbA==${BEL}clipboard` };
      return { text: `heard: ${users.join(' / ').slice(-200)}` };
    });
  });
  after(async () => {
    await model.close();
  });

  const envFor = (root: string): NodeJS.ProcessEnv => ({ ...Object.fromEntries(Object.entries(process.env).filter(([name]) => name !== 'HN_PARENT_SESSION' && !name.endsWith('_API_KEY'))), HN_HOME: join(root, '.home') });
  const args = () => ['--model', 'fake', '--base-url', model.url, '--window', '64000'];

  it('drives a real hn rpc process: open, prompt with streamed text, steer, state, fork, close, shutdown', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const events: string[] = [];
      const { client, process: child } = startRpcClient({ cwd: root, env: envFor(root), args: args(), onEvent: (_id, event) => event.type === 'text' && events.push(event.text ?? '') });
      try {
        const hello = (await client.initialize()) as Record<string, unknown>;
        assert.equal(hello['server'], 'hn');
        assert.equal(hello['approvals'], false);
        const opened = await client.openSession({ workdir: root, verify: 'off' });
        assert.equal(opened.mode, 'read-only', 'with nobody to approve, the default mode only looks');
        const first = await client.prompt(opened.sessionId, 'hello there');
        assert.equal(first.end, 'done');
        assert.match(first.text, /heard: [^]*hello there/);
        assert.ok(events.join('').includes('heard:'), 'text was streamed as session/event notifications');
        await client.steer(opened.sessionId, 'and mind the tests');
        const second = await client.prompt(opened.sessionId, 'carry on');
        assert.match(second.text, /and mind the tests/, 'a steer between turns is seen by the next one');
        const state = await client.state(opened.sessionId);
        assert.equal(state['turns'], 2);
        const forked = await client.fork(opened.sessionId);
        assert.notEqual(forked, opened.sessionId);
        const again = await client.openSession({ workdir: root, verify: 'off', sessionId: forked });
        assert.match((await client.prompt(again.sessionId, 'and now?')).text, /hello there/, 'the fork holds the finished turns');
        await assert.rejects(client.openSession({ workdir: root, sessionId: forked }), /already open/);
        await assert.rejects(client.openSession({ workdir: 'relative/path' }), /absolute/);
        await assert.rejects(client.openSession({ workdir: root, mode: 'superuser' }), /mode must be one of/);
        await client.closeSession(opened.sessionId);
        await assert.rejects(client.prompt(opened.sessionId, 'hi'), /no open session/);
        await client.shutdown();
        assert.equal(await child.exited, 0);
      } finally {
        child.kill();
      }
    });
  });

  it('sends approval cards to a client that can answer, and refuses them for one that cannot; model text is sanitized', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const cards: RpcCard[] = [];
      const answering = startRpcClient({ cwd: root, env: envFor(root), args: args(), approve: async (card) => (cards.push(card), 'once') });
      const silent = startRpcClient({ cwd: root, env: envFor(root), args: args() });
      try {
        await answering.client.initialize();
        const yes = await answering.client.openSession({ workdir: root, verify: 'off' });
        assert.equal(yes.mode, 'safe');
        const wrote = await answering.client.prompt(yes.sessionId, 'WRITE it');
        assert.equal(await readFile(join(root, 'out.txt'), 'utf8'), 'from rpc\n');
        assert.equal(cards.length, 1);
        assert.equal(cards[0]?.tool, 'write_file');
        assert.match(wrote.text, /wrote/);
        const coloured = await answering.client.prompt(yes.sessionId, 'COLOUR please');
        assert.ok(!coloured.text.includes(ESC), 'no escape sequence crosses the door');
        assert.ok(!coloured.text.includes(BEL));
        await answering.client.shutdown();

        await writeFile(join(root, 'out.txt'), 'untouched\n');
        await silent.client.initialize();
        const no = await silent.client.openSession({ workdir: root, mode: 'safe', verify: 'off' });
        const refused = await silent.client.prompt(no.sessionId, 'WRITE it');
        assert.match(refused.text, /nobody is here/);
        assert.equal(await readFile(join(root, 'out.txt'), 'utf8'), 'untouched\n');
        await silent.client.shutdown();
      } finally {
        answering.process.kill();
        silent.process.kill();
      }
    });
  });

  it('answers malformed lines with JSON-RPC errors and keeps serving; refuses a ninth session', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const toServer = new PassThrough();
      const fromServer = new PassThrough();
      const served = serveRpc(toServer, fromServer, { keys: KeyStore.capture({}), cwd: root, defaults: { model: 'fake', baseUrl: model.url, window: 64_000 }, env: { HN_HOME: join(root, '.home') }, sessionExtras: { verify: 'off', persist: false } });
      const lines: Record<string, unknown>[] = [];
      let partial = '';
      fromServer.setEncoding('utf8').on('data', (chunk: string) => {
        partial += chunk;
        for (let end = partial.indexOf('\n'); end !== -1; end = partial.indexOf('\n')) {
          lines.push(JSON.parse(partial.slice(0, end)) as Record<string, unknown>);
          partial = partial.slice(end + 1);
        }
      });
      const answer = async (count: number) => {
        while (lines.length < count) await new Promise((resolve) => setTimeout(resolve, 10));
        return lines[count - 1] as { id: unknown; error?: { code: number; message: string }; result?: unknown };
      };
      toServer.write('this is not json\n');
      assert.equal((await answer(1)).error?.code, -32700);
      toServer.write('[1, 2, 3]\n');
      assert.equal((await answer(2)).error?.code, -32600);
      toServer.write('{"jsonrpc":"2.0","id":7,"method":"session/explode"}\n');
      assert.deepEqual([(await answer(3)).id, (await answer(3)).error?.code], [7, -32601]);
      toServer.write('{"jsonrpc":"2.0","id":8,"method":"session/open","params":[1]}\n');
      assert.equal((await answer(4)).error?.code, -32602);
      toServer.write('{"jsonrpc":"2.0","id":9,"method":"session/prompt","params":{"sessionId":"nope","text":"hi"}}\n');
      assert.match(String((await answer(5)).error?.message), /no open session/);
      toServer.write(`${'x'.repeat(1024 * 1024 + 10)}\n`);
      assert.equal((await answer(6)).error?.code, -32600);
      // Still serving after all of that.
      toServer.write('{"jsonrpc":"2.0","id":10,"method":"initialize","params":{}}\n');
      assert.equal(((await answer(7)).result as Record<string, unknown>)['server'], 'hn');
      for (let index = 0; index < 8; index += 1) toServer.write(`{"jsonrpc":"2.0","id":${100 + index},"method":"session/open","params":{}}\n`);
      while (lines.filter((line) => typeof line['id'] === 'number' && (line['id'] as number) >= 100).length < 8) await new Promise((resolve) => setTimeout(resolve, 20));
      assert.ok(lines.filter((line) => typeof line['id'] === 'number' && (line['id'] as number) >= 100).every((line) => line['result'] !== undefined), 'eight sessions opened');
      toServer.write('{"jsonrpc":"2.0","id":200,"method":"session/open","params":{}}\n');
      const ninth = await answer(lines.length + 1);
      assert.match(String(ninth.error?.message), /8 sessions are already open/);
      toServer.end();
      await served;
      assert.equal(await exists(join(root, '.home', 'sessions')), false, 'persist: false sessions left nothing in the home');
    });
  });
});
