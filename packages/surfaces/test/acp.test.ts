import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { access, mkdir, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { JsonRpcPeer } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));
const exists = (path: string): Promise<boolean> => access(path).then(() => true, () => false);
/** Tool results since the last user message: earlier turns' results must not make the fake skip this turn's call. */
const toolResults = (request: { messages: readonly { role: string; content?: unknown }[] }): string[] => {
  const lastUser = request.messages.map((message) => message.role).lastIndexOf('user');
  return request.messages.slice(lastUser + 1).filter((message) => message.role === 'tool').map((message) => String(message.content));
};

describe('the ACP door (hn acp), as an editor drives it', () => {
  let model: FakeOpenAI;
  let release: (() => void) | null = null;
  before(async () => {
    model = await startFakeOpenAI(async (request) => {
      const prompt = lastContent(request, 'user');
      const results = toolResults(request);
      if (prompt.startsWith('WRITE ')) {
        const name = prompt.slice(6).trim();
        if (results.length === 0) return { calls: [{ id: 'w1', name: 'write_file', args: { path: name, content: 'from the editor\n' } }] };
        return { text: `\u001b]52;c;Y2xpcA==\u0007done: ${results[0]}` };
      }
      if (prompt.startsWith('SLOW')) {
        await new Promise<void>((resolve) => (release = resolve));
        return { text: 'too late' };
      }
      return { text: 'hello from hn' };
    });
  });
  after(async () => {
    release?.();
    await model.close();
  });

  it('initializes, opens a session, streams text, asks permission with allow-once and reject only, honours the answer, and cancels', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const project = join(top, 'project');
      await mkdir(project);
      const child: ChildProcessWithoutNullStreams = spawn(process.execPath, [launcher, 'acp', '--model', 'fake', '--base-url', model.url, '--window', '64000'], { cwd: project, env: { ...process.env, HN_HOME: join(top, 'home') }, stdio: ['pipe', 'pipe', 'pipe'] });
      const updates: Record<string, unknown>[] = [];
      const permissions: Record<string, unknown>[] = [];
      let answer: unknown = { outcome: { outcome: 'selected', optionId: 'allow-once' } };
      const editor = new JsonRpcPeer(child.stdout, child.stdin, {
        request: async (method, params) => {
          if (method !== 'session/request_permission') throw new Error(`unexpected ${method}`);
          permissions.push(params as Record<string, unknown>);
          return answer;
        },
        notification: (method, params) => {
          if (method === 'session/update') updates.push((params as { update: Record<string, unknown> }).update);
        },
      });
      try {
        const init = (await editor.request('initialize', { protocolVersion: 1, clientCapabilities: { fs: { readTextFile: true, writeTextFile: true } } })) as Record<string, unknown>;
        assert.equal(init['protocolVersion'], 1);
        const { sessionId } = (await editor.request('session/new', { cwd: project, mcpServers: [{ name: 'editor-mcp', command: 'C:/evil.exe', args: [] }] })) as { sessionId: string };
        assert.match(sessionId, /^[A-Za-z0-9-]+$/);
        await new Promise((resolve) => setTimeout(resolve, 200));
        assert.ok(updates.some((u) => JSON.stringify(u).includes('were not connected')), 'the editor was not told its MCP servers were ignored');

        const said = (await editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'say hello' }] })) as { stopReason: string };
        assert.equal(said.stopReason, 'end_turn');
        assert.ok(updates.some((u) => u['sessionUpdate'] === 'agent_message_chunk' && JSON.stringify(u).includes('hello from hn')));

        const wrote = (await editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'WRITE yes.txt' }] })) as { stopReason: string };
        assert.equal(wrote.stopReason, 'end_turn');
        assert.equal(permissions.length, 1);
        const options = (permissions[0]?.['options'] as { optionId: string; kind: string }[]).map((option) => option.kind);
        assert.deepEqual(options, ['allow_once', 'reject_once'], 'only once-at-a-time choices are offered');
        assert.ok(await exists(join(project, 'yes.txt')));
        assert.ok(updates.some((u) => u['sessionUpdate'] === 'tool_call' && u['title'] === 'write_file'));
        assert.ok(updates.some((u) => u['sessionUpdate'] === 'tool_call_update' && u['status'] === 'completed'));
        assert.ok(!JSON.stringify(updates).includes('\u001b'), 'an escape sequence from the model reached the editor');

        answer = { outcome: { outcome: 'selected', optionId: 'reject-once' } };
        await editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'WRITE no.txt' }] });
        assert.equal(await exists(join(project, 'no.txt')), false);
        assert.equal(permissions.length, 2, 'the write after a reject was never asked about, so the reject was not tested');
        answer = { outcome: { outcome: 'selected', optionId: 'allow-always' } };
        await editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'WRITE always.txt' }] });
        assert.equal(permissions.length, 3, 'the allow-always answer was never given');
        assert.equal(await exists(join(project, 'always.txt')), false, 'an option that was never offered counted as a yes');
        answer = { outcome: { outcome: 'cancelled' } };
        await editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'WRITE cancelled.txt' }] });
        assert.equal(permissions.length, 4, 'the cancelled answer was never given');
        assert.equal(await exists(join(project, 'cancelled.txt')), false);

        const slow = editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'SLOW' }] }) as Promise<{ stopReason: string }>;
        await new Promise((resolve) => setTimeout(resolve, 500));
        editor.notify('session/cancel', { sessionId });
        assert.equal((await slow).stopReason, 'cancelled');
        release?.();

        await assert.rejects(editor.request('session/prompt', { sessionId, prompt: [{ type: 'image', data: 'x', mimeType: 'image/png' }] }), /not accepted/);
        await assert.rejects(editor.request('session/set_mode', { sessionId, modeId: 'yolo' }), /chosen when hn starts/);
      } finally {
        child.stdin.end();
        await new Promise((resolve) => child.once('close', resolve));
      }
    });
  });
});
