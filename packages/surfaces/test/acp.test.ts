import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { access, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { JsonRpcPeer } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));
const exists = (path: string): Promise<boolean> => access(path).then(() => true, () => false);
const NOTES = 'alpha\nbeta\n';
/** A right-to-left override and a zero-width space inside a name, as an attacker would hide them. */
const HIDDEN_CONTENT = 'safe‮gnp.exe​\n';
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
      if (prompt.startsWith('EDIT ')) {
        const name = prompt.slice(5).trim();
        if (results.length === 0) return { calls: [{ id: 'r1', name: 'read_file', args: { path: name } }] };
        if (results.length === 1) return { calls: [{ id: 'e1', name: 'edit_file', args: { path: name, old_string: 'beta', new_string: 'gamma' } }] };
        return { text: 'edited' };
      }
      if (prompt.startsWith('HIDDEN ')) {
        const name = prompt.slice(7).trim();
        if (results.length === 0) return { calls: [{ id: 'h1', name: 'write_file', args: { path: name, content: HIDDEN_CONTENT } }] };
        return { text: 'written' };
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

  it('attack: editor_diff_shows_exact_bytes_written editor_diff_reveals_hidden_characters - shows an edit as a diff that matches what is written, shows hidden characters instead of stripping them, and reports a refused call as failed', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const project = join(top, 'project');
      await mkdir(project);
      await writeFile(join(project, 'notes.txt'), NOTES);
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
      const diffOf = (index: number): { type: string; path: string; oldText: string | null; newText: string } => ((permissions[index]?.['toolCall'] as { content: unknown[] }).content[0] as never);
      try {
        await editor.request('initialize', { protocolVersion: 1, clientCapabilities: {} });
        const { sessionId } = (await editor.request('session/new', { cwd: project, mcpServers: [] })) as { sessionId: string };

        await editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'EDIT notes.txt' }] });
        assert.equal(permissions.length, 1, 'the edit was never asked about');
        const call = permissions[0]?.['toolCall'] as { kind: string; locations: { path: string }[] };
        assert.equal(call.kind, 'edit');
        assert.deepEqual(call.locations, [{ path: 'notes.txt' }]);
        const shown = diffOf(0);
        assert.deepEqual({ type: shown.type, path: shown.path, oldText: shown.oldText }, { type: 'diff', path: 'notes.txt', oldText: NOTES });
        assert.equal(await readFile(join(project, 'notes.txt'), 'utf8'), shown.newText, 'what the editor was shown is not what was written');
        assert.equal(shown.newText, 'alpha\ngamma\n');
        assert.ok(updates.some((u) => u['sessionUpdate'] === 'tool_call' && u['title'] === 'edit_file' && u['kind'] === 'edit'));

        // A refused write is reported failed, never completed.
        answer = { outcome: { outcome: 'selected', optionId: 'reject-once' } };
        const mark = updates.length;
        await writeFile(join(project, 'notes.txt'), NOTES);
        await editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'EDIT notes.txt' }] });
        assert.equal(permissions.length, 2);
        assert.equal(await readFile(join(project, 'notes.txt'), 'utf8'), NOTES);
        const finished = updates.slice(mark).filter((u) => u['sessionUpdate'] === 'tool_call_update').map((u) => u['status']);
        assert.ok(finished.includes('failed'), 'the refused edit was not reported failed');
        assert.deepEqual(finished.filter((status) => status === 'failed').length, 1, 'only the refused call may be failed; the read completed');
        assert.ok(finished.includes('completed'));

        // A new file has no old text, and hidden characters are written out, not removed.
        answer = { outcome: { outcome: 'selected', optionId: 'allow-once' } };
        await editor.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: 'HIDDEN sneaky.txt' }] });
        const hidden = diffOf(2);
        assert.equal(hidden.oldText, null);
        assert.equal(hidden.newText, 'safe\\u{202e}gnp.exe\\u{200b}\n');
        assert.equal(await readFile(join(project, 'sneaky.txt'), 'utf8'), HIDDEN_CONTENT, 'the file holds the real characters');
      } finally {
        child.stdin.end();
        await new Promise((resolve) => child.once('close', resolve));
      }
    });
  });
});
