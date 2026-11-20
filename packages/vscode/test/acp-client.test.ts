import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { lastContent, startFakeOpenAI, withTempDir } from '@hn/testkit';
import { AcpClient, MAX_CHUNK_CHARS, MAX_DIFF_CHARS, MAX_TURN_CHARS, readApproval, type AgentEvent, type ApprovalRequest } from '../src/acp-client.ts';

const launcher = fileURLToPath(new URL('../../surfaces/bin/hn.mjs', import.meta.url));
const agentScript = fileURLToPath(new URL('./fixtures/fake-agent.mjs', import.meta.url));
const NOTES = 'alpha\nbeta\n';

/** Tool results since the last user message, so an earlier turn's results never make the fake skip this turn's call. */
const toolResults = (request: { messages: readonly { role: string; content?: unknown }[] }): string[] => {
  const lastUser = request.messages.map((message) => message.role).lastIndexOf('user');
  return request.messages.slice(lastUser + 1).filter((message) => message.role === 'tool').map((message) => String(message.content));
};

interface Seen {
  events: AgentEvent[];
  approvals: ApprovalRequest[];
  exits: string[];
}

function handlers(answer: () => 'allow' | 'reject', seen: Seen) {
  return {
    event: (event: AgentEvent) => void seen.events.push(event),
    approve: async (request: ApprovalRequest) => (seen.approvals.push(request), answer()),
    exited: (reason: string) => void seen.exits.push(reason),
  };
}

const fresh = (): Seen => ({ events: [], approvals: [], exits: [] });
const said = (seen: Seen): string => seen.events.flatMap((event) => (event.type === 'message' ? [event.text] : [])).join('');

describe('the editor ACP client against a real hn acp process', () => {
  it('opens a session, streams, shows an edit as a diff, applies it only on allow once, and cancels', { timeout: 180_000 }, async () => {
    const model = await startFakeOpenAI(async (request) => {
      const prompt = lastContent(request, 'user');
      const results = toolResults(request);
      if (prompt.startsWith('EDIT ')) {
        const name = prompt.slice(5).trim();
        if (results.length === 0) return { calls: [{ id: 'r1', name: 'read_file', args: { path: name } }] };
        if (results.length === 1) return { calls: [{ id: 'e1', name: 'edit_file', args: { path: name, old_string: 'beta', new_string: 'gamma' } }] };
        return { text: 'edited' };
      }
      if (prompt.startsWith('SLOW')) {
        await new Promise((resolve) => setTimeout(resolve, 20_000));
        return { text: 'too late' };
      }
      return { text: 'hello from hn' };
    });
    try {
      await withTempDir(async (dir) => {
        const top = await realpath(dir);
        const project = join(top, 'project');
        await mkdir(project);
        await writeFile(join(project, 'notes.txt'), NOTES);
        const seen = fresh();
        let answer: 'allow' | 'reject' = 'allow';
        const client = await AcpClient.start(
          { command: process.execPath, args: [launcher, 'acp', '--model', 'fake', '--base-url', model.url, '--window', '64000'], cwd: project, env: { ...process.env, HN_HOME: join(top, 'home') } },
          handlers(() => answer, seen),
        );
        try {
          const { sessionId, meta } = await client.newSession(project);
          assert.deepEqual(meta, { tier: 2, mode: 'safe', sandbox: false }, 'the editor was not told where the session runs');

          assert.equal(await client.prompt(sessionId, 'say hello'), 'end_turn');
          assert.match(said(seen), /hello from hn/);

          assert.equal(await client.prompt(sessionId, 'EDIT notes.txt'), 'end_turn');
          assert.equal(seen.approvals.length, 1);
          assert.equal(seen.approvals[0]?.kind, 'edit');
          assert.deepEqual(seen.approvals[0]?.diff, { path: 'notes.txt', oldText: NOTES, newText: 'alpha\ngamma\n', cut: false });
          assert.equal(await readFile(join(project, 'notes.txt'), 'utf8'), 'alpha\ngamma\n');
          assert.ok(seen.events.some((event) => event.type === 'tool-update' && event.status === 'completed'));

          answer = 'reject';
          await writeFile(join(project, 'notes.txt'), NOTES);
          const before = seen.events.length;
          await client.prompt(sessionId, 'EDIT notes.txt');
          assert.equal(seen.approvals.length, 2, 'the second edit was never asked about');
          assert.equal(await readFile(join(project, 'notes.txt'), 'utf8'), NOTES, 'a rejected edit was applied');
          assert.ok(seen.events.slice(before).some((event) => event.type === 'tool-update' && event.status === 'failed'), 'the rejected edit was not reported failed');

          const slow = client.prompt(sessionId, 'SLOW');
          await new Promise((resolve) => setTimeout(resolve, 500));
          client.cancel(sessionId);
          assert.equal(await slow, 'cancelled');
          await assert.rejects(client.prompt('nope', 'x'), /no such session/);
        } finally {
          await client.close();
        }
        assert.deepEqual(seen.exits, [], 'a close the editor asked for was reported as the agent dying');
      });
    } finally {
      await model.close();
    }
  });
});

/**
 * Every client the tests start. A test that fails (or a client that wrongly starts) must not leave its agent process
 * running: the test runner would wait for it to exit, so a failure would look like a hang.
 */
const started: AcpClient[] = [];
after(async () => {
  await Promise.all(started.map((client) => client.close().catch(() => undefined)));
});

/** Starts the scripted agent. `FAKE_AGENT_LOG` collects what the client answered. */
async function scripted(mode: string, seen: Seen, answer: () => 'allow' | 'reject' = () => 'allow') {
  const dir = await realpath(await (await import('node:fs/promises')).mkdtemp(join((await import('node:os')).tmpdir(), 'hn-vscode-')));
  const log = join(dir, 'log.jsonl');
  await writeFile(log, '');
  const client = await AcpClient.start({ command: process.execPath, args: [agentScript, mode], cwd: dir, env: { ...process.env, FAKE_AGENT_LOG: log } }, handlers(answer, seen));
  started.push(client);
  const logged = async (): Promise<Record<string, unknown>[]> => (await readFile(log, 'utf8')).split('\n').filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
  return { client, logged, dir };
}

describe('the editor ACP client against an agent that misbehaves', () => {
  it('attack: editor_agent_cannot_read_files_or_start_terminals editor_agent_cannot_pick_allow_always editor_oversized_line_and_garbage_contained - survives garbage, an oversized line, text for unknown sessions, escapes, file and terminal requests, and a made-up stop reason', { timeout: 60_000 }, async () => {
    const seen = fresh();
    const { client, logged } = await scripted('hostile', seen);
    try {
      const { sessionId, meta } = await client.newSession(process.cwd());
      assert.deepEqual(meta, { mode: 'safe' }, 'a malformed tier or sandbox value was believed, or the mode kept its escape');
      assert.equal(await client.prompt(sessionId, 'go'), 'end_turn', 'an unknown stop reason was passed on');

      const text = said(seen);
      assert.ok(!text.includes('ghost'), 'text for a session that was never opened was shown');
      assert.ok(!JSON.stringify(seen.events).includes('\\u001b') && ![...text].some((char) => char === '\u001b' || char === '‮'), 'an escape or bidi character reached the view');
      assert.match(text, /hello world/);
      assert.match(text, /after the big line/, 'one oversized line stopped the connection');
      assert.ok(seen.events.every((event) => event.type === 'tool' || event.type === 'tool-update' || event.text.length <= MAX_CHUNK_CHARS), 'a chunk was not capped');

      const tool = seen.events.find((event) => event.type === 'tool');
      assert.ok(tool?.type === 'tool' && tool.kind === 'other' && tool.status === 'in_progress' && tool.title === 'run it', 'an invented kind or status, or an escape in a title, was passed on');
      assert.ok(!seen.events.some((event) => event.type === 'tool-update' && (event.status as string) === 'nonsense'));

      const answers = await logged();
      const byKey = (key: string): Record<string, unknown> => (answers.find((entry) => key in entry)?.[key] ?? {}) as Record<string, unknown>;
      assert.ok('error' in byKey('file'), 'a file read request was served');
      assert.ok('error' in byKey('terminal'), 'a terminal request was served');
      // The agent listed allow-always first. Only the allow-once option may be chosen.
      assert.deepEqual(byKey('first')['result'], { outcome: { outcome: 'selected', optionId: 'once' } });
      assert.deepEqual(byKey('onlyAlways')['result'], { outcome: { outcome: 'cancelled' } }, 'a request offering only allow-always was answered yes');
      assert.ok('error' in byKey('ghost'), 'a permission request for an unknown session was asked about');

      const request = seen.approvals[0];
      assert.equal(request?.title, 'write x red');
      assert.equal(request?.diff?.path, 'a\\u{202e}txt.exe', 'a hidden character in a path was stripped instead of shown');
      assert.equal(request?.diff?.oldText, 'old\\u{200b}');
      assert.equal(request?.diff?.cut, true);
      assert.ok((request?.diff?.newText.length ?? 0) <= MAX_DIFF_CHARS, 'a huge diff was not capped');
    } finally {
      await client.close();
    }
  });

  it('attack: editor_reject_is_never_turned_into_allow - never allows when the person did not', { timeout: 60_000 }, async () => {
    const seen = fresh();
    const { client, logged } = await scripted('hostile', seen, () => 'reject');
    try {
      const { sessionId } = await client.newSession(process.cwd());
      await client.prompt(sessionId, 'go');
      const first = ((await logged()).find((entry) => 'first' in entry)?.['first'] ?? {}) as Record<string, unknown>;
      assert.deepEqual(first['result'], { outcome: { outcome: 'selected', optionId: 'no' } });
    } finally {
      await client.close();
    }
  });

  it('attack: editor_text_flood_contained - drops text beyond one turn\'s limit and says so once', { timeout: 60_000 }, async () => {
    const seen = fresh();
    const { client } = await scripted('flood', seen);
    try {
      const { sessionId } = await client.newSession(process.cwd());
      await client.prompt(sessionId, 'go');
      const total = seen.events.reduce((sum, event) => sum + (event.type === 'message' ? event.text.length : 0), 0);
      assert.ok(total <= MAX_TURN_CHARS + 1_000, `${total} characters were shown`);
      assert.equal(said(seen).split('too much text in one turn').length - 1, 1);
    } finally {
      await client.close();
    }
  });

  it('rejects the turn and reports why when the agent dies mid-turn', { timeout: 60_000 }, async () => {
    const seen = fresh();
    const { client } = await scripted('die', seen);
    const { sessionId } = await client.newSession(process.cwd());
    await assert.rejects(client.prompt(sessionId, 'go'), /stopped/);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(seen.exits.length, 1);
    assert.match(seen.exits[0] ?? '', /exit code 3/);
    assert.match(seen.exits[0] ?? '', /the agent crashed badly/, 'the last words were not shown, or kept their escape');
    assert.equal(client.alive, false);
    await assert.rejects(client.newSession(process.cwd()), /closed|stopped/);
  });

  it('refuses a protocol version it does not speak, and a command that is not there', { timeout: 60_000 }, async () => {
    await assert.rejects(scripted('oldproto', fresh()), /different version/);
    await assert.rejects(AcpClient.start({ command: 'hn-does-not-exist-12345', args: [], cwd: process.cwd() }, handlers(() => 'reject', fresh())), /Install hn, or set hn.path/);
  });

  it('sends no MCP servers and offers the agent no file or terminal access', { timeout: 60_000 }, async () => {
    const seen = fresh();
    const { client, logged } = await scripted('hostile', seen);
    try {
      await client.newSession('/some/where');
      assert.deepEqual((await logged())[0], { newParams: { cwd: '/some/where', mcpServers: [] } });
    } finally {
      await client.close();
    }
  });
});

describe('readApproval', () => {
  it('shows what it was given and offers only the two answers it may give', () => {
    const none = readApproval('s', { toolCall: { title: 'x', kind: 'execute' }, options: [{ optionId: 'a', kind: 'allow_always' }, 'junk', { kind: 'allow_once' }] });
    assert.equal(none.allowId, undefined, 'an option with no id, or allow-always, counted as allow-once');
    assert.equal(none.rejectId, undefined);
    assert.equal(none.request.kind, 'execute');
    const odd = readApproval('s', { toolCall: { title: 7, kind: {}, content: [{ type: 'diff', path: 5, newText: 'x' }, { type: 'diff', path: 'p', newText: 'n', oldText: 3 }] }, options: 'no' });
    assert.equal(odd.request.title, 'The agent wants to run a tool');
    assert.equal(odd.request.kind, 'other');
    assert.equal(odd.request.diff, undefined, 'a malformed diff was shown');
    const fine = readApproval('s', { toolCall: { content: [{ type: 'diff', path: 'p', newText: 'n' }] }, options: [{ optionId: 'ok', kind: 'allow_once' }, { optionId: 'no', kind: 'reject_once' }] });
    assert.deepEqual(fine.request.diff, { path: 'p', oldText: null, newText: 'n', cut: false });
    assert.equal(fine.allowId, 'ok');
    assert.equal(fine.rejectId, 'no');
  });
});
