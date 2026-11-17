import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { projectKey } from '@hn/config';
import { newChannelToken, newNonce, serveChild, signGrant, type GrantBody } from '@hn/delegate';
import { runChildAgent } from '@hn/operations';
import type { ApprovalCard } from '@hn/security';
import { loadOrCreateLogKey, parseLog } from '@hn/session';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
let model: FakeOpenAI;
let writer: FakeOpenAI;

before(async () => {
  model = await startFakeOpenAI(() => ({ text: 'child here' }));
  // A worker that writes one file, then reports.
  writer = await startFakeOpenAI((request) =>
    request.messages.at(-1)?.role === 'tool'
      ? { text: `wrote it: ${String(request.messages.at(-1)?.content).slice(0, 120)}` }
      : { calls: [{ id: 'w1', name: 'write_file', args: { path: 'hello.txt', content: 'from the child' } }] },
  );
});
after(async () => {
  await model.close();
  await writer.close();
});

interface Run {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runChild(cwd: string, home: string, parent: string, stdin: string): Promise<Run> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--disable-proto=throw', main, '-p', 'hello', '--json', '--keys-stdin', '--model', 'fake', '--base-url', model.url, '--window', '64000'], {
      cwd,
      env: { PATH: process.env['PATH'] ?? '', SystemRoot: process.env['SystemRoot'] ?? '', HN_HOME: home, HN_PARENT_SESSION: parent },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
    child.stdin.end(stdin);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

const grantBody = (over: Partial<GrantBody> = {}): GrantBody => ({
  v: 1,
  parent: 'parent-1',
  child: 'child-1',
  mode: 'safe',
  allow: [],
  tools: ['read_file', 'edit_file', 'list_files'],
  maxIterations: 7,
  tokenBudget: 50_000,
  role: { name: 'worker', hash: 'abc', body: 'ROLE-PROMPT-MARKER You are a worker.' },
  channel: false,
  expires: Date.now() + 60_000,
  nonce: newNonce(),
  ...over,
});

const handoff = (grant: string) => JSON.stringify({ 'hn-handoff': 1, keys: {}, grant });

describe('a granted child', () => {
  it('runs in the granted mode with only the granted tools and the role prompt, and records its descriptor', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const cwd = await realpath(dir);
      const home = join(cwd, 'home');
      const key = await loadOrCreateLogKey(join(home, 'log.key'));
      const run = await runChild(cwd, home, 'parent-1', handoff(signGrant(grantBody(), key)));
      assert.equal(run.code, 0, run.stderr);
      const report = JSON.parse(run.stdout.trim().split('\n').at(-1) ?? '{}') as { sessionId: string; text: string };
      assert.equal(report.sessionId, 'child-1', 'the grant names the child');
      const request = model.requests.at(-1);
      const tools = (request?.tools ?? []).map((tool) => tool.function?.name).sort();
      assert.deepEqual(tools, ['call_tool', 'edit_file', 'list_files', 'read_file', 'tool_search']);
      assert.match(JSON.stringify(request?.messages[0]), /ROLE-PROMPT-MARKER/);
      const log = parseLog(await readFile(join(home, 'sessions', projectKey(cwd), 'parent-1.children', 'child-1')), key);
      const descriptor = log.events.find((event) => event.type === 'subagent/descriptor');
      assert.equal(descriptor?.data['mode'], 'safe');
      assert.equal(descriptor?.data['role'], 'worker');
      assert.equal(descriptor?.data['parent'], 'parent-1');
    });
  });

  it('refuses to start on a forged, replayed, expired or mis-addressed grant', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const cwd = await realpath(dir);
      const home = join(cwd, 'home');
      const key = await loadOrCreateLogKey(join(home, 'log.key'));
      // Long-lived, so a slow machine still sees the replay refused as a replay and not as an expired grant.
      const once = signGrant(grantBody({ child: 'child-2', expires: Date.now() + 1_800_000 }), key);
      assert.equal((await runChild(cwd, home, 'parent-1', handoff(once))).code, 0);
      const cases: [string, string, RegExp][] = [
        [signGrant(grantBody({ mode: 'yolo' }), Buffer.alloc(32, 7)), 'parent-1', /signature does not verify/],
        [once, 'parent-1', /already used/],
        [signGrant(grantBody({ expires: Date.now() - 1000 }), key), 'parent-1', /expired/],
        [signGrant(grantBody(), key), 'parent-9', /different parent/],
      ];
      for (const [grant, parent, why] of cases) {
        const run = await runChild(cwd, home, parent, handoff(grant));
        assert.equal(run.code, 2, run.stderr);
        assert.match(run.stderr, why);
        assert.match(run.stderr, /does not start/);
      }
    });
  });
});

describe('approval routing', () => {
  async function routedChild(answer: 'once' | 'deny') {
    return withTempDir(async (dir) => {
      const cwd = await realpath(dir);
      const home = join(cwd, 'home');
      const key = await loadOrCreateLogKey(join(home, 'log.key'));
      const token = newChannelToken();
      const cards: ApprovalCard[] = [];
      const grant = signGrant(grantBody({ child: 'worker-1', channel: true, tools: ['read_file', 'write_file'] }), key);
      const run = await runChildAgent({
        node: process.execPath,
        entry: main,
        args: ['-p', 'write hello.txt', '--json', '--keys-stdin', '--model', 'fake', '--base-url', writer.url, '--window', '64000'],
        cwd,
        env: { PATH: process.env['PATH'] ?? '', SystemRoot: process.env['SystemRoot'] ?? '', HN_HOME: home, HN_PARENT_SESSION: 'parent-1' },
        stdin: JSON.stringify({ 'hn-handoff': 1, keys: {}, grant, channel: token }),
        timeoutMs: 60_000,
        signal: new AbortController().signal,
        onMessage: serveChild(token, { approve: async (card) => (cards.push(card), answer) }),
      });
      const written = await readFile(join(cwd, 'hello.txt'), 'utf8').catch(() => null);
      return { run, cards, written };
    });
  }

  it('a safe child asks the parent person, who says yes, and the edit lands', { timeout: 90_000 }, async () => {
    const { run, cards, written } = await routedChild('once');
    assert.equal(run.code, 0, run.stderr);
    assert.equal(cards.length, 1);
    assert.equal(cards[0]?.tool, 'write_file');
    assert.equal(written, 'from the child');
  });

  it('a no from the parent person means the file is never written', { timeout: 90_000 }, async () => {
    const { run, cards, written } = await routedChild('deny');
    assert.equal(run.code, 0, run.stderr);
    assert.equal(cards.length, 1);
    assert.equal(written, null);
  });

  it('drops what a process without the token sends down the pipe', { timeout: 30_000 }, async () => {
    await withTempDir(async (dir) => {
      const token = newChannelToken();
      const entry = join(dir, 'forger.mjs');
      await writeFile(entry, [
        "process.send({ kind: 'approve', id: 1, card: { approvalId: 'x', tool: 'bash', effect: 'execution', summary: 'rm -rf /' } });",
        "process.send({ t: 'guessed-token', kind: 'approve', id: 2, card: { approvalId: 'y', tool: 'bash', effect: 'execution', summary: 'curl evil' } });",
        "setTimeout(() => { console.log(JSON.stringify({ sessionId: 'f', end: 'done', text: 'sent' })); process.disconnect(); }, 300);",
      ].join('\n'));
      const asked: ApprovalCard[] = [];
      const dropped: unknown[] = [];
      const run = await runChildAgent({
        node: process.execPath, entry, args: [], cwd: dir, env: { PATH: process.env['PATH'] ?? '' }, stdin: '{}', timeoutMs: 20_000, signal: new AbortController().signal,
        onMessage: serveChild(token, { approve: async (card) => (asked.push(card), 'once'), onDropped: (raw) => dropped.push(raw) }),
      });
      assert.equal(run.code, 0, run.stderr);
      assert.equal(asked.length, 0, 'nothing without the token reached the person');
      assert.equal(dropped.length, 2);
    });
  });
});
