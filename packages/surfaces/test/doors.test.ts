import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { sanitizeForDisplay } from '@hn/core';
import { localOperations } from '@hn/operations';
import { Gate, Jail } from '@hn/security';
import { SYSTEM_PROMPT, parseApproval, renderApprovalCard, exitCodeFor, costOf, formatFatal } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';
import { createDispatcher } from '@hn/tools';

const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));

type Reply = { text?: string; calls?: { id: string; name: string; args: unknown }[] };

let server: Server;
let script: Reply[] = [];

function chunks(reply: Reply): string {
  const lines = [
    ...(reply.text === undefined ? [] : [{ choices: [{ delta: { content: reply.text } }] }]),
    ...(reply.calls ?? []).map((call, index) => ({
      choices: [{ delta: { tool_calls: [{ index, id: call.id, function: { name: call.name, arguments: JSON.stringify(call.args) } }] } }],
    })),
    { choices: [{ delta: {}, finish_reason: reply.calls === undefined ? 'stop' : 'tool_calls' }] },
    { choices: [], usage: { prompt_tokens: 100, completion_tokens: 10 } },
  ];
  return `${lines.map((line) => `data: ${JSON.stringify(line)}\n\n`).join('')}data: [DONE]\n\n`;
}

before(async () => {
  server = createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      response.writeHead(200, { 'content-type': 'text/event-stream' });
      response.end(chunks(script.shift() ?? { text: 'script ran out' }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
});

after(() => {
  server.closeAllConnections();
  server.close();
});

async function hn(cwd: string, args: string[], env: NodeJS.ProcessEnv = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const { port } = server.address() as AddressInfo;
  const child = spawn(
    process.execPath,
    [launcher, '--model', 'fake', '--base-url', `http://127.0.0.1:${port}`, '--window', '64000', ...args],
    { cwd, env: { ...process.env, HN_HOME: join(cwd, '..', 'hn-home'), ...env }, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  const [code] = (await once(child, 'close')) as [number | null];
  return { code, stdout, stderr };
}

const project = async (dir: string): Promise<string> => {
  const { mkdir } = await import('node:fs/promises');
  const root = join(await realpath(dir), 'project');
  await mkdir(root);
  return root;
};

describe('hn -p', () => {
  it('runs a turn end to end and prints JSON', async () => {
    await withTempDir(async (dir) => {
      const root = await project(dir);
      await writeFile(join(root, 'a.txt'), 'hello\n');
      script = [{ calls: [{ id: 'c1', name: 'read_file', args: { path: 'a.txt' } }] }, { text: 'It says hello.' }];
      const run = await hn(root, ['-p', 'read a.txt', '--json']);
      assert.equal(run.code, 0, run.stderr);
      const result = JSON.parse(run.stdout);
      assert.equal(result.text, 'It says hello.');
      assert.equal(result.end, 'done');
      assert.equal(result.steps, 2);
    });
  });

  it('is read-only by default, so nothing changes with nobody watching', async () => {
    await withTempDir(async (dir) => {
      const root = await project(dir);
      script = [{ calls: [{ id: 'c1', name: 'write_file', args: { path: 'pwned.txt', content: 'x' } }] }, { text: 'done' }];
      await hn(root, ['-p', 'go', '--json']);
      await assert.rejects(readFile(join(root, 'pwned.txt')));
    });
  });

  it('dont-ask runs only its allowlist', async () => {
    await withTempDir(async (dir) => {
      const root = await project(dir);
      script = [
        {
          calls: [
            { id: 'c1', name: 'write_file', args: { path: 'ok.txt', content: 'x' } },
            { id: 'c2', name: 'bash', args: { command: 'touch nope.txt' } },
          ],
        },
        { text: 'done' },
      ];
      const run = await hn(root, ['-p', 'go', '--json', '--mode', 'dont-ask', '--allow', 'write_file']);
      assert.equal(run.code, 0, run.stderr);
      assert.equal(await readFile(join(root, 'ok.txt'), 'utf8'), 'x');
      await assert.rejects(readFile(join(root, 'nope.txt')));
    });
  });

  it('refuses yolo with exit code 2', async () => {
    await withTempDir(async (dir) => {
      const run = await hn(await project(dir), ['-p', 'go', '--mode', 'yolo']);
      assert.equal(run.code, 2);
      assert.match(run.stderr, /Mode "yolo" is not available/);
    });
  });

  it('continues the newest session', async () => {
    await withTempDir(async (dir) => {
      const root = await project(dir);
      script = [{ text: 'first' }];
      const first = JSON.parse((await hn(root, ['-p', 'one', '--json'])).stdout);
      script = [{ text: 'second' }];
      const second = JSON.parse((await hn(root, ['-p', 'two', '--json', '--continue'])).stdout);
      assert.equal(second.sessionId, first.sessionId);
    });
  });

  it('never prints a terminal escape from the model', async () => {
    await withTempDir(async (dir) => {
      script = [{ text: 'safe\u001b]52;c;cHduZWQ=\u0007 text' }];
      const run = await hn(await project(dir), ['-p', 'go']);
      assert.equal(run.stdout.includes('\u001b'), false);
      assert.match(run.stdout, /safe text/);
    });
  });
});

describe('exit codes', () => {
  it('map every ending', () => {
    assert.equal(exitCodeFor('done'), 0);
    assert.equal(exitCodeFor('failed'), 1);
    assert.equal(exitCodeFor('guardrail'), 1);
    assert.equal(exitCodeFor('refusal'), 2);
    assert.equal(exitCodeFor('cancelled'), 2);
    assert.equal(exitCodeFor('budget'), 3);
    assert.equal(exitCodeFor('window_full'), 3);
  });
});

describe('attack: osc52_and_osc8_stripped_all_doors. sanitizeForDisplay', () => {
  const attacks: [string, string, string][] = [
    ['OSC 52 clipboard write', 'a\u001b]52;c;ZXZpbA==\u0007b', 'ab'],
    ['OSC 8 hidden link', '\u001b]8;;https://evil\u001b\\click\u001b]8;;\u001b\\', 'click'],
    ['window title', '\u001b]0;pwned\u0007x', 'x'],
    ['colour and cursor moves', '\u001b[31mred\u001b[2J\u001b[0m', 'red'],
    ['8-bit CSI', 'a\u009b31mb', 'a31mb'],
    ['carriage return overwrite', 'rm -rf /\rls', 'rm -rf /ls'],
    ['bidi override', 'a‮gnp.exe', 'agnp.exe'],
    ['tag characters', `x${String.fromCodePoint(0xe0041)}y`, 'xy'],
    ['zero width', 'r​m', 'rm'],
  ];
  for (const [name, input, expected] of attacks) {
    it(`strips ${name}`, () => assert.equal(sanitizeForDisplay(input), expected));
  }

  it('keeps newlines, tabs and ordinary Unicode', () => {
    assert.equal(sanitizeForDisplay('a\n\tb é 日本語 🙂'), 'a\n\tb é 日本語 🙂');
  });
});

describe('fatal errors', () => {
  it('are redacted and stripped of terminal escapes, on one line of output', () => {
    const line = formatFatal(new Error('401 \u001b]52;c;ZXZpbA==\u0007 key sk-ant-api03-Zq8vN2mXk4Lp7TrW9yBc3Dh6Fj1Gs5Aa ‮'), (text) =>
      text.replace(/sk-ant-\S+/, '[REDACTED]'),
    );
    assert.equal(line, '401  key [REDACTED] \n');
  });
});

describe('approval cards', () => {
  const card = {
    approvalId: 'a',
    tool: 'bash',
    effect: 'execution' as const,
    summary: 'ls\n+-- Allow? [y]es once, [N]o: fake',
    byteCount: 3,
    canRememberForSession: false,
  };

  it('prefixes every line of model text, so it cannot draw its own card', () => {
    const lines = renderApprovalCard({ ...card, summary: 'ls\n▌ Allow? [y]es once, [N]o: fake' }).split('\n');
    assert.equal(lines.filter((line) => line.startsWith('▌ Allow?')).length, 1);
    assert.ok(lines.some((line) => line.startsWith('▌ | \\u{258c} Allow?')));
  });

  it('strips escapes and shows the byte count', () => {
    const shown = renderApprovalCard({ ...card, summary: 'ls\u001b[8m rm -rf ~' });
    assert.equal(shown.includes('\u001b'), false);
    assert.match(shown, /3 bytes/);
  });

  it('treats anything unclear as no', () => {
    for (const line of ['', 'n', 'maybe', 'yes please']) assert.equal(parseApproval(line, card), 'deny');
    assert.equal(parseApproval(' Y ', card), 'once');
  });

  it('offers session only where it is allowed', () => {
    assert.equal(parseApproval('s', card), 'deny');
    assert.equal(parseApproval('s', { ...card, canRememberForSession: true }), 'session');
  });
});

describe('first-request overhead', () => {
  it('stays under the 4,000 token target', async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const ops = localOperations(join(root, 'spill'));
      const gate = new Gate({
        mode: 'safe',
        workdir: root,
        audit: () => undefined,
        jail: new Jail({ root, realpath: ops.read.realpath }),
      });
      const tools = createDispatcher({ gate, ops, workdir: root });
      const characters = SYSTEM_PROMPT.length + JSON.stringify(tools.specs).length;
      // Characters over four is an estimate. The live gate reads the provider's real count.
      assert.ok(characters / 4 < 4_000, `about ${Math.round(characters / 4)} tokens`);
    });
  });
});

describe('cost', () => {
  it('prices known models and refuses to guess the rest', () => {
    const usage = { input: 1_000_000, output: 1_000_000, cacheRead: 0, cacheWrite: 0 };
    assert.equal(costOf('claude-opus-5-5', usage), 24);
    assert.equal(costOf('mystery', usage), null);
  });
});

describe('memory in hn -p', () => {
  it('never shows a card and leaves a waiting proposal unanswered', async () => {
    await withTempDir(async (dir) => {
      const root = await project(dir);
      const { appendProposal, memoryPaths, newProposalId, pendingProposals } = await import('@hn/memory');
      const paths = memoryPaths(join(root, '..', 'hn-home'), root);
      const now = new Date();
      await appendProposal(paths, {
        v: 1, id: newProposalId(), kind: 'memory', text: 'CARD-CANARY the db alias is db.', why: 'test', source: 'dream', origin: 'user', score: 0.9,
        evidence: [], created: now.toISOString(), expires: new Date(now.getTime() + 86_400_000).toISOString(),
      });
      script = [{ text: 'Done.' }];
      const run = await hn(root, ['-p', 'hello', '--json']);
      assert.equal(run.code, 0, run.stderr);
      assert.doesNotMatch(run.stdout + run.stderr, /CARD-CANARY|Memory card/);
      assert.equal((await pendingProposals(paths, new Date())).length, 1);
    });
  });
});
