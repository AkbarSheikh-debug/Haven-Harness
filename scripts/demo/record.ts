// Records the README demo from a REAL run. A developer tool, not part of hn.
//
//   node --disable-proto=throw scripts/demo/record.ts [--out scripts/demo/transcript.json]
//
// It starts the real `hn` in a verified Windows box against a scripted model (a local server that answers with fixed
// tool calls, so the demo repeats), types the person's side, and writes what hn printed. The model's words are
// scripted; everything else is real: the verified-box banner, the approval cards, the edit, the test run in the box,
// and the refusal. To show results the person cannot normally see, the scripted model quotes the tool's own output
// back. Temporary paths are replaced so no user name or machine path ends up in the recording.
// Render the transcript with: python scripts/demo/render_gif.py

import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const launcher = join(ROOT, 'packages', 'surfaces', 'bin', 'hn.mjs');
const helper = join(ROOT, 'native', 'hn-sandbox', 'target', 'release', 'hn-sandbox.exe');

interface Reply {
  readonly text?: string;
  readonly call?: { name: string; args: unknown };
}

const sse = (reply: Reply, index: number): string => {
  const lines = [
    ...(reply.text === undefined ? [] : [{ choices: [{ delta: { content: reply.text } }] }]),
    ...(reply.call === undefined ? [] : [{ choices: [{ delta: { tool_calls: [{ index: 0, id: `call-${index}`, function: { name: reply.call.name, arguments: JSON.stringify(reply.call.args) } }] } }] }]),
    { choices: [{ delta: {}, finish_reason: reply.call === undefined ? 'stop' : 'tool_calls' }] },
    { choices: [], usage: { prompt_tokens: 100, completion_tokens: 10 } },
  ];
  return `${lines.map((line) => `data: ${JSON.stringify(line)}\n\n`).join('')}data: [DONE]\n\n`;
};

/** A tool result as a person would read it: PowerShell's CLIXML error wrapper is unpacked into its message. */
const plain = (text: string): string => {
  const errors = [...text.matchAll(/<S S="Error">(.*?)<\/S>/g)].map((match) => (match[1] as string).replace(/_x000D__x000A_/g, ' ').trim());
  return errors.length > 0 ? (errors[0] as string) : text.replace(/^\[stdout\]\s*/, '');
};

const clip = (raw: string, max = 150): string => {
  const one = plain(raw).replace(/\s+/g, ' ').trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
};

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { out: { type: 'string' } } });
  if (process.platform !== 'win32') throw new Error('The demo is recorded in the Windows box, so it runs on Windows.');
  if (!existsSync(helper)) throw new Error('Build the helper first: pnpm build:sandbox');
  const top = await realpath(await mkdtemp(join(tmpdir(), 'hn-demo-')));
  const project = join(top, 'calc');
  const secret = join(top, 'outside', 'secret.txt');
  await mkdir(project);
  await mkdir(join(top, 'outside'));
  await writeFile(join(project, 'calc.ps1'), 'function Add-Numbers($a, $b) {\n    return $a - $b\n}\n');
  await writeFile(join(project, 'test.ps1'), '. "$PSScriptRoot/calc.ps1"\n$got = Add-Numbers 2 3\nif ($got -ne 5) { Write-Error "FAIL: Add-Numbers 2 3 gave $got"; exit 1 }\nWrite-Output "ok: Add-Numbers 2 3 = $got"\n');
  await writeFile(secret, 'HOST-ONLY-SECRET\n');

  // The scripted model: what it does next depends on how many answers it has given, and it quotes tool results back.
  let given = 0;
  let lastTool = '';
  const server = createServer((request, response) => {
    const parts: Buffer[] = [];
    request.on('data', (part: Buffer) => parts.push(part));
    request.on('end', () => {
      const body = JSON.parse(Buffer.concat(parts).toString('utf8')) as { messages: { role: string; content: unknown }[] };
      const tool = [...body.messages].reverse().find((message) => message.role === 'tool');
      lastTool = typeof tool?.content === 'string' ? tool.content : JSON.stringify(tool?.content ?? '');
      if (process.env['DEMO_DEBUG'] !== undefined) process.stderr.write(`TOOL RESULT: ${JSON.stringify(lastTool)}
`);
      const replies: Reply[] = [
        { text: 'I will read the code first.', call: { name: 'read_file', args: { path: 'calc.ps1' } } },
        { call: { name: 'edit_file', args: { path: 'calc.ps1', old_string: 'return $a - $b', new_string: 'return $a + $b' } } },
        { call: { name: 'bash', args: { command: 'powershell -NoProfile -ExecutionPolicy Bypass -File test.ps1' } } },
        { text: `The bug was a minus where a plus belongs, in calc.ps1. In the box the test now says: ${clip(lastTool, 90)}` },
        { call: { name: 'read_file', args: { path: secret } } },
        { text: `I could not read it. hn answered: ${clip(lastTool, 190)}` },
        { call: { name: 'bash', args: { command: `Get-Content '${secret}'` } } },
        { text: `From inside the box the host's file is out of reach: ${clip(lastTool, 190)}` },
      ];
      const reply = replies[Math.min(given, replies.length - 1)] as Reply;
      given += 1;
      response.writeHead(200, { 'content-type': 'text/event-stream' });
      response.end(sse(reply, given));
    });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const events: { kind: 'out' | 'in'; text: string }[] = [];
  const child = spawn(process.execPath, ['--disable-proto=throw', '--no-warnings', launcher, '--model', 'demo', '--base-url', url, '--sandbox', 'native'], { cwd: project, env: { ...process.env, HN_HOME: join(top, 'home'), HN_SANDBOX_BIN: helper } });
  let pending = '';
  const take = (chunk: Buffer): void => {
    const text = chunk.toString('utf8');
    pending += text;
    events.push({ kind: 'out', text });
  };
  child.stdout.on('data', take);
  child.stderr.on('data', take);
  const waitFor = async (pattern: RegExp, seconds = 180): Promise<void> => {
    const until = Date.now() + seconds * 1000;
    while (!pattern.test(pending)) {
      if (Date.now() > until) throw new Error(`Timed out waiting for ${pattern}. Output so far:\n${pending}`);
      await new Promise((tick) => setTimeout(tick, 100));
    }
    pending = '';
  };
  const type = (line: string): void => {
    events.push({ kind: 'in', text: line });
    child.stdin.write(`${line}\n`);
  };
  try {
    await waitFor(/hn> /);
    type('make the failing test in test.ps1 pass');
    await waitFor(/Allow\?[^\n]*$/);
    type('y');
    await waitFor(/Allow\?[^\n]*$/);
    type('y');
    await waitFor(/\[done\][^]*hn> $/);
    type('now show me ../outside/secret.txt');
    await waitFor(/\[done\][^]*hn> $/);
    type('try it from the shell');
    await waitFor(/Allow\?[^\n]*$/);
    type('y');
    await waitFor(/\[done\][^]*hn> $/);
    type('/exit');
    await waitFor(/Resume with/);
    await new Promise((tick) => setTimeout(tick, 500));
  } finally {
    child.kill();
    await Promise.race([once(child, 'exit'), new Promise((tick) => setTimeout(tick, 3000))]);
    server.closeAllConnections();
    server.close();
  }
  // No user name or machine path in the recording.
  const forms = [top, top.replace(/\\/g, '/'), top.replace(/\\/g, '\\\\')];
  const scrub = (text: string): string => forms.reduce((out, form) => out.split(form).join('~/demo'), text).replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '3f2a9c1e-7b64-4d0a-9e51-0c8d2b6a47f3');
  const clean = events.map((event) => ({ kind: event.kind, text: scrub(event.text) }));
  const out = resolve(values.out ?? join(ROOT, 'scripts', 'demo', 'transcript.json'));
  await writeFile(out, `${JSON.stringify({ recorded: 'a real hn run in a verified Windows box, with a scripted model', events: clean }, null, 1)}\n`);
  await rm(top, { recursive: true, force: true });
  process.stdout.write(`Recorded ${clean.length} events to ${out}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
