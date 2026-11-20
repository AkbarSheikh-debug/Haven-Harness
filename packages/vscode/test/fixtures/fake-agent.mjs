// A scripted agent for testing the editor's ACP client. It is deliberately not honest: mode says how it misbehaves.
// What the client answered is written, one JSON object per line, to FAKE_AGENT_LOG.
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const mode = process.argv[2] ?? 'hostile';
const record = (value) => process.env.FAKE_AGENT_LOG && appendFileSync(process.env.FAKE_AGENT_LOG, `${JSON.stringify(value)}\n`);
const send = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
const update = (sessionId, body) => send({ jsonrpc: '2.0', method: 'session/update', params: { sessionId, update: body } });
const chunk = (sessionId, text) => update(sessionId, { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text } });

let nextId = 1000;
const waiting = new Map();
const ask = (method, params) =>
  new Promise((resolve) => {
    const id = (nextId += 1);
    waiting.set(id, resolve);
    send({ jsonrpc: '2.0', id, method, params });
  });

const permission = (sessionId, options, content) => ask('session/request_permission', { sessionId, toolCall: { toolCallId: 't1', title: 'write x\u001b[31m red', kind: 'edit', status: 'pending', content }, options });

async function hostile(id) {
  process.stdout.write('{this is not json\n');
  process.stdout.write('[1,2,3]\n');
  chunk('ghost', 'text for a session that was never opened');
  chunk('s1', 'hello \u001b]52;c;Y2xpcA==\u0007world‮');
  process.stdout.write(`${'x'.repeat(5 * 1024 * 1024)}\n`);
  chunk('s1', 'after the big line');
  chunk('s1', 'a'.repeat(200_000));
  update('s1', { sessionUpdate: 'tool_call', toolCallId: 'c1', title: 'run\u001b[1m it', kind: 'launch-missiles', status: 'weird' });
  update('s1', { sessionUpdate: 'tool_call_update', toolCallId: 'c1', status: 'completed' });
  update('s1', { sessionUpdate: 'tool_call_update', toolCallId: 'c1', status: 'nonsense' });
  record({ file: await ask('fs/read_text_file', { sessionId: 's1', path: '/etc/passwd' }) });
  record({ terminal: await ask('terminal/create', { sessionId: 's1', command: 'rm' }) });
  const diff = { type: 'diff', path: 'a‮txt.exe', oldText: 'old​', newText: `new${'z'.repeat(300_000)}` };
  record({
    first: await permission('s1', [{ optionId: 'always', name: 'Always', kind: 'allow_always' }, { optionId: 'once', name: 'Once', kind: 'allow_once' }, { optionId: 'no', name: 'No', kind: 'reject_once' }], [diff]),
  });
  record({ onlyAlways: await permission('s1', [{ optionId: 'always', name: 'Always', kind: 'allow_always' }], []) });
  record({ ghost: await permission('ghost', [{ optionId: 'once', name: 'Once', kind: 'allow_once' }], []) });
  send({ jsonrpc: '2.0', id, result: { stopReason: 'launch-missiles' } });
}

createInterface({ input: process.stdin }).on('line', async (line) => {
  const message = JSON.parse(line);
  if (message.method === undefined) {
    waiting.get(message.id)?.(message);
    waiting.delete(message.id);
    return;
  }
  if (message.method === 'initialize') {
    send({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: mode === 'oldproto' ? 99 : 1, agentCapabilities: {} } });
  } else if (message.method === 'session/new') {
    record({ newParams: message.params });
    send({ jsonrpc: '2.0', id: message.id, result: { sessionId: 's1', _meta: { hn: { tier: 'high', mode: '\u001b[31msafe', sandbox: 'yes' } } } });
  } else if (message.method === 'session/prompt') {
    if (mode === 'die') {
      process.stderr.write('the agent crashed\u001b[31m badly');
      process.exit(3);
    }
    if (mode === 'flood') {
      for (let n = 0; n < 200; n += 1) chunk('s1', 'f'.repeat(64 * 1024));
      send({ jsonrpc: '2.0', id: message.id, result: { stopReason: 'end_turn' } });
    } else if (mode === 'hostile') await hostile(message.id);
  }
});
