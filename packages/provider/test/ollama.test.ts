import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ProviderError, createOllamaProvider, resolveCaps, type ModelRequest } from '@hn/provider';

const request: ModelRequest = {
  model: 'qwen3:14b',
  system: 'sys',
  tools: [{ name: 'read_file', description: 'read', parameters: { type: 'object' } }],
  messages: [
    { role: 'user', parts: [{ type: 'text', text: 'hi' }] },
    { role: 'assistant', parts: [{ type: 'tool_call', id: 'c1', name: 'read_file', args: { path: 'a' } }] },
    { role: 'user', parts: [{ type: 'tool_result', callId: 'c1', content: 'data' }] },
  ],
  maxOutputTokens: 1000,
};

function provider(lines: unknown[], capture: { body?: Record<string, unknown>; url?: string } = {}, status = 200) {
  return createOllamaProvider({
    baseUrl: 'http://local',
    numCtx: 16_384,
    caps: () => resolveCaps('qwen3:14b', { maxOutput: 8_192 }),
    fetch: (async (url: string, init: RequestInit) => {
      capture.url = url;
      capture.body = JSON.parse(init.body as string);
      return new Response(lines.map((line) => `${JSON.stringify(line)}\n`).join(''), { status });
    }) as typeof fetch,
  });
}

describe('ollama', () => {
  it('uses the native endpoint, the only one that honours num_ctx', async () => {
    const capture: { body?: Record<string, unknown>; url?: string } = {};
    await provider([{ message: { content: 'ok' } }, { done: true, done_reason: 'stop' }], capture).complete(request);
    assert.equal(capture.url, 'http://local/api/chat');
    assert.deepEqual(capture.body?.['options'], { num_ctx: 16_384, num_predict: 1000 });
  });

  it('names the tool on each result, which this API needs in place of ids', async () => {
    const capture: { body?: Record<string, unknown> } = {};
    await provider([{ done: true }], capture).complete(request);
    const messages = capture.body?.['messages'] as Record<string, unknown>[];
    assert.deepEqual(messages.at(-1), { role: 'tool', tool_name: 'read_file', content: 'data' });
  });

  it('moves reasoning that leaked into the content, closed by </think>, out of the answer (seen live with qwen3)', async () => {
    const reply = await provider([
      { message: { content: 'Okay, the user wants the version. Let me check.\n</think>\n\n' } },
      { message: { content: 'It is 4.7.31.' } },
      { done: true, done_reason: 'stop' },
    ]).complete(request);
    assert.deepEqual(reply.parts.filter((part) => part.type === 'text'), [{ type: 'text', text: 'It is 4.7.31.' }]);
    const opaque = reply.parts.find((part) => part.type === 'opaque');
    assert.match(String(opaque?.type === 'opaque' ? opaque.value : ''), /Let me check\./);
    const only = await provider([{ message: { content: '<think>hmm</think>' } }, { done: true }]).complete(request);
    assert.equal(only.parts.some((part) => part.type === 'text'), false, 'nothing but reasoning means an empty reply, which the loop nudges');
  });

  it('gives each call a unique id, and reports usage', async () => {
    const call = { function: { name: 'read_file', arguments: { path: 'a' } } };
    const reply = await provider([
      { message: { tool_calls: [call, call] } },
      { done: true, done_reason: 'stop', prompt_eval_count: 7, eval_count: 3 },
    ]).complete(request);
    assert.equal(reply.stopReason, 'tool_use');
    const ids = reply.parts.map((part) => (part.type === 'tool_call' ? part.id : ''));
    assert.equal(new Set(ids).size, 2);
    assert.deepEqual(reply.usage, { input: 7, output: 3, cacheRead: 0, cacheWrite: 0 });
  });

  it('never surfaces a tool call from a reply cut off by the limit', async () => {
    const reply = await provider([
      { message: { tool_calls: [{ function: { name: 'write_file', arguments: {} } }] } },
      { done: true, done_reason: 'length' },
    ]).complete(request);
    assert.equal(reply.stopReason, 'length');
    assert.deepEqual(reply.parts, []);
  });

  it('reports a stream that never finishes as retryable', async () => {
    const failure = await provider([{ message: { content: 'par' } }]).complete(request).catch((error: unknown) => error);
    assert.ok(failure instanceof ProviderError);
    assert.equal(failure.reason, 'stream_cut');
  });

  it('classifies a server failure', async () => {
    const failure = await provider([{ error: 'out of memory' }], {}, 500).complete(request).catch((error: unknown) => error);
    assert.ok(failure instanceof ProviderError);
    assert.equal(failure.reason, 'server_error');
  });
});
