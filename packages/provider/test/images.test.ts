import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildAnthropicParams, createOllamaProvider, resolveCaps, toOpenAIMessages, type ModelRequest, type ProviderMessage } from '@hn/provider';

const png = { mediaType: 'image/png' as const, data: 'iVBORw0K' };

const messages: ProviderMessage[] = [
  { role: 'user', parts: [{ type: 'text', text: 'look at it' }] },
  { role: 'assistant', parts: [{ type: 'tool_call', id: 'c1', name: 'read_image', args: { path: 'a.png' } }, { type: 'tool_call', id: 'c2', name: 'read_file', args: { path: 'b' } }] },
  { role: 'user', parts: [{ type: 'tool_result', callId: 'c1', content: 'A PNG image.', images: [png] }] },
  { role: 'user', parts: [{ type: 'tool_result', callId: 'c2', content: 'text' }] },
];

const request: ModelRequest = { model: 'claude-opus-5-5', system: 'sys', tools: [], messages, maxOutputTokens: 1000 };

describe('images in tool results', () => {
  it('anthropic: the picture sits inside its tool_result, after the text', () => {
    const wire = buildAnthropicParams(request, resolveCaps('claude-opus-5-5'), 'error')['messages'] as { content: Record<string, unknown>[] }[];
    const result = wire[2]?.content[0];
    assert.equal(result?.['type'], 'tool_result');
    assert.deepEqual(result?.['content'], [
      { type: 'text', text: 'A PNG image.' },
      { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'iVBORw0K' } },
    ]);
    assert.equal(wire[2]?.content[1]?.['content'], 'text', 'a result without images stays a plain string');
  });

  it('openai-compatible: every tool message first, then one user message with the pictures', () => {
    const wire = toOpenAIMessages('sys', messages, 'r', false);
    assert.deepEqual(
      wire.slice(3).map((message) => message['role']),
      ['tool', 'tool', 'user'],
      'a user message between tool messages would break the call-result pairing',
    );
    assert.deepEqual(wire.at(-1)?.['content'], [
      { type: 'text', text: 'Images from tool call c1:' },
      { type: 'image_url', image_url: { url: 'data:image/png;base64,iVBORw0K' } },
    ]);
  });

  it('openai-compatible: no images, no extra message', () => {
    const plain = messages.map((message) => ({ ...message, parts: message.parts.map((part) => (part.type === 'tool_result' ? { ...part, images: [] } : part)) }));
    assert.deepEqual(toOpenAIMessages('sys', plain, 'r', false).slice(3).map((message) => message['role']), ['tool', 'tool']);
  });

  it('ollama: pictures ride on a user message after the results', async () => {
    let body: Record<string, unknown> = {};
    const provider = createOllamaProvider({
      baseUrl: 'http://local',
      numCtx: 16_384,
      caps: () => resolveCaps('qwen3:14b'),
      fetch: (async (_url: string, init: RequestInit) => {
        body = JSON.parse(init.body as string);
        return new Response(`${JSON.stringify({ done: true })}\n`);
      }) as typeof fetch,
    });
    await provider.complete({ ...request, model: 'qwen3:14b' });
    const wire = body['messages'] as Record<string, unknown>[];
    assert.deepEqual(wire.slice(3).map((message) => message['role']), ['tool', 'tool', 'user']);
    assert.deepEqual(wire.at(-1)?.['images'], ['iVBORw0K']);
  });
});
