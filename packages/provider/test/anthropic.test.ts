import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import Anthropic from '@anthropic-ai/sdk';
import {
  CONSERVATIVE_CAPS,
  ProviderError,
  buildAnthropicParams,
  createAnthropicProvider,
  resolveCaps,
  type AnthropicClient,
  type ModelRequest,
  type ProviderMessage,
} from '@hn/provider';

const opus = resolveCaps('claude-opus-5-5');

const baseRequest: ModelRequest = {
  model: 'claude-opus-5-5',
  system: 'You are hn.',
  tools: [{ name: 'read_file', description: 'Read a file', parameters: { type: 'object' } }],
  messages: [{ role: 'user', parts: [{ type: 'text', text: 'hi' }] }],
  maxOutputTokens: 32_000,
  effort: 'high',
};

function scriptedClient(events: unknown[], final: unknown, failWith?: unknown): AnthropicClient & { calls: unknown[][] } {
  const calls: unknown[][] = [];
  return {
    calls,
    beta: {
      messages: {
        stream: ((...args: unknown[]) => {
          calls.push(args);
          return {
            async *[Symbol.asyncIterator]() {
              yield* events;
              if (failWith !== undefined) throw failWith;
            },
            finalMessage: async () => final,
          };
        }) as never,
      },
    },
  };
}

function provider(client: AnthropicClient, prefixMismatch?: 'error' | 'drop_block') {
  return createAnthropicProvider({
    apiKey: () => 'test-key',
    caps: resolveCaps,
    createClient: () => client,
    ...(prefixMismatch === undefined ? {} : { prefixMismatch }),
  });
}

const message = (overrides: Record<string, unknown>): Record<string, unknown> => ({
  model: 'claude-opus-5-5',
  content: [{ type: 'text', text: 'done' }],
  stop_reason: 'end_turn',
  usage: { input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 90, cache_creation_input_tokens: 0 },
  ...overrides,
});

describe('building a request', () => {
  it('sends adaptive thinking, explicit effort, fallback and history-check settings', () => {
    const params = buildAnthropicParams(baseRequest, opus, 'drop_block');
    assert.deepEqual(params['thinking'], {
      type: 'adaptive',
      display: 'summarized',
      block_binding: { prefix_mismatch_behavior: 'drop_block' },
    });
    assert.deepEqual(params['output_config'], { effort: 'high' });
    assert.equal(params['fallbacks'], 'default');
    assert.deepEqual(params['betas'], ['thinking-binding-controls-2026-08-01', 'server-side-fallback-2026-07-01']);
    assert.equal('tool_choice' in params, false, 'forced tool choice is a 400 on this model');
  });

  it('sends none of that to an unknown model', () => {
    const params = buildAnthropicParams({ ...baseRequest, model: 'mystery' }, CONSERVATIVE_CAPS, 'drop_block');
    for (const field of ['thinking', 'output_config', 'fallbacks', 'betas']) assert.equal(field in params, false, field);
    assert.equal(params['max_tokens'], CONSERVATIVE_CAPS.maxOutput);
  });

  it('streams tool input eagerly', () => {
    const [tool] = buildAnthropicParams(baseRequest, opus, 'error')['tools'] as Record<string, unknown>[];
    assert.equal(tool?.['eager_input_streaming'], true);
  });

  it('merges parallel tool results into one user message', () => {
    const messages: ProviderMessage[] = [
      { role: 'assistant', parts: [{ type: 'tool_call', id: 'a', name: 'x', args: {} }, { type: 'tool_call', id: 'b', name: 'x', args: {} }] },
      { role: 'user', parts: [{ type: 'tool_result', callId: 'a', content: '1' }] },
      { role: 'user', parts: [{ type: 'tool_result', callId: 'b', content: '2', isError: true }] },
    ];
    const wire = buildAnthropicParams({ ...baseRequest, messages }, opus, 'error')['messages'] as { content: unknown[] }[];
    assert.equal(wire.length, 2);
    assert.equal(wire[1]?.content.length, 2);
  });

  it('marks only the last two messages, and never a thinking block', () => {
    const messages: ProviderMessage[] = [
      { role: 'user', parts: [{ type: 'text', text: '1' }] },
      { role: 'assistant', parts: [{ type: 'text', text: '2' }] },
      {
        role: 'user',
        parts: [{ type: 'text', text: '3' }],
      },
      {
        role: 'assistant',
        parts: [
          { type: 'opaque', route: 'anthropic', value: { type: 'thinking', thinking: '', signature: 's' } },
          { type: 'text', text: '4' },
        ],
      },
    ];
    const wire = buildAnthropicParams({ ...baseRequest, messages }, opus, 'error')['messages'] as {
      content: Record<string, unknown>[];
    }[];
    const marked = wire.flatMap((entry) => entry.content).filter((block) => 'cache_control' in block);
    assert.deepEqual(marked.map((block) => block['text']), ['3', '4']);
  });

  it('replays opaque parts only on their own route', () => {
    const messages: ProviderMessage[] = [
      {
        role: 'assistant',
        parts: [
          { type: 'opaque', route: 'anthropic', value: { type: 'thinking', signature: 'keep' } },
          { type: 'opaque', route: 'ollama', value: { reasoning: 'drop' } },
          { type: 'text', text: 'x' },
        ],
      },
    ];
    const wire = buildAnthropicParams({ ...baseRequest, messages }, opus, 'error')['messages'] as { content: unknown[] }[];
    assert.equal(wire[0]?.content.length, 2);
  });

  it('produces identical bytes for an identical request', () => {
    const once = JSON.stringify(buildAnthropicParams(baseRequest, opus, 'error'));
    assert.equal(once, JSON.stringify(buildAnthropicParams(baseRequest, opus, 'error')));
  });
});

describe('reading a reply', () => {
  it('normalizes text, thinking, usage and streamed deltas', async () => {
    const thinking = { type: 'thinking', thinking: 'hm', signature: 'sig' };
    const seen: string[] = [];
    const client = scriptedClient(
      [
        { type: 'content_block_delta', delta: { type: 'thinking_delta', thinking: 'hm' } },
        { type: 'content_block_delta', delta: { type: 'text_delta', text: 'done' } },
      ],
      message({ content: [thinking, { type: 'text', text: 'done' }], input_transformations: [] }),
    );
    const reply = await provider(client).complete({
      ...baseRequest,
      onEvent: (event) => seen.push(event.type),
    });
    assert.deepEqual(seen, ['thinking', 'text']);
    assert.equal(reply.stopReason, 'end');
    assert.deepEqual(reply.parts[0], { type: 'opaque', route: 'anthropic', value: thinking });
    assert.deepEqual(reply.usage, { input: 10, output: 5, cacheRead: 90, cacheWrite: 0 });
    assert.deepEqual(reply.transformations, []);
  });

  it('returns tool calls from a finished tool_use turn', async () => {
    const client = scriptedClient(
      [],
      message({
        stop_reason: 'tool_use',
        content: [{ type: 'tool_use', id: 'c1', name: 'read_file', input: { path: 'a' } }],
      }),
    );
    const reply = await provider(client).complete(baseRequest);
    assert.deepEqual(reply.parts, [{ type: 'tool_call', id: 'c1', name: 'read_file', args: { path: 'a' } }]);
  });

  for (const [stop, expected] of [
    ['max_tokens', 'length'],
    ['refusal', 'refusal'],
  ] as const) {
    it(`never surfaces a tool call from a ${stop} turn`, async () => {
      const client = scriptedClient(
        [],
        message({
          stop_reason: stop,
          content: [
            { type: 'text', text: 'partial' },
            { type: 'tool_use', id: 'c1', name: 'write_file', input: { path: 'half' } },
          ],
        }),
      );
      const reply = await provider(client).complete(baseRequest);
      assert.equal(reply.stopReason, expected);
      assert.deepEqual(reply.parts, [{ type: 'text', text: 'partial' }]);
    });
  }

  it('reports what the API dropped so the log can show it', async () => {
    const dropped = [{ type: 'thinking_dropped', path: 'messages.1.content.0', reason: 'prefix_binding_mismatch' }];
    const reply = await provider(scriptedClient([], message({ input_transformations: dropped }))).complete(baseRequest);
    assert.deepEqual(reply.transformations, dropped);
  });
});

describe('failures', () => {
  const apiError = (status: number, text: string, headers?: Record<string, string>): unknown =>
    Anthropic.APIError.generate(status, { error: { message: text } }, text, new Headers(headers));

  const failure = async (error: unknown): Promise<ProviderError> => {
    const rejected = await provider(scriptedClient([], null, error))
      .complete(baseRequest)
      .catch((caught: unknown) => caught);
    assert.ok(rejected instanceof ProviderError, String(rejected));
    return rejected;
  };

  it('treats a 400 "too long" as compactable, not fatal', async () => {
    const error = await failure(apiError(400, 'prompt is too long: 1200000 tokens > 1000000 maximum'));
    assert.equal(error.reason, 'context_too_long');
    assert.equal(error.flags.shouldCompress, true);
  });

  it('never retries exhausted credit', async () => {
    const error = await failure(apiError(400, 'Your credit balance is too low to access the API.'));
    assert.equal(error.reason, 'quota_exhausted');
    assert.equal(error.flags.retryable, false);
  });

  it('honours Retry-After on a 429', async () => {
    const error = await failure(apiError(429, 'rate limited', { 'retry-after': '7' }));
    assert.equal(error.reason, 'rate_limited');
    assert.equal(error.retryAfterMs, 7000);
  });

  it('never retries a bad key', async () => {
    const error = await failure(apiError(401, 'invalid x-api-key'));
    assert.equal(error.reason, 'auth');
    assert.equal(error.flags.retryable, false);
  });

  it('re-issues a turn whose tool input could not be parsed', async () => {
    assert.equal((await failure(new SyntaxError('bad json'))).reason, 'stream_cut');
  });

  it('reports an abort as an abort', async () => {
    assert.equal((await failure(new Anthropic.APIUserAbortError())).reason, 'aborted');
  });
});
