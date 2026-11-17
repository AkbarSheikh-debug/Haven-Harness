// Every adapter must behave the same to the loop. Each scenario runs against each adapter.
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import Anthropic from '@anthropic-ai/sdk';
import {
  ProviderError,
  createAnthropicProvider,
  createOpenAICompatibleProvider,
  resolveCaps,
  type AnthropicClient,
  type FailoverReason,
  type ModelProvider,
  type ModelReply,
  type ModelRequest,
} from '@hn/provider';

type Scenario =
  | { kind: 'text'; text: string }
  | { kind: 'tools'; calls: { id: string; name: string; args: unknown }[] }
  | { kind: 'cut' }
  | { kind: 'http'; status: number; body: string; retryAfter?: string };

const request: ModelRequest = {
  model: 'test-model',
  system: 'sys',
  tools: [{ name: 'read_file', description: 'read', parameters: { type: 'object' } }],
  messages: [{ role: 'user', parts: [{ type: 'text', text: 'hi' }] }],
  maxOutputTokens: 1000,
};

function anthropicFor(scenario: Scenario): ModelProvider {
  const client = {
    beta: {
      messages: {
        stream: () => ({
          async *[Symbol.asyncIterator]() {
            if (scenario.kind === 'cut') throw new SyntaxError('cut mid tool input');
            if (scenario.kind === 'http') {
              const headers = new Headers(scenario.retryAfter === undefined ? {} : { 'retry-after': scenario.retryAfter });
              const body = { type: 'error', error: { type: 'api_error', message: scenario.body } };
              throw Anthropic.APIError.generate(scenario.status, body, undefined, headers);
            }
          },
          finalMessage: async () =>
            scenario.kind === 'text'
              ? { model: 'test-model', stop_reason: 'end_turn', content: [{ type: 'text', text: scenario.text }] }
              : {
                  model: 'test-model',
                  stop_reason: 'tool_use',
                  content:
                    scenario.kind === 'tools'
                      ? scenario.calls.map((call) => ({ type: 'tool_use', id: call.id, name: call.name, input: call.args }))
                      : [],
                },
        }),
      },
    },
  } as unknown as AnthropicClient;
  return createAnthropicProvider({ apiKey: () => 'k', caps: resolveCaps, createClient: () => client });
}

let server: Server;
let current: Scenario;

function sse(chunks: unknown[], done = true): string {
  return [...chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`), ...(done ? ['data: [DONE]\n\n'] : [])].join('');
}

const openAIBody = (scenario: Scenario): string => {
  if (scenario.kind === 'text') {
    return sse([
      { choices: [{ delta: { content: scenario.text } }] },
      { choices: [{ delta: {}, finish_reason: 'stop' }] },
    ]);
  }
  if (scenario.kind === 'tools') {
    return sse([
      ...scenario.calls.flatMap((call, index) => {
        const args = JSON.stringify(call.args);
        return [
          { choices: [{ delta: { tool_calls: [{ index, id: call.id, function: { name: call.name, arguments: args.slice(0, 1) } }] } }] },
          { choices: [{ delta: { tool_calls: [{ index, function: { arguments: args.slice(1) } }] } }] },
        ];
      }),
      { choices: [{ delta: {}, finish_reason: 'tool_calls' }] },
    ]);
  }
  return sse([{ choices: [{ delta: { tool_calls: [{ index: 0, id: 'c', function: { name: 'x', arguments: '{"a' } }] } }] }], false);
};

function openAI(): ModelProvider {
  const { port } = server.address() as AddressInfo;
  return createOpenAICompatibleProvider({
    route: 'local',
    baseUrl: `http://127.0.0.1:${port}`,
    caps: () => resolveCaps('test-model', { nativeTools: true, maxOutput: 1000 }),
  });
}

before(async () => {
  server = createServer((incoming, response) => {
    incoming.resume();
    incoming.on('end', () => {
      if (current.kind === 'http') {
        response.writeHead(current.status, current.retryAfter === undefined ? {} : { 'retry-after': current.retryAfter });
        response.end(current.body);
        return;
      }
      response.writeHead(200, { 'content-type': 'text/event-stream' });
      response.end(openAIBody(current));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
});

after(() => {
  server.close();
});

const adapters: [string, (scenario: Scenario) => ModelProvider][] = [
  ['anthropic', anthropicFor],
  [
    'openai-compatible',
    (scenario) => {
      current = scenario;
      return openAI();
    },
  ],
];

const parts = (reply: ModelReply): unknown[] => reply.parts.filter((part) => part.type !== 'opaque');

for (const [name, adapter] of adapters) {
  describe(`conformance: ${name}`, () => {
    it('returns plain text', async () => {
      const reply = await adapter({ kind: 'text', text: 'hello' }).complete(request);
      assert.equal(reply.stopReason, 'end');
      assert.deepEqual(parts(reply), [{ type: 'text', text: 'hello' }]);
    });

    it('returns one tool call', async () => {
      const call = { id: 'c1', name: 'read_file', args: { path: 'a.ts' } };
      const reply = await adapter({ kind: 'tools', calls: [call] }).complete(request);
      assert.equal(reply.stopReason, 'tool_use');
      assert.deepEqual(parts(reply), [{ type: 'tool_call', ...call }]);
    });

    it('returns parallel tool calls in order', async () => {
      const calls = [
        { id: 'c1', name: 'read_file', args: { path: 'a' } },
        { id: 'c2', name: 'read_file', args: { path: 'b' } },
      ];
      const reply = await adapter({ kind: 'tools', calls }).complete(request);
      assert.deepEqual(parts(reply), calls.map((call) => ({ type: 'tool_call', ...call })));
    });

    it('reports a stream cut mid-tool as retryable', async () => {
      const failure = await adapter({ kind: 'cut' }).complete(request).catch((error: unknown) => error);
      assert.ok(failure instanceof ProviderError);
      assert.equal(failure.reason, 'stream_cut');
      assert.equal(failure.flags.retryable, true);
    });

    const failures: [string, Scenario & { kind: 'http' }, FailoverReason, boolean][] = [
      ['context too long', { kind: 'http', status: 400, body: 'maximum context length exceeded' }, 'context_too_long', false],
      ['a 429', { kind: 'http', status: 429, body: 'slow down', retryAfter: '3' }, 'rate_limited', true],
      ['a 401', { kind: 'http', status: 401, body: 'bad key' }, 'auth', false],
      ['quota exhausted', { kind: 'http', status: 429, body: 'You exceeded your current quota' }, 'quota_exhausted', false],
    ];
    for (const [label, scenario, reason, retryable] of failures) {
      it(`classifies ${label}`, async () => {
        const failure = await adapter(scenario).complete(request).catch((error: unknown) => error);
        assert.ok(failure instanceof ProviderError, String(failure));
        assert.equal(failure.reason, reason);
        assert.equal(failure.flags.retryable, retryable);
        if (scenario.retryAfter !== undefined) assert.equal(failure.retryAfterMs, 3000);
      });
    }
  });
}
