import Anthropic from '@anthropic-ai/sdk';
import type { ModelCaps } from './caps.ts';
import { ProviderError, classifyStatus, parseRetryAfter } from './errors.ts';
import type {
  MessagePart,
  ModelProvider,
  ModelReply,
  ModelRequest,
  ProviderMessage,
  StopReason,
  ToolSpec,
  Usage,
} from './types.ts';

const ROUTE = 'anthropic';
const THINKING_BINDING_BETA = 'thinking-binding-controls-2026-08-01';
const SERVER_FALLBACK_BETA = 'server-side-fallback-2026-07-01';

export type PrefixMismatchBehavior = 'drop_block' | 'error';

/** The slice of the SDK this adapter uses, so tests can supply a scripted stream. */
export interface AnthropicClient {
  readonly beta: { readonly messages: { stream: (...args: never[]) => AnthropicStream } };
}

export interface AnthropicStream extends AsyncIterable<unknown> {
  finalMessage(): Promise<unknown>;
}

export interface AnthropicOptions {
  /** Fetched per call, so the key is never kept in memory or the environment. */
  readonly apiKey: () => string | Promise<string>;
  readonly caps: (model: string) => ModelCaps;
  /** CI sets `error`, so a history edit fails the run instead of being papered over. */
  readonly prefixMismatch?: PrefixMismatchBehavior;
  readonly createClient?: (apiKey: string) => AnthropicClient;
}

type WireBlock = Record<string, unknown>;

interface WireMessage {
  role: 'user' | 'assistant';
  content: WireBlock[];
}

/** Ids from another route may hold characters this API refuses. The mapping is pure, so bytes stay stable. */
const wireId = (id: string): string => id.replace(/[^a-zA-Z0-9_-]/g, '_');

function toWireBlock(part: MessagePart): WireBlock | null {
  switch (part.type) {
    case 'text':
      return { type: 'text', text: part.text };
    case 'tool_call':
      return { type: 'tool_use', id: wireId(part.id), name: part.name, input: part.args };
    case 'tool_result':
      return {
        type: 'tool_result',
        tool_use_id: wireId(part.callId),
        content:
          part.images === undefined || part.images.length === 0
            ? part.content
            : [
                { type: 'text', text: part.content },
                ...part.images.map((image) => ({ type: 'image', source: { type: 'base64', media_type: image.mediaType, data: image.data } })),
              ],
        ...(part.isError === true ? { is_error: true } : {}),
      };
    case 'opaque':
      return part.route === ROUTE ? (part.value as WireBlock) : null;
  }
}

/** Parallel results must share one user message, or Claude learns to stop calling tools in parallel. */
function toWireMessages(messages: readonly ProviderMessage[]): WireMessage[] {
  const wire: WireMessage[] = [];
  for (const message of messages) {
    const content = message.parts.map(toWireBlock).filter((block) => block !== null);
    if (content.length === 0) continue;
    const last = wire.at(-1);
    if (last?.role === message.role) last.content.push(...content);
    else wire.push({ role: message.role, content });
  }
  return wire;
}

/** Marks the last two messages. Moving a marker never changes the bytes the history check compares. */
function withCacheMarkers(messages: WireMessage[]): WireMessage[] {
  return messages.map((message, index) => {
    if (index < messages.length - 2) return message;
    const content = [...message.content];
    const at = content.findLastIndex((block) => block['type'] !== 'thinking' && block['type'] !== 'redacted_thinking');
    const target = content[at];
    if (target !== undefined) content[at] = { ...target, cache_control: { type: 'ephemeral' } };
    return { ...message, content };
  });
}

function toWireTool(tool: ToolSpec, streaming: boolean): WireBlock {
  return {
    name: tool.name,
    description: tool.description,
    input_schema: tool.parameters,
    ...(streaming ? { eager_input_streaming: true } : {}),
  };
}

export function buildAnthropicParams(
  request: ModelRequest,
  caps: ModelCaps,
  prefixMismatch: PrefixMismatchBehavior,
): Record<string, unknown> {
  const betas = [
    ...(caps.thinkingBinding ? [THINKING_BINDING_BETA] : []),
    ...(caps.serverFallback ? [SERVER_FALLBACK_BETA] : []),
  ];
  const systemBlock: WireBlock = { type: 'text', text: request.system };
  if (caps.caching === 'explicit') systemBlock['cache_control'] = { type: 'ephemeral' };

  const wire = toWireMessages(request.messages);
  return {
    model: request.model,
    max_tokens: Math.min(request.maxOutputTokens, caps.maxOutput),
    system: [systemBlock],
    tools: request.tools.map((tool) => toWireTool(tool, true)),
    messages: caps.caching === 'explicit' ? withCacheMarkers(wire) : wire,
    ...(caps.adaptiveThinking
      ? {
          thinking: {
            type: 'adaptive',
            display: 'summarized',
            ...(caps.thinkingBinding ? { block_binding: { prefix_mismatch_behavior: prefixMismatch } } : {}),
          },
        }
      : {}),
    ...(caps.effort && request.effort !== undefined ? { output_config: { effort: request.effort } } : {}),
    ...(request.toolChoice === 'none' ? { tool_choice: { type: 'none' } } : {}),
    ...(caps.serverFallback ? { fallbacks: 'default' } : {}),
    ...(betas.length > 0 ? { betas } : {}),
  };
}

const STOP_REASONS: Readonly<Record<string, StopReason>> = {
  end_turn: 'end',
  stop_sequence: 'end',
  tool_use: 'tool_use',
  max_tokens: 'length',
  refusal: 'refusal',
  pause_turn: 'pause',
};

function toUsage(raw: Record<string, number | null | undefined> | undefined): Usage | null {
  if (raw === undefined) return null;
  return {
    input: raw['input_tokens'] ?? 0,
    output: raw['output_tokens'] ?? 0,
    cacheRead: raw['cache_read_input_tokens'] ?? 0,
    cacheWrite: raw['cache_creation_input_tokens'] ?? 0,
  };
}

function fromWireBlock(block: WireBlock): MessagePart | null {
  switch (block['type']) {
    case 'text':
      return { type: 'text', text: block['text'] as string };
    case 'tool_use':
      return { type: 'tool_call', id: block['id'] as string, name: block['name'] as string, args: block['input'] };
    case 'thinking':
    case 'redacted_thinking':
      return { type: 'opaque', route: ROUTE, value: block };
    default:
      return null;
  }
}

function toReply(message: Record<string, unknown>): ModelReply {
  const stopReason = STOP_REASONS[message['stop_reason'] as string] ?? 'end';
  const parts = (message['content'] as WireBlock[]).flatMap((block) => fromWireBlock(block) ?? []);
  const transformations = message['input_transformations'] as readonly unknown[] | undefined;
  return {
    // A reply cut off by max_tokens or a refusal may hold a half-written tool input
    // that still parses, so its tool calls must never reach a tool.
    parts: stopReason === 'tool_use' ? parts : parts.filter((part) => part.type !== 'tool_call'),
    stopReason,
    usage: toUsage(message['usage'] as Record<string, number> | undefined),
    model: message['model'] as string,
    ...(transformations === undefined ? {} : { transformations }),
  };
}

function headerValue(headers: unknown, name: string): string | undefined {
  return headers instanceof Headers ? (headers.get(name) ?? undefined) : undefined;
}

function toProviderError(error: unknown): ProviderError {
  if (error instanceof ProviderError) return error;
  if (error instanceof Anthropic.APIUserAbortError) return new ProviderError('aborted', 'Request aborted.');
  if (error instanceof Anthropic.APIConnectionTimeoutError) {
    return new ProviderError('timeout', 'The request timed out.', { cause: error });
  }
  if (error instanceof Anthropic.APIConnectionError) {
    return new ProviderError('connection', 'Could not reach the API.', { cause: error });
  }
  if (error instanceof Anthropic.APIError && error.status !== undefined) {
    const body = `${error.message} ${JSON.stringify(error.error ?? '')}`;
    return new ProviderError(classifyStatus(error.status, body), error.message, {
      status: error.status,
      retryAfterMs: parseRetryAfter(headerValue(error.headers, 'retry-after')),
      cause: error,
    });
  }
  // The SDK's tolerant parser raises only for tool input it cannot parse at all. No
  // tool_use block completed, so there is nothing to answer and the turn is re-issued.
  if (error instanceof SyntaxError) {
    return new ProviderError('stream_cut', 'Tool input was not valid JSON.', { cause: error });
  }
  return new ProviderError('connection', error instanceof Error ? error.message : 'Stream failed.', { cause: error });
}

function forward(event: unknown, request: ModelRequest): void {
  const { type, delta, content_block: block } = event as {
    type: string;
    delta?: { type: string; text?: string; thinking?: string };
    content_block?: { type: string; name?: string };
  };
  if (type === 'content_block_delta' && delta?.type === 'text_delta' && delta.text !== undefined) {
    request.onEvent?.({ type: 'text', text: delta.text });
  }
  if (type === 'content_block_delta' && delta?.type === 'thinking_delta' && delta.thinking !== undefined) {
    request.onEvent?.({ type: 'thinking', text: delta.thinking });
  }
  if (type === 'content_block_start' && block?.type === 'tool_use' && block.name !== undefined) {
    request.onEvent?.({ type: 'tool_input', name: block.name });
  }
}

export function createAnthropicProvider(options: AnthropicOptions): ModelProvider {
  // Retries belong to the loop, which logs each one and honours its budget.
  const createClient =
    options.createClient ??
    ((apiKey: string) => new Anthropic({ apiKey, maxRetries: 0 }) as unknown as AnthropicClient);
  const prefixMismatch = options.prefixMismatch ?? 'drop_block';

  return {
    route: ROUTE,
    async complete(request) {
      const params = buildAnthropicParams(request, options.caps(request.model), prefixMismatch);
      try {
        const client = createClient(await options.apiKey());
        const stream = (client.beta.messages.stream as (...args: unknown[]) => AnthropicStream)(
          params,
          request.signal === undefined ? {} : { signal: request.signal },
        );
        for await (const event of stream) forward(event, request);
        return toReply((await stream.finalMessage()) as Record<string, unknown>);
      } catch (error) {
        throw toProviderError(error);
      }
    },
  };
}
