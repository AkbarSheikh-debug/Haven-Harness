import type { ModelCaps } from './caps.ts';
import { ProviderError, classifyStatus, parseRetryAfter } from './errors.ts';
import type {
  MessagePart,
  ModelProvider,
  ModelReply,
  ModelRequest,
  ProviderMessage,
  StopReason,
  Usage,
} from './types.ts';

export interface OpenAICompatibleOptions {
  readonly route: string;
  readonly baseUrl: string;
  readonly apiKey?: () => string | Promise<string>;
  readonly caps: (model: string) => ModelCaps;
  readonly fetch?: typeof fetch;
}

type WireMessage = Record<string, unknown>;

interface ToolCallDraft {
  id: string;
  name: string;
  args: string;
}

interface StreamChoice {
  delta?: {
    content?: string | null;
    reasoning_content?: string | null;
    reasoning?: string | null;
    tool_calls?: { index: number; id?: string; function?: { name?: string; arguments?: string } }[];
  };
  finish_reason?: string | null;
}

interface StreamChunk {
  model?: string;
  choices?: StreamChoice[];
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    prompt_tokens_details?: { cached_tokens?: number };
  } | null;
}

function assistantMessage(parts: readonly MessagePart[], route: string, replay: boolean): WireMessage {
  const text = parts.flatMap((part) => (part.type === 'text' ? [part.text] : [])).join('');
  const calls = parts.flatMap((part) => (part.type === 'tool_call' ? [part] : []));
  const reasoning = parts.find((part) => part.type === 'opaque' && part.route === route);
  return {
    role: 'assistant',
    content: text,
    ...(replay && reasoning?.type === 'opaque' ? { reasoning_content: reasoning.value } : {}),
    ...(calls.length === 0
      ? {}
      : {
          tool_calls: calls.map((call) => ({
            id: call.id,
            type: 'function',
            function: { name: call.name, arguments: JSON.stringify(call.args) },
          })),
        }),
  };
}

type ContentPart = Record<string, unknown>;

function picturesOf(parts: readonly MessagePart[]): ContentPart[] {
  return parts.flatMap((part) =>
    part.type === 'tool_result' && part.images !== undefined && part.images.length > 0
      ? [
          { type: 'text', text: `Images from tool call ${part.callId}:` },
          ...part.images.map((image) => ({ type: 'image_url', image_url: { url: `data:${image.mediaType};base64,${image.data}` } })),
        ]
      : [],
  );
}

export function toOpenAIMessages(
  system: string,
  messages: readonly ProviderMessage[],
  route: string,
  replay: boolean,
): WireMessage[] {
  const wire: WireMessage[] = [{ role: 'system', content: system }];
  // A tool message holds text only, and nothing may sit between the tool messages of one round. Pictures wait
  // until the round's last result, then go in one user message (with any text that follows the round).
  let pictures: ContentPart[] = [];
  const flush = (text: string): void => {
    if (pictures.length > 0) wire.push({ role: 'user', content: text === '' ? pictures : [...pictures, { type: 'text', text }] });
    else if (text !== '') wire.push({ role: 'user', content: text });
    pictures = [];
  };
  for (const message of messages) {
    if (message.role === 'assistant') {
      flush('');
      wire.push(assistantMessage(message.parts, route, replay));
      continue;
    }
    for (const part of message.parts) {
      if (part.type === 'tool_result') wire.push({ role: 'tool', tool_call_id: part.callId, content: part.content });
    }
    pictures.push(...picturesOf(message.parts));
    const text = message.parts.flatMap((part) => (part.type === 'text' ? [part.text] : [])).join('\n');
    if (text !== '') flush(text);
  }
  flush('');
  return wire;
}

/** Yields each JSON payload of a server-sent event stream. */
async function* sseEvents(body: ReadableStream<Uint8Array>): AsyncGenerator<string> {
  const decoder = new TextDecoder();
  let buffer = '';
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    let end = buffer.indexOf('\n');
    while (end !== -1) {
      const line = buffer.slice(0, end).trim();
      buffer = buffer.slice(end + 1);
      if (line.startsWith('data:')) yield line.slice(5).trim();
      end = buffer.indexOf('\n');
    }
  }
}

function parseArgs(raw: string): unknown {
  try {
    return JSON.parse(raw === '' ? '{}' : raw);
  } catch {
    // Handed on as data, so the loop can tell the model exactly what it sent.
    return { INVALID_JSON: raw };
  }
}

const STOP_REASONS: Readonly<Record<string, StopReason>> = {
  stop: 'end',
  tool_calls: 'tool_use',
  length: 'length',
  content_filter: 'refusal',
};

function toUsage(raw: StreamChunk['usage']): Usage | null {
  if (raw === null || raw === undefined) return null;
  const cached = raw.prompt_tokens_details?.cached_tokens ?? 0;
  return { input: (raw.prompt_tokens ?? 0) - cached, output: raw.completion_tokens ?? 0, cacheRead: cached, cacheWrite: 0 };
}

class ReplyBuilder {
  text = '';
  reasoning = '';
  model: string;
  finish: string | null = null;
  usage: Usage | null = null;
  readonly calls = new Map<number, ToolCallDraft>();

  constructor(model: string) {
    this.model = model;
  }

  add(chunk: StreamChunk, request: ModelRequest): void {
    this.model = chunk.model ?? this.model;
    this.usage = toUsage(chunk.usage) ?? this.usage;
    const choice = chunk.choices?.[0];
    if (choice === undefined) return;
    this.finish = choice.finish_reason ?? this.finish;
    const { content, tool_calls: calls } = choice.delta ?? {};
    const reasoning = choice.delta?.reasoning_content ?? choice.delta?.reasoning;
    if (content) {
      this.text += content;
      request.onEvent?.({ type: 'text', text: content });
    }
    if (reasoning) {
      this.reasoning += reasoning;
      request.onEvent?.({ type: 'thinking', text: reasoning });
    }
    for (const call of calls ?? []) this.addCall(call, request);
  }

  private addCall(call: NonNullable<NonNullable<StreamChoice['delta']>['tool_calls']>[number], request: ModelRequest): void {
    const draft = this.calls.get(call.index) ?? { id: '', name: '', args: '' };
    if (draft.name === '' && call.function?.name) request.onEvent?.({ type: 'tool_input', name: call.function.name });
    draft.id = call.id ?? draft.id;
    draft.name += call.function?.name ?? '';
    draft.args += call.function?.arguments ?? '';
    this.calls.set(call.index, draft);
  }

  build(route: string): ModelReply {
    if (this.finish === null) throw new ProviderError('stream_cut', 'The stream ended before a finish reason.');
    const stopReason = this.calls.size > 0 && this.finish === 'stop' ? 'tool_use' : (STOP_REASONS[this.finish] ?? 'end');
    const parts: MessagePart[] = [];
    if (this.reasoning !== '') parts.push({ type: 'opaque', route, value: this.reasoning });
    if (this.text !== '') parts.push({ type: 'text', text: this.text });
    if (stopReason === 'tool_use') {
      for (const [index, call] of [...this.calls].sort(([a], [b]) => a - b)) {
        parts.push({ type: 'tool_call', id: call.id || `call_${index}`, name: call.name, args: parseArgs(call.args) });
      }
    }
    return { parts, stopReason, usage: this.usage, model: this.model };
  }
}

function toProviderError(error: unknown): ProviderError {
  if (error instanceof ProviderError) return error;
  if (error instanceof Error && error.name === 'AbortError') return new ProviderError('aborted', 'Request aborted.');
  return new ProviderError('connection', error instanceof Error ? error.message : 'Request failed.', { cause: error });
}

export function createOpenAICompatibleProvider(options: OpenAICompatibleOptions): ModelProvider {
  const send = options.fetch ?? fetch;
  const { route } = options;

  return {
    route,
    async complete(request) {
      const caps = options.caps(request.model);
      const body = {
        model: request.model,
        stream: true,
        stream_options: { include_usage: true },
        max_tokens: Math.min(request.maxOutputTokens, caps.maxOutput),
        messages: toOpenAIMessages(request.system, request.messages, route, caps.reasoningReplay),
        ...(request.tools.length === 0
          ? {}
          : {
              tools: request.tools.map((tool) => ({
                type: 'function',
                function: { name: tool.name, description: tool.description, parameters: tool.parameters },
              })),
            }),
        ...(request.toolChoice === 'none' ? { tool_choice: 'none' } : {}),
      };

      try {
        const key = await options.apiKey?.();
        const response = await send(`${options.baseUrl}/chat/completions`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(key === undefined ? {} : { authorization: `Bearer ${key}` }),
          },
          body: JSON.stringify(body),
          ...(request.signal === undefined ? {} : { signal: request.signal }),
        });
        if (!response.ok || response.body === null) {
          const text = await response.text();
          throw new ProviderError(classifyStatus(response.status, text), text.slice(0, 500), {
            status: response.status,
            retryAfterMs: parseRetryAfter(response.headers.get('retry-after')),
          });
        }

        const reply = new ReplyBuilder(request.model);
        for await (const data of sseEvents(response.body)) {
          if (data === '[DONE]') break;
          reply.add(JSON.parse(data) as StreamChunk, request);
        }
        return reply.build(route);
      } catch (error) {
        if (error instanceof SyntaxError) {
          throw new ProviderError('stream_cut', 'The stream held invalid JSON.', { cause: error });
        }
        throw toProviderError(error);
      }
    },
  };
}
