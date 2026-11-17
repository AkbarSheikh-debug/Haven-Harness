import { randomUUID } from 'node:crypto';
import type { ModelCaps } from './caps.ts';
import { ProviderError, classifyStatus } from './errors.ts';
import type { MessagePart, ModelProvider, ModelRequest, ProviderMessage, Usage } from './types.ts';

const ROUTE = 'ollama';

export interface OllamaOptions {
  readonly baseUrl: string;
  readonly caps: (model: string) => ModelCaps;
  readonly numCtx: number;
  readonly fetch?: typeof fetch;
}

interface OllamaChunk {
  message?: {
    content?: string;
    thinking?: string;
    tool_calls?: { function: { name: string; arguments: unknown } }[];
  };
  done?: boolean;
  done_reason?: string;
  prompt_eval_count?: number;
  eval_count?: number;
  error?: string;
}

type WireMessage = Record<string, unknown>;

function toWire(system: string, messages: readonly ProviderMessage[]): WireMessage[] {
  const toolNames = new Map<string, string>();
  const wire: WireMessage[] = [{ role: 'system', content: system }];
  // Pictures wait for the round's last result, then ride on one user message, the form Ollama vision models read.
  let images: string[] = [];
  const flush = (text: string): void => {
    if (images.length > 0) wire.push({ role: 'user', content: text === '' ? 'Images from the tool results above.' : text, images });
    else if (text !== '') wire.push({ role: 'user', content: text });
    images = [];
  };
  for (const { role, parts } of messages) {
    const text = parts.flatMap((part) => (part.type === 'text' ? [part.text] : [])).join('');
    const calls = parts.flatMap((part) => (part.type === 'tool_call' ? [part] : []));
    calls.forEach((call) => toolNames.set(call.id, call.name));
    if (role === 'assistant') {
      flush('');
      wire.push({
        role,
        content: text,
        ...(calls.length === 0
          ? {}
          : { tool_calls: calls.map((call) => ({ function: { name: call.name, arguments: call.args } })) }),
      });
      continue;
    }
    for (const part of parts) {
      if (part.type === 'tool_result') {
        wire.push({ role: 'tool', tool_name: toolNames.get(part.callId) ?? '', content: part.content });
        images.push(...(part.images ?? []).map((image) => image.data));
      }
    }
    if (text !== '') flush(text);
  }
  flush('');
  return wire;
}

async function* ndjson(body: ReadableStream<Uint8Array>): AsyncGenerator<OllamaChunk> {
  const decoder = new TextDecoder();
  let buffer = '';
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';
    for (const line of lines) if (line.trim() !== '') yield JSON.parse(line) as OllamaChunk;
  }
}

async function send(options: OllamaOptions, request: ModelRequest): Promise<Response> {
  const caps = options.caps(request.model);
  const response = await (options.fetch ?? fetch)(`${options.baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: request.model,
      stream: true,
      messages: toWire(request.system, request.messages),
      options: { num_ctx: options.numCtx, num_predict: Math.min(request.maxOutputTokens, caps.maxOutput) },
      ...(request.toolChoice === 'none' || request.tools.length === 0
        ? {}
        : {
            tools: request.tools.map((tool) => ({
              type: 'function',
              function: { name: tool.name, description: tool.description, parameters: tool.parameters },
            })),
          }),
    }),
    ...(request.signal === undefined ? {} : { signal: request.signal }),
  });
  if (!response.ok || response.body === null) {
    const text = await response.text();
    throw new ProviderError(classifyStatus(response.status, text), text.slice(0, 500), { status: response.status });
  }
  return response;
}

/**
 * Ollama's OpenAI-style endpoint silently ignores `num_ctx` and truncates at its
 * default of 4,096 tokens, so local models use the native endpoint.
 */
export function createOllamaProvider(options: OllamaOptions): ModelProvider {
  return {
    route: ROUTE,
    async complete(request) {
      let text = '';
      let thinking = '';
      let last: OllamaChunk | null = null;
      const calls: MessagePart[] = [];
      try {
        const response = await send(options, request);
        for await (const chunk of ndjson(response.body as ReadableStream<Uint8Array>)) {
          if (chunk.error !== undefined) throw new ProviderError('server_error', chunk.error);
          const { content, thinking: reasoning, tool_calls: toolCalls } = chunk.message ?? {};
          if (content) {
            text += content;
            request.onEvent?.({ type: 'text', text: content });
          }
          if (reasoning) {
            thinking += reasoning;
            request.onEvent?.({ type: 'thinking', text: reasoning });
          }
          for (const call of toolCalls ?? []) {
            request.onEvent?.({ type: 'tool_input', name: call.function.name });
            // Ollama sends no ids, so each call gets one here.
            calls.push({ type: 'tool_call', id: `call_${randomUUID()}`, name: call.function.name, args: call.function.arguments });
          }
          if (chunk.done === true) last = chunk;
        }
      } catch (error) {
        if (error instanceof ProviderError) throw error;
        if (error instanceof SyntaxError) throw new ProviderError('stream_cut', 'The stream held invalid JSON.');
        if (error instanceof Error && error.name === 'AbortError') throw new ProviderError('aborted', 'Request aborted.');
        throw new ProviderError('connection', error instanceof Error ? error.message : 'Request failed.', { cause: error });
      }
      if (last === null) throw new ProviderError('stream_cut', 'The stream ended before it finished.');

      // Some thinking models (qwen3 on Ollama 0.40, seen live) sometimes put their reasoning in the content,
      // closed by `</think>`. That is reasoning, not the answer, so it joins the thinking part.
      const closed = text.lastIndexOf('</think>');
      if (closed !== -1) {
        thinking += text.slice(0, closed).replace(/^\s*<think>/, '');
        text = text.slice(closed + '</think>'.length).trim();
      }
      const finished = last as OllamaChunk;
      const cutOff = finished.done_reason === 'length';
      const usage: Usage = { input: finished.prompt_eval_count ?? 0, output: finished.eval_count ?? 0, cacheRead: 0, cacheWrite: 0 };
      return {
        parts: [
          ...(thinking === '' ? [] : [{ type: 'opaque' as const, route: ROUTE, value: thinking }]),
          ...(text === '' ? [] : [{ type: 'text' as const, text }]),
          ...(cutOff ? [] : calls),
        ],
        stopReason: cutOff ? 'length' : calls.length > 0 ? 'tool_use' : 'end',
        usage,
        model: request.model,
      };
    },
  };
}
