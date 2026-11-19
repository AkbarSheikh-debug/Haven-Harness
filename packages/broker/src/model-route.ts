import { HnError } from '@hn/core';
import { costOf, createAnthropicProvider, createOllamaProvider, createOpenAICompatibleProvider, resolveCaps, type KeyStore, type MessagePart, type ModelProvider, type ModelReply, type ModelRequest, type ProviderMessage, type StreamEvent, type ToolSpec } from '@hn/provider';
import type { PolicySet } from '@hn/security';
import { globMatch, type Upstream } from './config.ts';

/**
 * A governed model call (decision 5). The client sends a provider-neutral request; the broker decides whether this
 * person may use this model today, removes tools the policy denies them from what goes upstream, calls the model
 * with a key the client never sees, and removes any call to a denied tool from the reply, so a client that
 * ignores its own gate still never receives one. What arrives is untrusted input and is checked field by field.
 */

export class ModelRouteError extends HnError {
  readonly status: number;
  constructor(status: number, message: string) {
    super('BROKER_REFUSED', message);
    this.status = status;
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const bad = (message: string): never => {
  throw new ModelRouteError(400, message);
};

function parsePart(value: unknown): MessagePart {
  if (!isRecord(value)) return bad('A message part is not an object.');
  switch (value['type']) {
    case 'text':
      if (typeof value['text'] !== 'string') bad('A text part has no text.');
      return { type: 'text', text: value['text'] as string };
    case 'tool_call':
      if (typeof value['id'] !== 'string' || typeof value['name'] !== 'string') bad('A tool call needs an id and a name.');
      return { type: 'tool_call', id: value['id'] as string, name: value['name'] as string, args: value['args'] };
    case 'tool_result': {
      if (typeof value['callId'] !== 'string' || typeof value['content'] !== 'string') bad('A tool result needs a call id and content.');
      const images = value['images'];
      if (images !== undefined && (!Array.isArray(images) || !images.every((image) => isRecord(image) && ['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(image['mediaType'] as string) && typeof image['data'] === 'string'))) bad('A tool result has a bad image.');
      return { type: 'tool_result', callId: value['callId'] as string, content: value['content'] as string, ...(value['isError'] === true ? { isError: true } : {}), ...(images === undefined ? {} : { images: images as never }) };
    }
    case 'opaque':
      if (typeof value['route'] !== 'string') bad('An opaque part needs a route.');
      return { type: 'opaque', route: value['route'] as string, value: value['value'] };
    default:
      return bad('A message part has an unknown type.');
  }
}

/** The request as the broker will use it. Nothing the client sends beyond these fields is passed on. */
export function parseModelRequest(value: unknown): Omit<ModelRequest, 'signal' | 'onEvent'> {
  if (!isRecord(value)) return bad('The request is not an object.');
  const { model, system, tools, messages, maxOutputTokens, effort, toolChoice } = value;
  if (typeof model !== 'string' || model === '' || model.length > 200) bad('model is missing.');
  if (typeof system !== 'string') bad('system is missing.');
  if (typeof maxOutputTokens !== 'number' || !Number.isInteger(maxOutputTokens) || maxOutputTokens < 1 || maxOutputTokens > 1_000_000) bad('maxOutputTokens is not a sane number.');
  if (!Array.isArray(tools) || tools.length > 512) bad('tools must be a list.');
  const specs = (tools as unknown[]).map((tool): ToolSpec => {
    if (!isRecord(tool) || typeof tool['name'] !== 'string' || typeof tool['description'] !== 'string' || !isRecord(tool['parameters'])) return bad('A tool needs a name, a description and parameters.');
    return { name: tool['name'], description: tool['description'], parameters: tool['parameters'] };
  });
  if (!Array.isArray(messages) || messages.length > 100_000) bad('messages must be a list.');
  const parsed = (messages as unknown[]).map((message): ProviderMessage => {
    if (!isRecord(message) || (message['role'] !== 'user' && message['role'] !== 'assistant') || !Array.isArray(message['parts'])) return bad('A message needs a role and parts.');
    return { role: message['role'], parts: message['parts'].map(parsePart) };
  });
  if (effort !== undefined && !['low', 'medium', 'high', 'xhigh', 'max'].includes(effort as string)) bad('effort is not a known level.');
  if (toolChoice !== undefined && toolChoice !== 'none') bad('toolChoice may only be none.');
  return {
    model: model as string,
    system: system as string,
    tools: specs,
    messages: parsed,
    maxOutputTokens: maxOutputTokens as number,
    ...(effort === undefined ? {} : { effort: effort as ModelRequest['effort'] & string }),
    ...(toolChoice === undefined ? {} : { toolChoice: 'none' as const }),
  };
}

export function upstreamFor(upstreams: readonly Upstream[], model: string): Upstream | null {
  return upstreams.find((upstream) => upstream.models.some((pattern) => globMatch(pattern, model))) ?? null;
}

/** One provider per upstream, holding the broker's key. The key is fetched per call and never written anywhere. */
export function makeUpstreamProvider(upstream: Upstream, keys: KeyStore): ModelProvider {
  const apiKey = upstream.key === undefined ? undefined : (): string => keys.get(upstream.key as never);
  if (upstream.kind === 'anthropic') return createAnthropicProvider({ apiKey: apiKey ?? ((): string => keys.get('ANTHROPIC_API_KEY')), caps: resolveCaps });
  const caps = (model: string) => resolveCaps(model, { window: 32_000, maxOutput: 8_192, usage: 'final', caching: 'auto' });
  if (upstream.kind === 'ollama') return createOllamaProvider({ baseUrl: upstream.baseUrl as string, caps, numCtx: 32_000 });
  return createOpenAICompatibleProvider({ route: `broker:${upstream.name}`, baseUrl: upstream.baseUrl as string, caps, ...(apiKey === undefined ? {} : { apiKey }) });
}

export interface ToolRule {
  /** Why this person may not use the tool, or null. Both the policy and the token's own caveats are asked. */
  (tool: string): string | null;
}

export function toolRule(policy: PolicySet, covers: (tool: string) => boolean): ToolRule {
  return (tool) => policy.toolReason(tool) ?? (covers(tool) ? null : `${tool} is not covered by this session's token.`);
}

/** Removes calls to denied tools. With none left, a reply that stopped to run tools is now just finished. */
export function stripDeniedCalls(reply: ModelReply, rule: ToolRule): { reply: ModelReply; stripped: { name: string; reason: string }[] } {
  const stripped: { name: string; reason: string }[] = [];
  const parts: MessagePart[] = [];
  for (const part of reply.parts) {
    // A deferred tool is reached through `call_tool`, so the tool it names is judged too (found in the live run).
    const inner = part.type === 'tool_call' && part.name === 'call_tool' && typeof (part.args as { name?: unknown } | null)?.name === 'string' ? ((part.args as { name: string }).name) : null;
    const reason = part.type === 'tool_call' ? (rule(part.name) ?? (inner === null ? null : rule(inner))) : null;
    if (part.type === 'tool_call' && reason !== null) stripped.push({ name: inner ?? part.name, reason });
    else parts.push(part);
  }
  if (stripped.length === 0) return { reply, stripped };
  parts.push({ type: 'text', text: `[broker] Removed ${stripped.length} call(s) to tools you may not use: ${stripped.map((item) => item.name).join(', ')}.` });
  const anyCall = parts.some((part) => part.type === 'tool_call');
  return { reply: { ...reply, parts, stopReason: reply.stopReason === 'tool_use' && !anyCall ? 'end' : reply.stopReason }, stripped };
}

export interface GovernedCall {
  readonly request: Omit<ModelRequest, 'signal' | 'onEvent'>;
  readonly provider: ModelProvider;
  readonly rule: ToolRule;
  readonly onEvent: (event: StreamEvent) => void;
  readonly signal: AbortSignal;
}

export interface GovernedResult {
  readonly reply: ModelReply;
  readonly removedTools: readonly string[];
  readonly stripped: readonly { name: string; reason: string }[];
  readonly usd: number;
  readonly tokens: number;
}

/** Calls upstream with only the allowed tools, then strips the reply. Tool-name text in a stream is not forwarded for denied tools. */
export async function governedCall(call: GovernedCall): Promise<GovernedResult> {
  const allowed = call.request.tools.filter((tool) => call.rule(tool.name) === null);
  const removedTools = call.request.tools.filter((tool) => call.rule(tool.name) !== null).map((tool) => tool.name);
  const raw = await call.provider.complete({
    ...call.request,
    tools: allowed,
    signal: call.signal,
    onEvent: (event) => {
      if (event.type === 'tool_input' && call.rule(event.name) !== null) return;
      call.onEvent(event);
    },
  });
  const { reply, stripped } = stripDeniedCalls(raw, call.rule);
  const usage = reply.usage;
  const tokens = usage === null ? 0 : usage.input + usage.output + usage.cacheRead + usage.cacheWrite;
  const usd = usage === null ? 0 : (costOf(call.request.model, usage) ?? 0);
  return { reply, removedTools, stripped, usd, tokens };
}
