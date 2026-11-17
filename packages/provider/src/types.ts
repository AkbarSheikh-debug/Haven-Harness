/** Neutral shapes. Nothing above this package may import a vendor type. */

export interface TextPart {
  readonly type: 'text';
  readonly text: string;
}

export interface ToolCallPart {
  readonly type: 'tool_call';
  readonly id: string;
  readonly name: string;
  readonly args: unknown;
}

/** One image, base64 encoded. Only formats every vision route accepts. */
export interface ImageData {
  readonly mediaType: 'image/png' | 'image/jpeg' | 'image/gif' | 'image/webp';
  readonly data: string;
}

export interface ToolResultPart {
  readonly type: 'tool_result';
  readonly callId: string;
  readonly content: string;
  readonly isError?: boolean;
  /** Pictures that belong to this result. Each adapter carries them the way its API allows. */
  readonly images?: readonly ImageData[];
}

/**
 * Provider data the harness stores but never reads, such as thinking signatures.
 * It is replayed byte for byte on its own route and dropped everywhere else.
 */
export interface OpaquePart {
  readonly type: 'opaque';
  readonly route: string;
  readonly value: unknown;
}

export type MessagePart = TextPart | ToolCallPart | ToolResultPart | OpaquePart;

export interface ProviderMessage {
  readonly role: 'user' | 'assistant';
  readonly parts: readonly MessagePart[];
}

export interface ToolSpec {
  readonly name: string;
  readonly description: string;
  readonly parameters: Readonly<Record<string, unknown>>;
}

export type Effort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';

export interface ModelRequest {
  readonly model: string;
  readonly system: string;
  readonly tools: readonly ToolSpec[];
  readonly messages: readonly ProviderMessage[];
  readonly maxOutputTokens: number;
  readonly effort?: Effort;
  /** `none` asks for words only. The tools stay in the request, so the prefix stays cached. */
  readonly toolChoice?: 'none';
  readonly signal?: AbortSignal;
  readonly onEvent?: (event: StreamEvent) => void;
}

export type StreamEvent =
  | { readonly type: 'text'; readonly text: string }
  | { readonly type: 'thinking'; readonly text: string }
  | { readonly type: 'tool_input'; readonly name: string };

/** `refusal` and `length` mean no tool from this reply may run. */
export type StopReason = 'end' | 'tool_use' | 'length' | 'refusal' | 'pause';

export interface Usage {
  /** Fresh input tokens, excluding cache reads and writes. */
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number;
  readonly cacheWrite: number;
}

export interface ModelReply {
  readonly parts: readonly MessagePart[];
  readonly stopReason: StopReason;
  readonly usage: Usage | null;
  readonly model: string;
  /** Provider notes about what it changed in the request, kept for the log. */
  readonly transformations?: readonly unknown[];
}

export interface ModelProvider {
  readonly route: string;
  complete(request: ModelRequest): Promise<ModelReply>;
}

/** Everything the context window currently holds, as the provider counts it. */
export function contextTokens(usage: Usage): number {
  return usage.input + usage.cacheRead + usage.cacheWrite;
}
