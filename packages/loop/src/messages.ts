import { toolCallsOf, type SessionEvent } from '@hn/core';
import type { ImageData, MessagePart, ModelReply, OpaquePart, ProviderMessage } from '@hn/provider';
import { deriveSurface } from '@hn/session';

function textOf(event: SessionEvent): string {
  return typeof event.data['text'] === 'string' ? event.data['text'] : '';
}

function opaqueOf(event: SessionEvent): readonly OpaquePart[] {
  const opaque = event.data['opaque'];
  return Array.isArray(opaque) ? (opaque as OpaquePart[]) : [];
}

function toMessage(event: SessionEvent, keepOpaque: boolean): ProviderMessage | null {
  switch (event.type) {
    case 'user/message':
      return { role: 'user', parts: [{ type: 'text', text: textOf(event) }] };
    case 'tool/result': {
      const images = event.data['images'];
      return {
        role: 'user',
        parts: [
          {
            type: 'tool_result',
            callId: event.data['callId'] as string,
            content: event.data['content'] as string,
            isError: event.data['isError'] === true,
            ...(Array.isArray(images) && images.length > 0 ? { images: images as ImageData[] } : {}),
          },
        ],
      };
    }
    case 'assistant/message': {
      const text = textOf(event);
      const parts: MessagePart[] = [
        ...(keepOpaque ? opaqueOf(event) : []),
        ...(text === '' ? [] : [{ type: 'text' as const, text }]),
        ...toolCallsOf(event).map((call) => ({ type: 'tool_call' as const, ...call })),
      ];
      return parts.length === 0 ? null : { role: 'assistant', parts };
    }
    default:
      return null;
  }
}

/**
 * Rebuilds the model's view from the log. A fold changes what came before it, so any
 * thinking block at or before the newest fold would fail the provider's history
 * check. Those blocks are dropped; their text and tool calls stay word for word.
 */
export function toProviderMessages(events: readonly SessionEvent[]): ProviderMessage[] {
  return surfaceMessages(deriveSurface(events));
}

/** The same mapping for surface rows already derived, such as the prefix a replay summary resends. */
export function surfaceMessages(rows: readonly SessionEvent[]): ProviderMessage[] {
  const newestFold = rows.findLastIndex((row) => row.data['surfaceOp'] !== undefined);
  return rows.flatMap((row, index) => toMessage(row, index > newestFold) ?? []);
}

/** What an `assistant/message` stores, so a reply can be replayed byte for byte. */
export function assistantRow(reply: ModelReply): Record<string, unknown> {
  const text = reply.parts.flatMap((part) => (part.type === 'text' ? [part.text] : [])).join('');
  return {
    text,
    model: reply.model,
    toolCalls: reply.parts.flatMap((part) =>
      part.type === 'tool_call' ? [{ id: part.id, name: part.name, args: part.args }] : [],
    ),
    opaque: reply.parts.filter((part) => part.type === 'opaque'),
  };
}
