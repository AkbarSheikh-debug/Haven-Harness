import assert from 'node:assert/strict';
import { balancedCuts, estimateText, isPinned, SUMMARY_SECTIONS } from '@hn/context';
import type { SessionEvent } from '@hn/core';
import type { ModelRequest } from '@hn/provider';
import { deriveSurface } from '@hn/session';

/** A summary draft with every section, as a well-behaved summary model writes it. */
export const DRAFT = SUMMARY_SECTIONS.map((section) => `## ${section}\nWork so far on ${section}.`).join('\n');

/**
 * What a fake provider counts for a request. It includes the JSON framing of every message, so it reads about
 * twice our own estimate: the loop must cope with a provider that counts more than we do.
 */
export function requestTokens(request: ModelRequest): number {
  const parts = request.messages.map((message) => estimateText(JSON.stringify(message.parts)) + 4);
  return estimateText(request.system) + estimateText(JSON.stringify(request.tools)) + parts.reduce((a, b) => a + b, 0);
}

export const isSummaryRequest = (request: ModelRequest): boolean =>
  JSON.stringify(request.messages.at(-1)).includes('NEW TURNS TO INCORPORATE');

/** Every call on the surface has its result there, and no result lacks its call. */
export function assertSurfaceBalanced(events: readonly SessionEvent[], label: string): void {
  const rows = deriveSurface(events).filter((row) => !isPinned(row));
  assert.equal(balancedCuts(rows).at(-1), true, `${label}: a call on the surface has no result`);
  const calls = new Set(
    rows.flatMap((row) => (row.data['toolCalls'] as { id: string }[] | undefined)?.map((call) => call.id) ?? []),
  );
  for (const row of rows) {
    if (row.type === 'tool/result') assert.ok(calls.has(row.data['callId'] as string), `${label}: an orphan result`);
  }
}

/**
 * Every call has exactly one original result, and no original result lacks its call. A fold adds replacement
 * rows that shadow an original, so those are not counted: the surface check judges what the model sees.
 */
export function assertOneResultPerCall(events: readonly SessionEvent[]): void {
  const results = new Map<string, number>();
  for (const event of events) {
    if (event.type !== 'tool/result' || event.data['surfaceOp'] !== undefined) continue;
    const id = event.data['callId'] as string;
    results.set(id, (results.get(id) ?? 0) + 1);
  }
  const calls = new Set<string>();
  for (const event of events) {
    if (event.type !== 'assistant/message') continue;
    for (const call of (event.data['toolCalls'] as { id: string }[] | undefined) ?? []) {
      calls.add(call.id);
      assert.equal(results.get(call.id), 1, `call ${call.id} has ${results.get(call.id) ?? 0} results`);
    }
  }
  for (const id of results.keys()) assert.ok(calls.has(id), `result for ${id} has no call`);
}

/**
 * The pairing rule a provider enforces on every request: each assistant message's calls are answered, every one,
 * by the user messages right after it, and no result answers a call from anywhere else. Null when it holds.
 */
export function pairingProblem(request: ModelRequest): string | null {
  let open = new Set<string>();
  for (const [index, message] of request.messages.entries()) {
    if (message.role === 'assistant') {
      if (open.size > 0) return `message ${index}: calls ${[...open].join(', ')} have no result`;
      open = new Set(message.parts.flatMap((part) => (part.type === 'tool_call' ? [part.id] : [])));
      continue;
    }
    for (const part of message.parts) {
      if (part.type !== 'tool_result') continue;
      if (!open.has(part.callId)) return `message ${index}: result for ${part.callId} answers no open call`;
      open.delete(part.callId);
    }
  }
  return open.size > 0 ? `the last calls ${[...open].join(', ')} have no result` : null;
}

/** Every fold that started also ended. */
export function assertFoldsClosed(events: readonly SessionEvent[], label: string): void {
  const open = new Set<string>();
  for (const event of events) {
    if (event.type === 'compaction/start') open.add(event.data['compactionId'] as string);
    if (event.type === 'compaction/end') open.delete(event.data['compactionId'] as string);
  }
  assert.equal(open.size, 0, `${label}: a fold was left open`);
}
