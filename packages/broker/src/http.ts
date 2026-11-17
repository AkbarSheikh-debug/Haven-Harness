import type { IncomingMessage, ServerResponse } from 'node:http';
import { sanitizeForDisplay } from '@hn/core';

/** Small, strict HTTP helpers for the broker. Every body has a size cap and must be JSON. */

export class HttpRefusal extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function readJson(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  const type = request.headers['content-type'] ?? '';
  if (!type.startsWith('application/json')) throw new HttpRefusal(415, 'The body must be JSON.');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += (chunk as Buffer).length;
    if (size > maxBytes) throw new HttpRefusal(413, 'The body is too large.');
    chunks.push(chunk as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpRefusal(400, 'The body is not JSON.');
  }
}

export function sendJson(response: ServerResponse, status: number, body: unknown): void {
  if (response.headersSent) return;
  const text = JSON.stringify(body);
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(text), 'x-content-type-options': 'nosniff' });
  response.end(text);
}

/** A refusal's text is shown on someone's terminal, so it is cleaned like any other text from far away. */
export const refusal = (response: ServerResponse, status: number, message: string): void => sendJson(response, status, { error: sanitizeForDisplay(message) });

export const header = (request: IncomingMessage, name: string): string | undefined => {
  const value = request.headers[name];
  return typeof value === 'string' ? value : undefined;
};
