import type { Readable, Writable } from 'node:stream';

/** One message, one line. A longer line is dropped, never buffered without end. */
export const MAX_LINE = 4 * 1024 * 1024;

export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL = -32603;

export class RpcError extends Error {
  readonly code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export type Params = Readonly<Record<string, unknown>>;

interface Pending {
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout | undefined;
}

const isId = (value: unknown): value is string | number => typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value));
const isParams = (value: unknown): value is Params | undefined => value === undefined || (typeof value === 'object' && value !== null && !Array.isArray(value));

/**
 * JSON-RPC 2.0, one object per line, both directions over one pair of streams. This is the editor's end of a pipe to a
 * process it did not write, so every line is hostile until it parses into one well-formed message, and a bad line is
 * dropped (or answered with an error when it has an id) and never stops the peer. A line over MAX_LINE is discarded up to
 * its newline, so one oversized message cannot become many.
 */
export class Peer {
  readonly #output: Writable;
  readonly #pending = new Map<string | number, Pending>();
  readonly #onRequest: (method: string, params: Params) => Promise<unknown>;
  readonly #onNotification: (method: string, params: Params) => void;
  #nextId = 1;
  #buffer = '';
  #skipping = false;
  #open = true;
  dropped = 0;

  constructor(input: Readable, output: Writable, handlers: { request: (method: string, params: Params) => Promise<unknown>; notification: (method: string, params: Params) => void }) {
    this.#output = output;
    this.#onRequest = handlers.request;
    this.#onNotification = handlers.notification;
    output.on('error', () => this.#shut());
    input.setEncoding('utf8');
    input.on('data', (chunk: string) => this.#take(chunk));
    input.on('end', () => this.#shut());
    input.on('close', () => this.#shut());
    input.on('error', () => this.#shut());
  }

  get open(): boolean {
    return this.#open;
  }

  #take(chunk: string): void {
    let rest = chunk;
    while (rest !== '') {
      const end = rest.indexOf('\n');
      if (this.#skipping) {
        if (end === -1) return;
        this.#skipping = false;
        rest = rest.slice(end + 1);
        continue;
      }
      if (end === -1) {
        this.#buffer += rest;
        if (this.#buffer.length > MAX_LINE) {
          this.#buffer = '';
          this.#skipping = true;
          this.dropped += 1;
        }
        return;
      }
      const line = (this.#buffer + rest.slice(0, end)).trim();
      this.#buffer = '';
      rest = rest.slice(end + 1);
      if (line.length > MAX_LINE) this.dropped += 1;
      else if (line !== '') this.#line(line);
    }
  }

  #line(line: string): void {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      this.dropped += 1;
      return;
    }
    if (typeof message !== 'object' || message === null || Array.isArray(message) || (message as Record<string, unknown>)['jsonrpc'] !== '2.0') {
      this.dropped += 1;
      return;
    }
    const record = message as Record<string, unknown>;
    const { id, method, params } = record;
    if (typeof method === 'string') {
      if (!isParams(params)) {
        if (isId(id)) this.#send({ jsonrpc: '2.0', id, error: { code: INVALID_PARAMS, message: 'params must be an object.' } });
        return;
      }
      if (id === undefined) {
        try {
          this.#onNotification(method, params ?? {});
        } catch {
          // A notification has nobody to answer, and a bad one never stops the peer.
        }
        return;
      }
      if (!isId(id)) {
        this.dropped += 1;
        return;
      }
      void this.#onRequest(method, params ?? {}).then(
        (result) => this.#send({ jsonrpc: '2.0', id, result: result ?? null }),
        (error: unknown) => this.#send({ jsonrpc: '2.0', id, error: { code: error instanceof RpcError ? error.code : INTERNAL, message: error instanceof Error ? error.message : 'failed' } }),
      );
      return;
    }
    // A response to one of ours. An unknown id is dropped.
    if (!isId(id)) return;
    const pending = this.#pending.get(id);
    if (pending === undefined) return;
    this.#pending.delete(id);
    if (pending.timer !== undefined) clearTimeout(pending.timer);
    const error = record['error'];
    if (typeof error === 'object' && error !== null) {
      const { code, message: text } = error as Record<string, unknown>;
      pending.reject(new RpcError(typeof code === 'number' ? code : INTERNAL, typeof text === 'string' ? text : 'The agent failed.'));
    } else pending.resolve(record['result']);
  }

  #send(message: Record<string, unknown>): void {
    if (!this.#open) return;
    this.#output.write(`${JSON.stringify(message)}\n`);
  }

  request(method: string, params: Params = {}, timeoutMs?: number): Promise<unknown> {
    if (!this.#open) return Promise.reject(new RpcError(INTERNAL, 'The connection to hn is closed.'));
    const id = this.#nextId;
    this.#nextId += 1;
    return new Promise((resolve, reject) => {
      const timer =
        timeoutMs === undefined
          ? undefined
          : setTimeout(() => {
              this.#pending.delete(id);
              reject(new RpcError(INTERNAL, `${method} got no answer in ${Math.round(timeoutMs / 1000)} seconds.`));
            }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#send({ jsonrpc: '2.0', id, method, params });
    });
  }

  notify(method: string, params: Params = {}): void {
    this.#send({ jsonrpc: '2.0', method, params });
  }

  #shut(): void {
    if (!this.#open) return;
    this.#open = false;
    for (const [id, pending] of this.#pending) {
      if (pending.timer !== undefined) clearTimeout(pending.timer);
      pending.reject(new RpcError(INTERNAL, 'hn stopped before it answered.'));
      this.#pending.delete(id);
    }
  }

  close(): void {
    this.#shut();
    this.#output.end();
  }
}
