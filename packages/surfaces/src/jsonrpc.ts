import type { Readable, Writable } from 'node:stream';

/** One message, one line. A bigger line is refused and dropped, never buffered without end. */
export const MAX_RPC_LINE = 1024 * 1024;

export const RPC_PARSE_ERROR = -32700;
export const RPC_INVALID_REQUEST = -32600;
export const RPC_METHOD_NOT_FOUND = -32601;
export const RPC_INVALID_PARAMS = -32602;
export const RPC_INTERNAL = -32603;
/** The application's own refusals: busy, too many sessions, refused by the gate. */
export const RPC_REFUSED = -32000;

export class RpcError extends Error {
  readonly code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export type RpcParams = Readonly<Record<string, unknown>>;
export type RequestHandler = (method: string, params: RpcParams) => Promise<unknown>;
export type NotificationHandler = (method: string, params: RpcParams) => void;

interface Pending {
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout | undefined;
}

const isId = (value: unknown): value is string | number => typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value));
const isParams = (value: unknown): value is RpcParams | undefined => value === undefined || (typeof value === 'object' && value !== null && !Array.isArray(value));

/**
 * JSON-RPC 2.0, one object per line, in both directions over one pair of streams: either end may send requests and
 * notifications. Every incoming line is hostile until it parses into exactly one well-formed message; a bad line is
 * answered with an error (when it has an id to answer) and never stops the peer.
 */
export class JsonRpcPeer {
  readonly #output: Writable;
  readonly #pending = new Map<string | number, Pending>();
  readonly #onRequest: RequestHandler;
  readonly #onNotification: NotificationHandler;
  readonly #closed: Promise<void>;
  #nextId = 1;
  #buffer = '';
  #open = true;

  constructor(input: Readable, output: Writable, handlers: { readonly request?: RequestHandler; readonly notification?: NotificationHandler } = {}) {
    this.#output = output;
    this.#onRequest = handlers.request ?? (async (method) => {
      throw new RpcError(RPC_METHOD_NOT_FOUND, `There is no method ${method}.`);
    });
    this.#onNotification = handlers.notification ?? (() => undefined);
    output.on('error', () => this.#shut());
    input.setEncoding('utf8');
    this.#closed = new Promise((resolve) => {
      input.on('end', () => {
        this.#shut();
        resolve();
      });
      input.on('close', () => {
        this.#shut();
        resolve();
      });
      input.on('error', () => {
        this.#shut();
        resolve();
      });
    });
    input.on('data', (chunk: string) => this.#take(chunk));
  }

  /** Settles when the other end closes its side. */
  get closed(): Promise<void> {
    return this.#closed;
  }

  get open(): boolean {
    return this.#open;
  }

  #take(chunk: string): void {
    this.#buffer += chunk;
    for (let end = this.#buffer.indexOf('\n'); end !== -1; end = this.#buffer.indexOf('\n')) {
      const line = this.#buffer.slice(0, end).trim();
      this.#buffer = this.#buffer.slice(end + 1);
      if (line !== '') this.#line(line);
    }
    if (this.#buffer.length > MAX_RPC_LINE) {
      this.#buffer = '';
      this.#send({ jsonrpc: '2.0', id: null, error: { code: RPC_INVALID_REQUEST, message: `A message may be at most ${MAX_RPC_LINE} bytes on one line.` } });
    }
  }

  #line(line: string): void {
    if (line.length > MAX_RPC_LINE) {
      this.#send({ jsonrpc: '2.0', id: null, error: { code: RPC_INVALID_REQUEST, message: `A message may be at most ${MAX_RPC_LINE} bytes on one line.` } });
      return;
    }
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      this.#send({ jsonrpc: '2.0', id: null, error: { code: RPC_PARSE_ERROR, message: 'That line is not JSON.' } });
      return;
    }
    if (typeof message !== 'object' || message === null || Array.isArray(message) || (message as Record<string, unknown>)['jsonrpc'] !== '2.0') {
      this.#send({ jsonrpc: '2.0', id: null, error: { code: RPC_INVALID_REQUEST, message: 'Send one JSON-RPC 2.0 object per line.' } });
      return;
    }
    const record = message as Record<string, unknown>;
    const { id, method, params } = record;
    if (typeof method === 'string') {
      if (!isParams(params)) {
        if (isId(id)) this.#send({ jsonrpc: '2.0', id, error: { code: RPC_INVALID_PARAMS, message: 'params must be an object.' } });
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
        this.#send({ jsonrpc: '2.0', id: null, error: { code: RPC_INVALID_REQUEST, message: 'id must be a string or an integer.' } });
        return;
      }
      void this.#onRequest(method, params ?? {}).then(
        (result) => this.#send({ jsonrpc: '2.0', id, result: result ?? null }),
        (error: unknown) => {
          const code = error instanceof RpcError ? error.code : RPC_INTERNAL;
          this.#send({ jsonrpc: '2.0', id, error: { code, message: error instanceof Error ? error.message : String(error) } });
        },
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
      pending.reject(new RpcError(typeof code === 'number' ? code : RPC_INTERNAL, typeof text === 'string' ? text : 'The other end failed.'));
    } else pending.resolve(record['result']);
  }

  #send(message: Record<string, unknown>): void {
    if (!this.#open) return;
    this.#output.write(`${JSON.stringify(message)}\n`);
  }

  request(method: string, params: RpcParams = {}, timeoutMs?: number): Promise<unknown> {
    if (!this.#open) return Promise.reject(new RpcError(RPC_INTERNAL, 'The connection is closed.'));
    const id = this.#nextId;
    this.#nextId += 1;
    return new Promise((resolve, reject) => {
      const timer =
        timeoutMs === undefined
          ? undefined
          : setTimeout(() => {
              this.#pending.delete(id);
              reject(new RpcError(RPC_INTERNAL, `${method} got no answer in ${timeoutMs} ms.`));
            }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#send({ jsonrpc: '2.0', id, method, params });
    });
  }

  notify(method: string, params: RpcParams = {}): void {
    this.#send({ jsonrpc: '2.0', method, params });
  }

  #shut(): void {
    if (!this.#open) return;
    this.#open = false;
    for (const [id, pending] of this.#pending) {
      if (pending.timer !== undefined) clearTimeout(pending.timer);
      pending.reject(new RpcError(RPC_INTERNAL, 'The connection closed before an answer.'));
      this.#pending.delete(id);
    }
  }

  close(): void {
    this.#shut();
    this.#output.end();
  }
}
