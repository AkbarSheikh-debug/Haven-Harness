import { pathToFileURL } from 'node:url';
import type { RunningProcess } from './processes.ts';

/**
 * A Language Server Protocol client over a running process's standard streams (Content-Length framing, JSON-RPC 2.0).
 * The process is started by the session's own process operations, so in a box the server runs in the box. The server
 * runs project code (invariant 14), so starting it is a gated call made by the caller, not here.
 */

export interface LspPosition {
  readonly line: number;
  readonly character: number;
}

export interface LspDiagnostic {
  readonly range: { readonly start: LspPosition; readonly end: LspPosition };
  readonly severity?: number;
  readonly message: string;
  readonly source?: string;
}

interface Pending {
  resolve(value: unknown): void;
  reject(error: Error): void;
  timer: NodeJS.Timeout;
}

const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;

export const fileUri = (path: string): string => pathToFileURL(path).href;

export class LspClient {
  readonly #process: RunningProcess;
  readonly #pending = new Map<number, Pending>();
  readonly #diagnostics = new Map<string, readonly LspDiagnostic[]>();
  readonly #diagnosticWaiters: (() => void)[] = [];
  #buffer = Buffer.alloc(0);
  #next = 1;
  #closed = false;
  #lastDiagnosticAt = 0;

  constructor(process: RunningProcess) {
    this.#process = process;
    process.stdout.onData((chunk) => this.#read(chunk));
    void process.exited.then(() => this.#fail(new Error('The language server exited.')));
  }

  get closed(): boolean {
    return this.#closed;
  }

  #fail(error: Error): void {
    this.#closed = true;
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.#pending.clear();
  }

  #read(chunk: Buffer): void {
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    for (;;) {
      const headerEnd = this.#buffer.indexOf('\r\n\r\n');
      if (headerEnd < 0) {
        if (this.#buffer.length > 8_192) this.#buffer = Buffer.alloc(0);
        return;
      }
      const length = Number(/content-length:\s*(\d+)/i.exec(this.#buffer.subarray(0, headerEnd).toString('ascii'))?.[1] ?? NaN);
      if (!Number.isFinite(length) || length > MAX_MESSAGE_BYTES) {
        // A broken or hostile stream: stop listening rather than buffer without end.
        this.close();
        return;
      }
      if (this.#buffer.length < headerEnd + 4 + length) return;
      const body = this.#buffer.subarray(headerEnd + 4, headerEnd + 4 + length).toString('utf8');
      this.#buffer = this.#buffer.subarray(headerEnd + 4 + length);
      let message: { id?: unknown; method?: unknown; params?: unknown; result?: unknown; error?: { message?: unknown } };
      try {
        message = JSON.parse(body) as typeof message;
      } catch {
        continue;
      }
      this.#handle(message);
    }
  }

  #handle(message: { id?: unknown; method?: unknown; params?: unknown; result?: unknown; error?: { message?: unknown } }): void {
    if (typeof message.method === 'string') {
      if (message.method === 'textDocument/publishDiagnostics') {
        const params = message.params as { uri?: unknown; diagnostics?: unknown } | undefined;
        if (typeof params?.uri === 'string' && Array.isArray(params.diagnostics)) {
          this.#diagnostics.set(params.uri, (params.diagnostics as LspDiagnostic[]).slice(0, 200));
          this.#lastDiagnosticAt = Date.now();
          for (const wake of this.#diagnosticWaiters.splice(0)) wake();
        }
      } else if (message.id !== undefined) {
        // A request from the server (workspace/configuration, window/workDoneProgress/create): answer null, grant nothing.
        this.#send({ jsonrpc: '2.0', id: message.id, result: null });
      }
      return;
    }
    if (typeof message.id !== 'number') return;
    const pending = this.#pending.get(message.id);
    if (pending === undefined) return;
    this.#pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.error !== undefined) pending.reject(new Error(String(message.error.message ?? 'The language server refused.')));
    else pending.resolve(message.result);
  }

  #send(message: unknown): void {
    if (this.#closed) return;
    const body = Buffer.from(JSON.stringify(message), 'utf8');
    this.#process.write(`Content-Length: ${body.length}\r\n\r\n${body.toString('utf8')}`);
  }

  request(method: string, params: unknown, timeoutMs = REQUEST_TIMEOUT_MS): Promise<unknown> {
    if (this.#closed) return Promise.reject(new Error('The language server is not running.'));
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`The language server did not answer ${method} in time.`));
      }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#send({ jsonrpc: '2.0', id, method, params });
    });
  }

  notify(method: string, params: unknown): void {
    this.#send({ jsonrpc: '2.0', method, params });
  }

  async initialize(root: string): Promise<void> {
    await this.request('initialize', {
      processId: null,
      rootUri: fileUri(root),
      workspaceFolders: [{ uri: fileUri(root), name: 'project' }],
      capabilities: {
        textDocument: {
          synchronization: { didSave: false, dynamicRegistration: false },
          publishDiagnostics: { relatedInformation: false },
          hover: { contentFormat: ['plaintext', 'markdown'] },
          definition: {},
          references: {},
          implementation: {},
          documentSymbol: { hierarchicalDocumentSymbolSupport: true },
        },
        workspace: { configuration: false, workspaceFolders: true },
      },
    }, 60_000);
    this.notify('initialized', {});
  }

  diagnostics(uri: string): readonly LspDiagnostic[] {
    return this.#diagnostics.get(uri) ?? [];
  }

  /** Waits until the server has been quiet for `quietMs` after a diagnostics message, or `maxMs` passes. */
  async settle(quietMs: number, maxMs: number): Promise<void> {
    const started = Date.now();
    const sinceLast = (): number => Date.now() - Math.max(this.#lastDiagnosticAt, started);
    while (Date.now() - started < maxMs) {
      if (this.#lastDiagnosticAt >= started && sinceLast() >= quietMs) return;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, Math.min(quietMs, Math.max(1, maxMs - (Date.now() - started))));
        this.#diagnosticWaiters.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#process.signal('kill');
    this.#fail(new Error('The language server was stopped.'));
  }
}
