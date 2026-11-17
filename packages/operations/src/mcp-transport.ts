import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { HnError } from '@hn/core';

/**
 * The stdio transport for an MCP server. The server is somebody else's code, so it starts in a small box of its
 * own: an absolute path (never found through a PATH or the project), an environment that holds only what the
 * operator listed, a HOME that is an empty scratch folder, and a working directory that is the same folder. It
 * never sees the project, the real home, or a key. Requests the server makes of US that would hand it more
 * (sampling, elicitation, roots) are always refused, and were never advertised.
 */

export class McpError extends HnError {}

export interface McpProcessSpec {
  /** Must be an absolute path. A bare name could be satisfied by a program committed to the project. */
  readonly command: string;
  readonly args?: readonly string[];
  /** The only environment variables the server gets, with their values. Nothing is inherited. */
  readonly env?: Readonly<Record<string, string>>;
}

export interface JsonRpcMessage {
  readonly jsonrpc?: string;
  readonly id?: number | string | null;
  readonly method?: string;
  readonly params?: unknown;
  readonly result?: unknown;
  readonly error?: { readonly code: number; readonly message: string; readonly data?: unknown };
}

/** What a server asked of us that we refused, kept so the refusal is visible and testable. */
export interface RefusedRequest {
  readonly method: string;
  readonly id: JsonRpcMessage['id'];
}

const MAX_LINE_BYTES = 4 * 1024 * 1024;
const MAX_STDERR = 4_096;
/** Requests a server may make that grant nothing. Everything else it asks for is refused. */
const HARMLESS = new Set(['ping']);

/** The environment a server gets. Exported so a test can see exactly what is handed over. */
export function serverEnvironment(spec: McpProcessSpec, scratch: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...spec.env, HOME: scratch, USERPROFILE: scratch, TMPDIR: scratch, TMP: scratch, TEMP: scratch };
  if (process.platform === 'win32') {
    // Windows adds the user's profile variables to any child that does not set them itself, which would tell the
    // server the real home folder and account name. A variable that is set is left alone, so every one is set here.
    const root = process.env['SystemRoot'] ?? 'C:/Windows';
    const defaults: Record<string, string> = {
      SystemRoot: root,
      windir: root,
      HOMEDRIVE: scratch.slice(0, 2),
      HOMEPATH: scratch.slice(2),
      USERNAME: 'hn-mcp',
      USERDOMAIN: 'HN',
      LOGONSERVER: '//HN',
      PATH: `${root}/System32`,
    };
    for (const [name, value] of Object.entries(defaults)) env[name] ??= value;
  }
  return env;
}

export class McpConnection {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #scratch: string;
  readonly #pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();
  readonly refused: RefusedRequest[] = [];
  readonly notifications: JsonRpcMessage[] = [];
  #next = 1;
  #buffer = '';
  #closed: string | null = null;
  #stderr = '';

  private constructor(child: ChildProcessWithoutNullStreams, scratch: string) {
    this.#child = child;
    this.#scratch = scratch;
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => this.#onData(chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => {
      this.#stderr = (this.#stderr + chunk).slice(-MAX_STDERR);
    });
    child.on('error', (error) => this.#fail(`The server could not start: ${error.message}`));
    child.on('close', (code) => this.#fail(`The server exited${code === null ? '' : ` with code ${code}`}.`));
    child.stdin.on('error', () => undefined);
  }

  static async start(spec: McpProcessSpec): Promise<McpConnection> {
    if (!isAbsolute(spec.command)) throw new McpError('MCP_COMMAND_NOT_ABSOLUTE', `The server command must be an absolute path, not "${spec.command}". A bare name could run a program committed to the project.`);
    const scratch = await mkdtemp(join(tmpdir(), 'hn-mcp-'));
    const child = spawn(spec.command, [...(spec.args ?? [])], { cwd: scratch, env: serverEnvironment(spec, scratch), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    return new McpConnection(child, scratch);
  }

  /** What the server wrote to stderr, for diagnostics. Redact it before it is shown. */
  get stderr(): string {
    return this.#stderr;
  }

  get scratch(): string {
    return this.#scratch;
  }

  #fail(reason: string): void {
    if (this.#closed !== null) return;
    this.#closed = reason;
    for (const [id, entry] of this.#pending) {
      clearTimeout(entry.timer);
      entry.reject(new McpError('MCP_CLOSED', reason));
      this.#pending.delete(id);
    }
    void rm(this.#scratch, { recursive: true, force: true }).catch(() => undefined);
  }

  #send(message: JsonRpcMessage): void {
    if (this.#closed !== null) return;
    this.#child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...message })}\n`);
  }

  #onData(chunk: string): void {
    this.#buffer += chunk;
    if (this.#buffer.length > MAX_LINE_BYTES && !this.#buffer.includes('\n')) {
      this.close();
      return this.#fail('The server wrote a line longer than the limit, so it was stopped.');
    }
    for (let at = this.#buffer.indexOf('\n'); at !== -1; at = this.#buffer.indexOf('\n')) {
      const line = this.#buffer.slice(0, at).trim();
      this.#buffer = this.#buffer.slice(at + 1);
      if (line === '') continue;
      let message: JsonRpcMessage;
      try {
        message = JSON.parse(line) as JsonRpcMessage;
      } catch {
        continue;
      }
      this.#onMessage(message);
    }
  }

  #onMessage(message: JsonRpcMessage): void {
    if (message.method !== undefined) {
      if (message.id === undefined || message.id === null) {
        this.notifications.push(message);
        return;
      }
      // A request from the server to us. Nothing is granted: only `ping` is answered, and everything else is refused.
      if (HARMLESS.has(message.method)) return this.#send({ id: message.id, result: {} });
      this.refused.push({ method: message.method, id: message.id });
      return this.#send({ id: message.id, error: { code: -32601, message: `hn does not allow ${message.method}. It grants a server nothing it was not given.` } });
    }
    if (typeof message.id !== 'number') return;
    const entry = this.#pending.get(message.id);
    if (entry === undefined) return;
    this.#pending.delete(message.id);
    clearTimeout(entry.timer);
    if (message.error !== undefined) entry.reject(new McpError('MCP_SERVER_ERROR', `${message.error.message} (code ${message.error.code})`));
    else entry.resolve(message.result);
  }

  request(method: string, params: unknown, timeoutMs = 30_000): Promise<unknown> {
    if (this.#closed !== null) return Promise.reject(new McpError('MCP_CLOSED', this.#closed));
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new McpError('MCP_TIMEOUT', `${method} did not answer within ${timeoutMs} ms.`));
      }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#send({ id, method, params });
    });
  }

  notify(method: string, params?: unknown): void {
    this.#send({ method, ...(params === undefined ? {} : { params }) });
  }

  get closed(): string | null {
    return this.#closed;
  }

  close(): void {
    this.#child.kill();
    this.#fail('The connection was closed.');
  }
}
