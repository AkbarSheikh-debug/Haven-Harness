import type { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { startHnProcess, type HnProcess } from '@hn/operations';
import { JsonRpcPeer, RpcError, RPC_INVALID_PARAMS, type RpcParams } from './jsonrpc.ts';

export type RpcDecision = 'once' | 'session' | 'deny';

export interface RpcCard {
  readonly approvalId: string;
  readonly tool: string;
  readonly effect: string;
  readonly summary: string;
  readonly target?: string;
}

export interface RpcClientOptions {
  /** Answers approval cards. Without it the server is told nobody can, and the gate refuses what needs a person. */
  readonly approve?: (card: RpcCard, sessionId: string) => Promise<RpcDecision>;
  /** Streamed text and tool names, already sanitized by the server. */
  readonly onEvent?: (sessionId: string, event: { readonly type: string; readonly text?: string; readonly name?: string }) => void;
}

export interface RpcTurn {
  readonly sessionId: string;
  readonly end: string;
  readonly text: string;
  readonly steps: number;
  readonly usage: Readonly<Record<string, number>>;
  readonly detail?: string;
}

/** The SDK client for the JSON-RPC door: talks to `hn rpc` over any pair of streams. */
export class RpcClient {
  readonly #peer: JsonRpcPeer;
  readonly #options: RpcClientOptions;

  constructor(fromServer: Readable, toServer: Writable, options: RpcClientOptions = {}) {
    this.#options = options;
    this.#peer = new JsonRpcPeer(fromServer, toServer, {
      request: async (method, params) => {
        if (method !== 'approval/request' || options.approve === undefined) throw new RpcError(RPC_INVALID_PARAMS, 'This client does not answer that.');
        const card = params['card'] as RpcCard;
        return { decision: await options.approve(card, String(params['sessionId'])) };
      },
      notification: (method, params) => {
        if (method === 'session/event') options.onEvent?.(String(params['sessionId']), params['event'] as { type: string });
      },
    });
  }

  get closed(): Promise<void> {
    return this.#peer.closed;
  }

  request(method: string, params: RpcParams = {}, timeoutMs?: number): Promise<unknown> {
    return this.#peer.request(method, params, timeoutMs);
  }

  /** `keys` are handed to the server here, never through its environment. */
  initialize(keys?: Readonly<Record<string, string>>): Promise<unknown> {
    return this.request('initialize', { client: { name: 'hn-sdk' }, capabilities: { approvals: this.#options.approve !== undefined }, ...(keys === undefined ? {} : { keys }) });
  }

  async openSession(params: RpcParams = {}): Promise<{ readonly sessionId: string; readonly mode: string; readonly tier: number; readonly notes: readonly string[] }> {
    return (await this.request('session/open', params)) as { sessionId: string; mode: string; tier: number; notes: string[] };
  }

  async prompt(sessionId: string, text: string, origin?: 'user' | 'ipc'): Promise<RpcTurn> {
    return (await this.request('session/prompt', { sessionId, text, ...(origin === undefined ? {} : { origin }) })) as RpcTurn;
  }

  async steer(sessionId: string, text: string): Promise<void> {
    await this.request('session/steer', { sessionId, text });
  }

  async stop(sessionId: string): Promise<void> {
    await this.request('session/stop', { sessionId });
  }

  async state(sessionId: string): Promise<Readonly<Record<string, unknown>>> {
    return (await this.request('session/state', { sessionId })) as Record<string, unknown>;
  }

  async fork(sessionId: string): Promise<string> {
    return ((await this.request('session/fork', { sessionId })) as { sessionId: string }).sessionId;
  }

  async closeSession(sessionId: string): Promise<void> {
    await this.request('session/close', { sessionId });
  }

  async shutdown(): Promise<void> {
    await this.request('shutdown').catch(() => undefined);
    this.#peer.close();
  }
}

/** The `hn` entry point, for doors that start another hn (the RPC client, the supervisor). */
export const HN_ENTRY = fileURLToPath(new URL('./main.ts', import.meta.url));

export interface StartedRpc {
  readonly client: RpcClient;
  readonly process: HnProcess;
}

/** Starts `hn rpc` in `cwd` and connects a client to it. The environment must hold no model key; pass keys to `initialize`. */
export function startRpcClient(options: { readonly cwd: string; readonly env: NodeJS.ProcessEnv; readonly args?: readonly string[] } & RpcClientOptions): StartedRpc {
  const child = startHnProcess({ entry: HN_ENTRY, args: ['rpc', ...(options.args ?? [])], cwd: options.cwd, env: options.env });
  return { client: new RpcClient(child.stdout, child.stdin, options), process: child };
}
