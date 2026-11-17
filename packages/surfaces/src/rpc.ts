import { isAbsolute } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { sanitizeForDisplay } from '@hn/core';
import { KeyStore } from '@hn/provider';
import { MODES, type ApprovalAnswer, type ApprovalCard } from '@hn/security';
import { Harness, type HarnessOptions } from './harness.ts';
import { JsonRpcPeer, RPC_INVALID_PARAMS, RPC_METHOD_NOT_FOUND, RPC_REFUSED, RpcError, type RpcParams } from './jsonrpc.ts';

export const RPC_PROTOCOL = 1;
export const MAX_RPC_SESSIONS = 8;
/** How long a client has to answer an approval card. No answer is no. */
export const RPC_APPROVAL_TIMEOUT_MS = 10 * 60_000;
const SESSION_ID = /^[A-Za-z0-9-]{1,64}$/;
const METHODS = ['initialize', 'session/open', 'session/prompt', 'session/steer', 'session/stop', 'session/state', 'session/fork', 'session/close', 'shutdown'] as const;

export interface RpcServerOptions {
  /** The keys this process holds. A client may hand over its own in `initialize`, never through the environment. */
  readonly keys: KeyStore;
  /** Where a session opens when the client names no folder. */
  readonly cwd: string;
  /** Model settings a session uses unless `session/open` names its own. */
  readonly defaults: Pick<HarnessOptions, 'model' | 'baseUrl' | 'window' | 'numCtx'>;
  readonly env?: NodeJS.ProcessEnv;
  /** Tests only: passed to every session. */
  readonly sessionExtras?: Partial<HarnessOptions>;
}

const text = (params: RpcParams, name: string, required = true): string | undefined => {
  const value = params[name];
  if (value === undefined && !required) return undefined;
  if (typeof value !== 'string' || value === '') throw new RpcError(RPC_INVALID_PARAMS, `${name} must be a non-empty string.`);
  return value;
};

/** A card as the client sees it: the model's words sanitized, because this door is attacker-reachable. */
const cardForClient = (card: ApprovalCard): Record<string, unknown> => ({
  approvalId: card.approvalId,
  tool: sanitizeForDisplay(card.tool),
  effect: card.effect,
  summary: sanitizeForDisplay(card.summary),
  ...(card.target === undefined ? {} : { target: sanitizeForDisplay(card.target) }),
  canRememberForSession: card.canRememberForSession,
});

/**
 * The JSON-RPC door (`hn rpc`): JSON-RPC 2.0, one object per line over stdio. The client that started the
 * process owns it, so its prompts are `user`; the supervisor marks what it forwards `ipc`. Approval cards go to the
 * client only when it said it can answer them; otherwise nobody is there and the gate refuses what needs a person.
 */
export async function serveRpc(input: Readable, output: Writable, options: RpcServerOptions): Promise<void> {
  const sessions = new Map<string, Harness>();
  let keys = options.keys;
  let approvals = false;
  let peer: JsonRpcPeer;
  const redact = (value: string): string => sanitizeForDisplay(keys.redact(value));

  const find = (params: RpcParams): Harness => {
    const id = text(params, 'sessionId') as string;
    const harness = sessions.get(id);
    if (harness === undefined) throw new RpcError(RPC_INVALID_PARAMS, `There is no open session ${id}.`);
    return harness;
  };

  const open = async (params: RpcParams): Promise<Record<string, unknown>> => {
    if (sessions.size >= MAX_RPC_SESSIONS) throw new RpcError(RPC_REFUSED, `${MAX_RPC_SESSIONS} sessions are already open in this process. Close one first.`);
    const workdir = text(params, 'workdir', false) ?? options.cwd;
    if (!isAbsolute(workdir)) throw new RpcError(RPC_INVALID_PARAMS, 'workdir must be an absolute path.');
    const mode = text(params, 'mode', false) ?? (approvals ? 'safe' : 'read-only');
    if (!(MODES as readonly string[]).includes(mode)) throw new RpcError(RPC_INVALID_PARAMS, `mode must be one of: ${MODES.join(', ')}.`);
    const resume = text(params, 'sessionId', false);
    if (resume !== undefined && !SESSION_ID.test(resume)) throw new RpcError(RPC_INVALID_PARAMS, 'sessionId is not a session id.');
    if (resume !== undefined && sessions.has(resume)) throw new RpcError(RPC_REFUSED, `Session ${resume} is already open here.`);
    const allow = params['allow'];
    if (allow !== undefined && !(Array.isArray(allow) && allow.every((name) => typeof name === 'string'))) throw new RpcError(RPC_INVALID_PARAMS, 'allow must be a list of tool names.');
    const window = params['window'];
    if (window !== undefined && !(typeof window === 'number' && Number.isSafeInteger(window) && window > 0)) throw new RpcError(RPC_INVALID_PARAMS, 'window must be a positive integer.');
    let sessionId = '';
    const harness = new Harness({
      ...options.defaults,
      ...options.sessionExtras,
      workdir,
      mode,
      keys,
      ...(options.env === undefined ? {} : { env: options.env }),
      ...(text(params, 'model', false) === undefined ? {} : { model: text(params, 'model') as string }),
      ...(text(params, 'baseUrl', false) === undefined ? {} : { baseUrl: text(params, 'baseUrl') as string }),
      ...(window === undefined ? {} : { window }),
      ...(resume === undefined ? {} : { sessionId: resume }),
      ...(allow === undefined ? {} : { allow: allow as string[] }),
      ...(text(params, 'verify', false) === undefined ? {} : { verify: text(params, 'verify') as string }),
      ...(params['persist'] === false ? { persist: false } : {}),
      ...(params['control'] === true ? { control: true } : {}),
      ...(approvals
        ? {
            approver: async (card: ApprovalCard): Promise<ApprovalAnswer> => {
              const answer = await peer.request('approval/request', { sessionId, card: cardForClient(card) }, RPC_APPROVAL_TIMEOUT_MS).catch(() => null);
              const decision = typeof answer === 'object' && answer !== null ? (answer as Record<string, unknown>)['decision'] : null;
              return decision === 'once' || decision === 'session' ? decision : 'deny';
            },
          }
        : {}),
      onEvent: (event) => {
        if (event.type === 'text') peer.notify('session/event', { sessionId, event: { type: 'text', text: sanitizeForDisplay(event.text) } });
        else if (event.type === 'tool_input') peer.notify('session/event', { sessionId, event: { type: 'tool', name: sanitizeForDisplay(event.name) } });
      },
    });
    const session = await harness.open();
    sessionId = session.sessionId;
    sessions.set(sessionId, harness);
    return { sessionId, mode: session.gate.mode, tier: session.tier, notes: session.notes.map(redact) };
  };

  const handle = async (method: string, params: RpcParams): Promise<unknown> => {
    switch (method) {
      case 'initialize': {
        const capabilities = params['capabilities'];
        approvals = typeof capabilities === 'object' && capabilities !== null && (capabilities as Record<string, unknown>)['approvals'] === true;
        // A client hands over its keys here, never through this process's environment.
        if (params['keys'] !== undefined) keys = KeyStore.fromHandoff(JSON.stringify(params['keys']));
        return { server: 'hn', protocol: RPC_PROTOCOL, methods: METHODS, approvals };
      }
      case 'session/open':
        return open(params);
      case 'session/prompt': {
        const harness = find(params);
        if (harness.session?.agent.busy === true) throw new RpcError(RPC_REFUSED, 'This session is in a turn. Steer it, stop it, or wait.');
        const origin = params['origin'] === undefined ? 'user' : params['origin'];
        if (origin !== 'user' && origin !== 'ipc') throw new RpcError(RPC_INVALID_PARAMS, 'origin must be user or ipc.');
        const { sessionId, text: answer, detail, ...result } = await harness.run(text(params, 'text') as string, { origin });
        return { sessionId, ...result, text: sanitizeForDisplay(answer), ...(detail === undefined ? {} : { detail: redact(detail) }) };
      }
      case 'session/steer':
        find(params).steer(text(params, 'text') as string);
        return {};
      case 'session/stop':
        find(params).stop();
        return {};
      case 'session/state':
        return find(params).state();
      case 'session/fork':
        return { sessionId: await find(params).fork() };
      case 'session/close': {
        const harness = find(params);
        sessions.delete(harness.sessionId as string);
        const handback = await harness.close();
        return handback === null ? {} : { handback: { applied: handback.result.applied, held: handback.result.blocked.map((entry) => entry.path) } };
      }
      case 'shutdown':
        await closeAll();
        setImmediate(() => peer.close());
        return {};
      default:
        throw new RpcError(RPC_METHOD_NOT_FOUND, `There is no method ${sanitizeForDisplay(method).slice(0, 80)}.`);
    }
  };

  const closeAll = async (): Promise<void> => {
    const all = [...sessions.values()];
    sessions.clear();
    await Promise.all(all.map((harness) => harness.close().catch(() => null)));
  };

  peer = new JsonRpcPeer(input, output, {
    request: async (method, params) => {
      try {
        return await handle(method, params);
      } catch (error) {
        if (error instanceof RpcError) throw error;
        throw new RpcError(RPC_REFUSED, redact(error instanceof Error ? error.message : String(error)));
      }
    },
  });
  await peer.closed;
  await closeAll();
}
