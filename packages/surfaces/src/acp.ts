import { isAbsolute } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { sanitizeForDisplay } from '@hn/core';
import type { KeyStore } from '@hn/provider';
import type { ApprovalAnswer, ApprovalCard } from '@hn/security';
import { Harness, type HarnessOptions } from './harness.ts';
import { JsonRpcPeer, RPC_INVALID_PARAMS, RPC_METHOD_NOT_FOUND, RPC_REFUSED, RpcError, type RpcParams } from './jsonrpc.ts';

/**
 * The Agent Client Protocol door (`hn acp`): ACP v1, JSON-RPC over stdio, for editors. The editor that
 * started the process is the person at this door, so its prompts are `user`. Every approval card becomes a
 * `session/request_permission` offering only "allow once" and "reject once": a remembered "always" would outlive what
 * the person saw. MCP servers an editor sends are not connected (MCP comes from the user's own file), and the session
 * says so. Everything the model wrote is sanitized before it reaches the editor.
 */

export const ACP_PROTOCOL_VERSION = 1;
export const MAX_ACP_SESSIONS = 8;
const PERMISSION_TIMEOUT_MS = 10 * 60_000;

export interface AcpServerOptions {
  readonly keys: KeyStore;
  readonly defaults: Pick<HarnessOptions, 'model' | 'baseUrl' | 'window' | 'numCtx'>;
  readonly env?: NodeJS.ProcessEnv;
  /** Tests only: passed to every session. */
  readonly sessionExtras?: Partial<HarnessOptions>;
}

const STOP_REASONS: Readonly<Record<string, string>> = { done: 'end_turn', cancelled: 'cancelled', refusal: 'refusal', window_full: 'max_tokens', budget: 'max_turn_requests', guardrail: 'max_turn_requests' };

/** The kind ACP shows for a tool, from its effect. */
const kindOf = (card: ApprovalCard): string =>
  card.effect === 'observe' ? 'read' : card.effect === 'reversible' ? 'edit' : card.effect === 'external' ? 'fetch' : card.effect === 'execution' ? 'execute' : 'other';

/** The text an ACP prompt carries. Only text blocks are taken; a resource link is named, never fetched. */
function promptText(prompt: unknown): string {
  if (!Array.isArray(prompt)) throw new RpcError(RPC_INVALID_PARAMS, 'prompt must be a list of content blocks.');
  const parts: string[] = [];
  for (const block of prompt) {
    const value = (typeof block === 'object' && block !== null ? block : {}) as Record<string, unknown>;
    if (value['type'] === 'text' && typeof value['text'] === 'string') parts.push(value['text']);
    else if (value['type'] === 'resource_link' && typeof value['uri'] === 'string') parts.push(`(The user pointed at ${value['uri']}.)`);
    else throw new RpcError(RPC_INVALID_PARAMS, `Content of type ${sanitizeForDisplay(String(value['type'])).slice(0, 40)} is not accepted; this agent takes text.`);
  }
  const text = parts.join('\n').trim();
  if (text === '') throw new RpcError(RPC_INVALID_PARAMS, 'The prompt is empty.');
  return text;
}

export async function serveAcp(input: Readable, output: Writable, options: AcpServerOptions): Promise<void> {
  const sessions = new Map<string, { harness: Harness; tools: number }>();
  let peer: JsonRpcPeer;

  const update = (sessionId: string, value: Record<string, unknown>): void => peer.notify('session/update', { sessionId, update: value });

  const find = (params: RpcParams): { harness: Harness; tools: number; id: string } => {
    const id = params['sessionId'];
    const entry = typeof id === 'string' ? sessions.get(id) : undefined;
    if (entry === undefined || typeof id !== 'string') throw new RpcError(RPC_INVALID_PARAMS, 'There is no such session.');
    return { ...entry, id };
  };

  const open = async (params: RpcParams, resume?: string): Promise<{ sessionId: string; notes: string[] }> => {
    if (sessions.size >= MAX_ACP_SESSIONS) throw new RpcError(RPC_REFUSED, `${MAX_ACP_SESSIONS} sessions are already open.`);
    const cwd = params['cwd'];
    if (typeof cwd !== 'string' || !isAbsolute(cwd)) throw new RpcError(RPC_INVALID_PARAMS, 'cwd must be an absolute path.');
    const notes: string[] = [];
    if (Array.isArray(params['mcpServers']) && params['mcpServers'].length > 0) notes.push(`The editor offered ${params['mcpServers'].length} MCP server(s); they were not connected. hn uses only the MCP servers in your own ~/.hn/mcp.json.`);
    let sessionId = '';
    let toolCalls = 0;
    const harness = new Harness({
      ...options.defaults,
      ...options.sessionExtras,
      workdir: cwd,
      mode: 'safe',
      keys: options.keys,
      ...(options.env === undefined ? {} : { env: options.env }),
      ...(resume === undefined ? {} : { sessionId: resume }),
      approver: async (card: ApprovalCard): Promise<ApprovalAnswer> => {
        const answer = (await peer
          .request(
            'session/request_permission',
            {
              sessionId,
              toolCall: { toolCallId: card.approvalId, title: sanitizeForDisplay(card.summary).slice(0, 2_000), kind: kindOf(card), status: 'pending', ...(card.target === undefined ? {} : { locations: [], rawInput: { target: sanitizeForDisplay(card.target) } }) },
              options: [
                { optionId: 'allow-once', name: 'Allow once', kind: 'allow_once' },
                { optionId: 'reject-once', name: 'Reject', kind: 'reject_once' },
              ],
            },
            PERMISSION_TIMEOUT_MS,
          )
          .catch(() => null)) as { outcome?: { outcome?: unknown; optionId?: unknown } } | null;
        // Only the one allow option counts. Cancelled, unknown, malformed or late is a no.
        return answer?.outcome?.outcome === 'selected' && answer.outcome.optionId === 'allow-once' ? 'once' : 'deny';
      },
      onEvent: (event) => {
        if (event.type === 'text') update(sessionId, { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: sanitizeForDisplay(event.text) } });
        else if (event.type === 'thinking') update(sessionId, { sessionUpdate: 'agent_thought_chunk', content: { type: 'text', text: sanitizeForDisplay(event.text) } });
        else if (event.type === 'tool_input') {
          toolCalls += 1;
          const entry = sessions.get(sessionId);
          if (entry !== undefined) entry.tools = toolCalls;
          update(sessionId, { sessionUpdate: 'tool_call', toolCallId: `${sessionId}-${toolCalls}`, title: sanitizeForDisplay(event.name), kind: 'other', status: 'in_progress' });
        }
      },
    });
    const session = await harness.open();
    sessionId = session.sessionId;
    sessions.set(sessionId, { harness, tools: 0 });
    return { sessionId, notes: [...notes, ...session.notes.map((note) => sanitizeForDisplay(options.keys.redact(note)))] };
  };

  const handle = async (method: string, params: RpcParams): Promise<unknown> => {
    switch (method) {
      case 'initialize':
        return {
          protocolVersion: ACP_PROTOCOL_VERSION,
          agentCapabilities: { loadSession: true, promptCapabilities: { image: false, audio: false, embeddedContext: false }, mcpCapabilities: { http: false, sse: false } },
          authMethods: [],
        };
      case 'authenticate':
        return {};
      case 'session/new': {
        const { sessionId, notes } = await open(params);
        for (const note of notes) update(sessionId, { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: `[hn] ${note}\n` } });
        return { sessionId };
      }
      case 'session/load': {
        const id = params['sessionId'];
        if (typeof id !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(id)) throw new RpcError(RPC_INVALID_PARAMS, 'sessionId is not a session id.');
        if (sessions.has(id)) throw new RpcError(RPC_REFUSED, 'That session is already open.');
        await open(params, id);
        return null;
      }
      case 'session/prompt': {
        const session = find(params);
        if (session.harness.session?.agent.busy === true) throw new RpcError(RPC_REFUSED, 'This session is in a turn.');
        const before = session.tools;
        const result = await session.harness.run(promptText(params['prompt']), { origin: 'user' });
        const after = sessions.get(session.id)?.tools ?? before;
        for (let n = before + 1; n <= after; n += 1) update(session.id, { sessionUpdate: 'tool_call_update', toolCallId: `${session.id}-${n}`, status: 'completed' });
        return { stopReason: STOP_REASONS[result.end] ?? 'end_turn' };
      }
      case 'session/set_mode':
        throw new RpcError(RPC_REFUSED, 'The mode is chosen when hn starts, never by the client mid-session.');
      default:
        throw new RpcError(RPC_METHOD_NOT_FOUND, `There is no method ${sanitizeForDisplay(method).slice(0, 80)}.`);
    }
  };

  peer = new JsonRpcPeer(input, output, {
    request: async (method, params) => {
      try {
        return await handle(method, params);
      } catch (error) {
        if (error instanceof RpcError) throw error;
        throw new RpcError(RPC_REFUSED, sanitizeForDisplay(options.keys.redact(error instanceof Error ? error.message : String(error))));
      }
    },
    notification: (method, params) => {
      if (method !== 'session/cancel') return;
      const id = params['sessionId'];
      const entry = typeof id === 'string' ? sessions.get(id) : undefined;
      entry?.harness.stop();
    },
  });
  await peer.closed;
  await Promise.all([...sessions.values()].map((entry) => entry.harness.close().catch(() => null)));
}
