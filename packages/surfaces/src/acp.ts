import { isAbsolute } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { revealHidden, sanitizeForDisplay } from '@hn/core';
import type { KeyStore } from '@hn/provider';
import type { ApprovalAnswer, ApprovalCard } from '@hn/security';
import { Harness, type HarnessOptions } from './harness.ts';
import { JsonRpcPeer, RPC_INVALID_PARAMS, RPC_METHOD_NOT_FOUND, RPC_REFUSED, RpcError, type RpcParams } from './jsonrpc.ts';

/**
 * The Agent Client Protocol door (`hn acp`, decision 11): ACP v1, JSON-RPC over stdio, for editors. The editor that
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

/** The kind ACP shows for a tool: from its name where it is one hn knows, else from its effect. */
const TOOL_KINDS: Readonly<Record<string, string>> = { read_file: 'read', write_file: 'edit', edit_file: 'edit', bash: 'execute', web_fetch: 'fetch', web_search: 'search', grep: 'search', list_files: 'search' };
const kindOfTool = (name: string): string => TOOL_KINDS[name] ?? 'other';
const kindOf = (card: ApprovalCard): string =>
  TOOL_KINDS[card.tool] ??
  (card.effect === 'observe' ? 'read' : card.effect === 'reversible' ? 'edit' : card.effect === 'external' ? 'fetch' : card.effect === 'execution' ? 'execute' : 'other');

/**
 * The tool call an approval request describes. An edit carries its change as a diff, so the editor shows what will be
 * written and not only a summary. Nothing is hidden from the person: a control, bidi or zero-width character is shown as
 * an escape, never stripped, so the diff cannot read differently from what is written. Where only part of the change is
 * shown (a big file, or a cut side), the title says so.
 */
export function permissionToolCall(card: ApprovalCard): Record<string, unknown> {
  const change = card.change;
  const notes = change === undefined ? '' : `${change.partial ? ' (changed part only)' : ''}${change.truncated ? ' (cut: not all of it is shown)' : ''}`;
  return {
    toolCallId: card.approvalId,
    title: `${sanitizeForDisplay(card.summary).slice(0, 2_000)}${notes}`,
    kind: kindOf(card),
    status: 'pending',
    ...(change === undefined
      ? card.target === undefined
        ? {}
        : { locations: [], rawInput: { target: sanitizeForDisplay(card.target) } }
      : {
          locations: [{ path: revealHidden(change.path) }],
          content: [{ type: 'diff', path: revealHidden(change.path), oldText: change.oldText === null ? null : revealHidden(change.oldText), newText: revealHidden(change.newText) }],
          rawInput: { path: revealHidden(change.path), ...(card.target === undefined ? {} : { target: sanitizeForDisplay(card.target) }) },
        }),
  };
}

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

/** For each tool call in a run of log rows, in order: did it produce a result without an error. */
export function toolOutcomes(events: readonly { type: string; data: Record<string, unknown> }[]): ('completed' | 'failed')[] {
  const failed = new Map<string, boolean>();
  for (const event of events) if (event.type === 'tool/result') failed.set(String(event.data['callId']), event.data['isError'] === true);
  return events.filter((event) => event.type === 'tool/call').map((event) => (failed.get(String(event.data['callId'])) === false ? 'completed' : 'failed'));
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

  const open = async (params: RpcParams, resume?: string): Promise<{ sessionId: string; notes: string[]; meta: Record<string, unknown> }> => {
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
              toolCall: permissionToolCall(card),
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
          update(sessionId, { sessionUpdate: 'tool_call', toolCallId: `${sessionId}-${toolCalls}`, title: sanitizeForDisplay(event.name), kind: kindOfTool(event.name), status: 'in_progress' });
        }
      },
    });
    const session = await harness.open();
    sessionId = session.sessionId;
    sessions.set(sessionId, { harness, tools: 0 });
    // Where this session runs, for the editor to show. tier 2 is the permission gate alone; 3 is a verified box.
    return { sessionId, notes: [...notes, ...session.notes.map((note) => sanitizeForDisplay(options.keys.redact(note)))], meta: { tier: session.tier, mode: 'safe', sandbox: session.sandbox !== null } };
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
        const { sessionId, notes, meta } = await open(params);
        for (const note of notes) update(sessionId, { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: `[hn] ${note}\n` } });
        return { sessionId, _meta: { hn: meta } };
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
        const text = promptText(params['prompt']);
        const logged = session.harness.session?.agent.events.length ?? 0;
        const result = await session.harness.run(text, { origin: 'user' });
        const after = sessions.get(session.id)?.tools ?? before;
        // A tool is `completed` only when its result says it worked. A refused, denied or failed call is `failed`.
        const outcomes = toolOutcomes(session.harness.session?.agent.events.slice(logged) ?? []);
        for (let n = before + 1; n <= after; n += 1) update(session.id, { sessionUpdate: 'tool_call_update', toolCallId: `${session.id}-${n}`, status: outcomes[n - before - 1] === 'completed' ? 'completed' : 'failed' });
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
