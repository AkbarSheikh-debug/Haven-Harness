import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { INVALID_PARAMS, METHOD_NOT_FOUND, Peer, RpcError, type Params } from './rpc.ts';
import { cap, revealHidden, sanitize } from './text.ts';

/**
 * The editor's end of the Agent Client Protocol (v1) for `hn acp`. No `vscode` import, so it is tested against a real
 * `hn acp` process without an editor. The agent is another program: nothing it sends is trusted. Text is stripped or
 * revealed (text.ts), sizes are capped, unknown methods are refused, this end offers the agent no file or terminal
 * access, and a permission request is answered with the "allow once" or the "reject" option the agent itself listed,
 * never any other.
 */

export const ACP_VERSION = 1;
export const MAX_CHUNK_CHARS = 64 * 1024;
export const MAX_TITLE_CHARS = 2_000;
export const MAX_DIFF_CHARS = 256 * 1024;
/** More text than this in one turn is dropped, so an agent cannot flood the editor. */
export const MAX_TURN_CHARS = 8 * 1024 * 1024;
const SESSION_ID = /^[A-Za-z0-9-]{1,64}$/;

export type ToolKind = 'read' | 'edit' | 'delete' | 'move' | 'search' | 'execute' | 'think' | 'fetch' | 'switch_mode' | 'other';
export type ToolStatus = 'pending' | 'in_progress' | 'completed' | 'failed';
export type StopReason = 'end_turn' | 'max_tokens' | 'max_turn_requests' | 'refusal' | 'cancelled';

const KINDS: ReadonlySet<string> = new Set(['read', 'edit', 'delete', 'move', 'search', 'execute', 'think', 'fetch', 'switch_mode', 'other']);
const STATUSES: ReadonlySet<string> = new Set(['pending', 'in_progress', 'completed', 'failed']);
const STOP_REASONS: ReadonlySet<string> = new Set(['end_turn', 'max_tokens', 'max_turn_requests', 'refusal', 'cancelled']);

export type AgentEvent =
  | { readonly type: 'message' | 'thought'; readonly sessionId: string; readonly text: string }
  | { readonly type: 'tool'; readonly sessionId: string; readonly id: string; readonly title: string; readonly kind: ToolKind; readonly status: ToolStatus }
  | { readonly type: 'tool-update'; readonly sessionId: string; readonly id: string; readonly status: ToolStatus };

/** A file change, for a person to compare. Hidden characters are escapes; `cut` says some of it is not shown. */
export interface DiffView {
  readonly path: string;
  readonly oldText: string | null;
  readonly newText: string;
  readonly cut: boolean;
}

export interface ApprovalRequest {
  readonly sessionId: string;
  readonly title: string;
  readonly kind: ToolKind;
  readonly diff?: DiffView;
}

/** What hn says about the session it opened. Anything missing or malformed is simply absent. */
export interface SessionMeta {
  readonly tier?: number;
  readonly mode?: string;
  readonly sandbox?: boolean;
}

export interface AcpHandlers {
  event(event: AgentEvent): void;
  /** Resolves `allow` only for a person's explicit yes. Anything else, and any failure, is a no. */
  approve(request: ApprovalRequest, signal: AbortSignal): Promise<'allow' | 'reject'>;
  /** The process ended or the connection broke. Called once. */
  exited(reason: string): void;
}

export interface LaunchSpec {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env?: NodeJS.ProcessEnv;
  /** Windows only: `args` are already one quoted command line for cmd.exe and must not be quoted again. */
  readonly verbatim?: boolean;
}

const record = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {});
const text = (value: unknown): string | undefined => (typeof value === 'string' ? value : undefined);

/**
 * What a permission request shows a person, and the ids of the two answers this end may give. Pure, so a hostile
 * request can be tested without a process.
 */
export function readApproval(sessionId: string, params: Params): { request: ApprovalRequest; allowId?: string; rejectId?: string } {
  const call = record(params['toolCall']);
  const options = Array.isArray(params['options']) ? params['options'].map(record) : [];
  const allow = options.find((option) => option['kind'] === 'allow_once' && typeof option['optionId'] === 'string');
  const reject = options.find((option) => option['kind'] === 'reject_once' && typeof option['optionId'] === 'string');
  const title = cap(sanitize(text(call['title']) ?? 'The agent wants to run a tool'), MAX_TITLE_CHARS).text;
  const kind = typeof call['kind'] === 'string' && KINDS.has(call['kind']) ? (call['kind'] as ToolKind) : 'other';
  const content = Array.isArray(call['content']) ? call['content'].map(record) : [];
  const found = content.find((item) => item['type'] === 'diff' && typeof item['path'] === 'string' && typeof item['newText'] === 'string' && (item['oldText'] === null || item['oldText'] === undefined || typeof item['oldText'] === 'string'));
  let diff: DiffView | undefined;
  if (found !== undefined) {
    const after = cap(revealHidden(found['newText'] as string), MAX_DIFF_CHARS);
    const before = typeof found['oldText'] === 'string' ? cap(revealHidden(found['oldText']), MAX_DIFF_CHARS) : null;
    diff = { path: cap(revealHidden(found['path'] as string), 1_000).text, oldText: before === null ? null : before.text, newText: after.text, cut: after.cut || before?.cut === true };
  }
  return {
    request: { sessionId, title, kind, ...(diff === undefined ? {} : { diff }) },
    ...(allow === undefined ? {} : { allowId: allow['optionId'] as string }),
    ...(reject === undefined ? {} : { rejectId: reject['optionId'] as string }),
  };
}

export class AcpClient {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #peer: Peer;
  readonly #handlers: AcpHandlers;
  readonly #sessions = new Set<string>();
  readonly #turns = new Map<string, AbortController>();
  readonly #stderr: string[] = [];
  readonly #exit: Promise<void>;
  #opening = 0;
  #chars = 0;
  #told = false;
  #ended = false;
  #closing = false;

  private constructor(child: ChildProcessWithoutNullStreams, handlers: AcpHandlers) {
    this.#child = child;
    this.#handlers = handlers;
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      this.#stderr.push(chunk);
      while (this.#stderr.join('').length > 4_000) this.#stderr.shift();
    });
    this.#peer = new Peer(child.stdout, child.stdin, {
      request: (method, params) => this.#request(method, params),
      notification: (method, params) => this.#notification(method, params),
    });
    this.#exit = new Promise((resolve) => {
      child.once('close', (code, signal) => {
        this.#end(`hn stopped (${signal ?? `exit code ${code ?? 'unknown'}`}).${this.#why()}`);
        resolve();
      });
    });
  }

  /** The last words hn wrote to its error stream, safe to show. */
  #why(): string {
    const last = sanitize(this.#stderr.join('')).trim();
    return last === '' ? '' : ` It said: ${last.slice(-600)}`;
  }

  #end(reason: string): void {
    if (this.#ended) return;
    this.#ended = true;
    for (const turn of this.#turns.values()) turn.abort();
    this.#turns.clear();
    this.#peer.close();
    if (!this.#closing) this.#handlers.exited(reason);
  }

  /** Starts `hn acp` and agrees the protocol version, or fails with a reason a person can act on. */
  static async start(spec: LaunchSpec, handlers: AcpHandlers): Promise<AcpClient> {
    const child = spawn(spec.command, [...spec.args], { cwd: spec.cwd, env: spec.env ?? process.env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false, windowsVerbatimArguments: spec.verbatim === true });
    const failed = new Promise<never>((_, reject) => {
      child.once('error', (error: NodeJS.ErrnoException) => reject(new Error(error.code === 'ENOENT' ? `Could not start "${sanitize(spec.command)}". Install hn, or set hn.path in your user settings to where it is.` : `Could not start hn: ${sanitize(error.message)}`)));
    });
    const client = new AcpClient(child, handlers);
    try {
      const init = (await Promise.race([client.#peer.request('initialize', { protocolVersion: ACP_VERSION, clientCapabilities: {} }, 30_000), failed])) as unknown;
      if (record(init)['protocolVersion'] !== ACP_VERSION) throw new Error('hn speaks a different version of the editor protocol than this extension.');
    } catch (error) {
      await client.close();
      throw error instanceof RpcError || error instanceof Error ? new Error(`${sanitize(error.message)}${client.#why()}`) : error;
    }
    return client;
  }

  get alive(): boolean {
    return !this.#ended;
  }

  async #request(method: string, params: Params): Promise<unknown> {
    // The agent may ask the editor for a person's yes. Files and terminals were not offered, so they are not served.
    if (method !== 'session/request_permission') throw new RpcError(METHOD_NOT_FOUND, 'This editor offers no such method.');
    const sessionId = params['sessionId'];
    if (typeof sessionId !== 'string' || !this.#sessions.has(sessionId)) throw new RpcError(INVALID_PARAMS, 'There is no such session.');
    const { request, allowId, rejectId } = readApproval(sessionId, params);
    const turn = this.#turns.get(sessionId);
    const signal = turn?.signal ?? new AbortController().signal;
    let answer: 'allow' | 'reject' = 'reject';
    try {
      answer = await this.#handlers.approve(request, signal);
    } catch {
      answer = 'reject';
    }
    if (signal.aborted) return { outcome: { outcome: 'cancelled' } };
    if (answer === 'allow' && allowId !== undefined) return { outcome: { outcome: 'selected', optionId: allowId } };
    if (rejectId !== undefined) return { outcome: { outcome: 'selected', optionId: rejectId } };
    return { outcome: { outcome: 'cancelled' } };
  }

  #emit(event: AgentEvent): void {
    try {
      this.#handlers.event(event);
    } catch {
      // A failing view never stops the connection.
    }
  }

  #notification(method: string, params: Params): void {
    if (method !== 'session/update') return;
    const sessionId = params['sessionId'];
    if (typeof sessionId !== 'string' || !SESSION_ID.test(sessionId)) return;
    // hn says things while a session opens, before it has told us the session's id.
    if (!this.#sessions.has(sessionId) && this.#opening === 0) return;
    const update = record(params['update']);
    const kind = update['sessionUpdate'];
    if (kind === 'agent_message_chunk' || kind === 'agent_thought_chunk') {
      const content = record(update['content']);
      const raw = content['type'] === 'text' ? text(content['text']) : undefined;
      if (raw === undefined) return;
      const chunk = cap(sanitize(raw), MAX_CHUNK_CHARS).text;
      this.#chars += chunk.length;
      if (this.#chars > MAX_TURN_CHARS) {
        if (!this.#told) {
          this.#told = true;
          this.#emit({ type: 'message', sessionId, text: '\n[hn: too much text in one turn; the rest is not shown.]\n' });
        }
        return;
      }
      this.#emit({ type: kind === 'agent_message_chunk' ? 'message' : 'thought', sessionId, text: chunk });
    } else if (kind === 'tool_call') {
      const id = text(update['toolCallId']);
      if (id === undefined) return;
      const status = typeof update['status'] === 'string' && STATUSES.has(update['status']) ? (update['status'] as ToolStatus) : 'in_progress';
      const toolKind = typeof update['kind'] === 'string' && KINDS.has(update['kind']) ? (update['kind'] as ToolKind) : 'other';
      this.#emit({ type: 'tool', sessionId, id: cap(sanitize(id), 200).text, title: cap(sanitize(text(update['title']) ?? 'tool'), MAX_TITLE_CHARS).text, kind: toolKind, status });
    } else if (kind === 'tool_call_update') {
      const id = text(update['toolCallId']);
      const status = typeof update['status'] === 'string' && STATUSES.has(update['status']) ? (update['status'] as ToolStatus) : undefined;
      if (id === undefined || status === undefined) return;
      this.#emit({ type: 'tool-update', sessionId, id: cap(sanitize(id), 200).text, status });
    }
  }

  /** Opens a session on `cwd`. The editor's MCP servers are never sent: hn uses only the user's own. */
  async newSession(cwd: string): Promise<{ sessionId: string; meta: SessionMeta }> {
    this.#opening += 1;
    try {
      const result = record(await this.#peer.request('session/new', { cwd, mcpServers: [] }, 120_000));
      const sessionId = result['sessionId'];
      if (typeof sessionId !== 'string' || !SESSION_ID.test(sessionId)) throw new Error('hn answered with something that is not a session id.');
      this.#sessions.add(sessionId);
      const hn = record(record(result['_meta'])['hn']);
      const meta: SessionMeta = {
        ...(typeof hn['tier'] === 'number' && Number.isInteger(hn['tier']) ? { tier: hn['tier'] } : {}),
        ...(typeof hn['mode'] === 'string' ? { mode: cap(sanitize(hn['mode']), 40).text } : {}),
        ...(typeof hn['sandbox'] === 'boolean' ? { sandbox: hn['sandbox'] } : {}),
      };
      return { sessionId, meta };
    } finally {
      this.#opening -= 1;
    }
  }

  async loadSession(sessionId: string, cwd: string): Promise<void> {
    if (!SESSION_ID.test(sessionId)) throw new Error('That is not a session id.');
    this.#opening += 1;
    try {
      await this.#peer.request('session/load', { sessionId, cwd, mcpServers: [] }, 120_000);
      this.#sessions.add(sessionId);
    } finally {
      this.#opening -= 1;
    }
  }

  /** One turn. Resolves with why it ended; a connection that breaks mid-turn rejects. */
  async prompt(sessionId: string, message: string): Promise<StopReason> {
    if (!this.#sessions.has(sessionId)) throw new Error('There is no such session.');
    if (this.#turns.has(sessionId)) throw new Error('This session is already working on a turn.');
    const turn = new AbortController();
    this.#turns.set(sessionId, turn);
    this.#chars = 0;
    this.#told = false;
    try {
      const result = record(await this.#peer.request('session/prompt', { sessionId, prompt: [{ type: 'text', text: message }] }));
      const reason = result['stopReason'];
      return typeof reason === 'string' && STOP_REASONS.has(reason) ? (reason as StopReason) : 'end_turn';
    } finally {
      this.#turns.delete(sessionId);
    }
  }

  /** Asks the turn to stop. Any approval still waiting is told it was cancelled. */
  cancel(sessionId: string): void {
    this.#peer.notify('session/cancel', { sessionId });
    this.#turns.get(sessionId)?.abort();
  }

  /** Closes hn's input so it ends its sessions, and stops it if it does not within five seconds. */
  async close(): Promise<void> {
    this.#closing = true;
    for (const turn of this.#turns.values()) turn.abort();
    if (this.#child.exitCode === null && this.#child.signalCode === null) {
      this.#peer.close();
      const timer = setTimeout(() => this.#child.kill(), 5_000);
      await this.#exit.catch(() => undefined);
      clearTimeout(timer);
    }
    this.#ended = true;
  }
}
