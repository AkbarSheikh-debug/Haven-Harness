import { createHash, randomBytes } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { sanitizeForDisplay } from '@hn/core';
import { git } from '@hn/operations';
import type { GitRemote, McpUpstream } from './config.ts';
import { readJson, refusal, sendJson } from './http.ts';
import type { BrokerContext, Route } from './server.ts';
import type { Authenticated } from './tokens.ts';

/**
 * Server-side tools (decision 6). The credential for each one lives in the broker's memory only; the client sends
 * a request, the broker checks the person's policy and token, and runs the call itself. A modified client can ask
 * for anything here and gets only what the policy allows. MCP servers are spoken to over HTTP with no client
 * capabilities declared, so sampling, elicitation and roots cannot be asked of anyone.
 */

export interface ToolListing {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  /** Pushes to a protected ref need an approval first (Task 5). */
  readonly external: boolean;
}

const MAX_BUNDLE = 64 * 1024 * 1024;
const REF = /^refs\/heads\/[A-Za-z0-9._/-]{1,200}$/;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** One JSON-RPC exchange over MCP's streamable HTTP: the answer is either JSON or an event stream holding it. */
class McpHttp {
  readonly #server: McpUpstream;
  readonly #headers: Record<string, string>;
  #session: string | null = null;
  #ready: Promise<void> | null = null;
  #id = 0;

  constructor(server: McpUpstream, secrets: ReadonlyMap<string, string>) {
    this.#server = server;
    this.#headers = Object.fromEntries(Object.entries(server.headers).map(([header, variable]) => [header, secrets.get(variable) ?? '']));
  }

  async #post(body: Record<string, unknown>): Promise<Record<string, unknown> | null> {
    const response = await fetch(this.#server.url, {
      method: 'POST',
      redirect: 'error',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...this.#headers, ...(this.#session === null ? {} : { 'mcp-session-id': this.#session }) },
      body: JSON.stringify({ jsonrpc: '2.0', ...body }),
      signal: AbortSignal.timeout(60_000),
    });
    const session = response.headers.get('mcp-session-id');
    if (session !== null) this.#session = session;
    if (!('id' in body)) return null;
    if (!response.ok) throw new Error(`The MCP server answered ${response.status}.`);
    const text = (await response.text()).slice(0, 8 * 1024 * 1024);
    const candidates = (response.headers.get('content-type') ?? '').includes('text/event-stream')
      ? text.split('\n').filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trim())
      : [text];
    for (const candidate of candidates) {
      try {
        const message: unknown = JSON.parse(candidate);
        if (isRecord(message) && message['id'] === body['id']) {
          if (isRecord(message['error'])) throw new Error(`The MCP server refused: ${String(message['error']['message'] ?? 'error')}`);
          return isRecord(message['result']) ? message['result'] : {};
        }
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('The MCP server')) throw error;
      }
    }
    throw new Error('The MCP server sent no answer to the request.');
  }

  async request(method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.#ready ??= (async () => {
      await this.#post({ id: ++this.#id, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'hn-broker', version: '0' } } });
      await this.#post({ method: 'notifications/initialized' });
    })();
    await this.#ready;
    return (await this.#post({ id: ++this.#id, method, params })) ?? {};
  }
}

const GIT_PUSH: Omit<ToolListing, 'name'> = {
  description: 'Pushes the current HEAD of the project to a branch of a team repository. The broker pushes with its own credential; you never see it.',
  inputSchema: { type: 'object', properties: { repo: { type: 'string', description: 'owner/name' }, branch: { type: 'string' }, bundle: { type: 'string', description: 'Filled in by hn, not by the model.' } }, required: ['repo', 'branch'] },
  external: true,
};

export interface ServerTools {
  readonly routes: readonly Route[];
}

export function serverTools(context0: { config: { tools?: { mcp?: readonly McpUpstream[]; git?: readonly GitRemote[] }; secrets: ReadonlyMap<string, string>; state: string } }, approve?: (context: BrokerContext, who: Authenticated, action: string) => Promise<string | null>): ServerTools {
  const { config } = context0;
  const clients = new Map<string, McpHttp>();
  const client = (server: McpUpstream): McpHttp => {
    let found = clients.get(server.name);
    if (found === undefined) clients.set(server.name, (found = new McpHttp(server, config.secrets)));
    return found;
  };
  const listings = new Map<string, { at: number; tools: { name: string; description: string; inputSchema: Record<string, unknown> }[] }>();

  /** Why this person may not call this tool, or null. Asked on every listing and again on every call. */
  const reason = (context: BrokerContext, who: Authenticated, name: string): string | null => {
    const policy = context.policyFor(who.identity);
    const server = /^mcp__([a-z0-9_-]+)__/.exec(name)?.[1];
    if (server !== undefined && !policy.mcpAllowed(server)) return `The MCP server ${server} is not allowed for ${who.identity.user}.`;
    return policy.toolReason(name) ?? (context.tokens.covers(who, name) ? null : `${name} is not covered by this session's token.`);
  };

  async function list(context: BrokerContext, who: Authenticated): Promise<ToolListing[]> {
    const out: ToolListing[] = [];
    for (const server of config.tools?.mcp ?? []) {
      // A server this person may not use is never contacted on their behalf, not even to list it.
      if (!context.policyFor(who.identity).mcpAllowed(server.name)) continue;
      let cached = listings.get(server.name);
      if (cached === undefined || context.now() - cached.at > 300_000) {
        try {
          const result = await client(server).request('tools/list', {});
          const tools = Array.isArray(result['tools']) ? result['tools'].filter(isRecord) : [];
          cached = { at: context.now(), tools: tools.filter((tool) => typeof tool['name'] === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(tool['name'])).map((tool) => ({ name: String(tool['name']), description: String(tool['description'] ?? '').slice(0, 2000), inputSchema: isRecord(tool['inputSchema']) ? tool['inputSchema'] : { type: 'object' } })) };
          listings.set(server.name, cached);
        } catch {
          continue;
        }
      }
      for (const tool of cached.tools) {
        const name = `mcp__${server.name}__${tool.name}`;
        if (reason(context, who, name) === null) out.push({ name, description: tool.description, inputSchema: tool.inputSchema, external: true });
      }
    }
    const policy = context.policyFor(who.identity);
    if ((config.tools?.git ?? []).some((remote) => policy.gitRepoAllowed(remote.repo)) && reason(context, who, 'git_push') === null) out.push({ name: 'git_push', ...GIT_PUSH });
    return out;
  }

  async function push(context: BrokerContext, who: Authenticated, args: Record<string, unknown>): Promise<{ ok: boolean; text: string }> {
    const policy = context.policyFor(who.identity);
    const repo = String(args['repo'] ?? '');
    const remote = (config.tools?.git ?? []).find((item) => item.repo === repo);
    if (remote === undefined || !policy.gitRepoAllowed(repo)) return { ok: false, text: `Pushing to ${repo} is not allowed for ${who.identity.user}.` };
    const ref = `refs/heads/${String(args['branch'] ?? '')}`;
    if (!REF.test(ref) || ref.includes('..') || ref.includes('//') || ref.endsWith('/') || ref.endsWith('.lock') || ref.split('/').some((part) => part.startsWith('-') || part.startsWith('.'))) return { ok: false, text: 'The branch name is not allowed.' };
    const bundle = typeof args['bundle'] === 'string' ? Buffer.from(args['bundle'], 'base64') : Buffer.alloc(0);
    if (bundle.length === 0 || bundle.length > MAX_BUNDLE) return { ok: false, text: 'No bundle, or one that is too large.' };
    const mirror = join(config.state, 'git', createHash('sha256').update(repo).digest('hex').slice(0, 16));
    const file = join(config.state, 'git', `incoming-${randomBytes(8).toString('hex')}.bundle`);
    await mkdir(mirror, { recursive: true, mode: 0o700 });
    try {
      await writeFile(file, bundle, { mode: 0o600 });
      await git(['init', '--bare', '--quiet'], { cwd: mirror });
      const heads = (await git(['bundle', 'list-heads', file], { cwd: mirror })).stdout.split('\n').map((line) => line.trim().split(' ')).filter((parts) => parts.length === 2);
      const head = heads.find(([, name]) => name === 'HEAD') ?? heads[0];
      if (head === undefined || !/^[0-9a-f]{40,64}$/.test(head[0] as string)) return { ok: false, text: 'The bundle names no commit.' };
      // An approval is bound to the exact commit, so approving one push does not approve another.
      if (policy.refProtected(ref)) {
        const refused = approve === undefined ? 'This branch is protected and needs an approval, which this broker cannot ask for.' : await approve(context, who, `git_push ${repo} ${ref} ${head[0]}`);
        if (refused !== null) return { ok: false, text: refused };
      }
      await git(['fetch', '--quiet', '--no-tags', file, `+${head[1]}:refs/hn/incoming`], { cwd: mirror });
      const token = remote.tokenEnv === undefined ? undefined : config.secrets.get(remote.tokenEnv);
      const header = token === undefined ? undefined : `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`;
      // No force: a push that is not a fast-forward is refused by the remote, as it would be for a person.
      const result = await git(['push', '--porcelain', '--', remote.remote, `refs/hn/incoming:${ref}`], { cwd: mirror, check: false, remote: header === undefined ? {} : { header } });
      const scrub = (text: string): string => (token === undefined ? text : text.replaceAll(token, '[REDACTED]'));
      context.audit('broker/git-push', { user: who.identity.user, repo, ref, commit: head[0], ok: result.code === 0 });
      return result.code === 0 ? { ok: true, text: `Pushed ${String(head[0]).slice(0, 12)} to ${repo} ${ref}.` } : { ok: false, text: `The push was refused: ${sanitizeForDisplay(scrub(result.stderr)).slice(0, 2000)}` };
    } finally {
      await rm(file, { force: true });
    }
  }

  const routes: Route[] = [
    {
      method: 'GET',
      path: '/v1/tools',
      async handle(context, request, response) {
        const who = context.auth(request, response, 'session');
        if (who === null) return;
        sendJson(response, 200, { tools: await list(context, who) });
      },
    },
    {
      method: 'POST',
      path: '/v1/tools/call',
      async handle(context, request, response) {
        const who = context.auth(request, response, 'session');
        if (who === null) return;
        const body = await readJson(request, MAX_BUNDLE * 2);
        if (!isRecord(body) || typeof body['name'] !== 'string' || !isRecord(body['args'])) return refusal(response, 400, 'Expected {name, args}.');
        const name = body['name'];
        const why = reason(context, who, name);
        if (why !== null) {
          context.audit('broker/tool-refused', { user: who.identity.user, tool: name, reason: why });
          return refusal(response, 403, why);
        }
        if (name === 'git_push') return sendJson(response, 200, await push(context, who, body['args']));
        const match = /^mcp__([a-z0-9_-]+)__([A-Za-z0-9_-]+)$/.exec(name);
        const server = match === null ? undefined : (config.tools?.mcp ?? []).find((item) => item.name === match[1]);
        if (server === undefined || match === null) return refusal(response, 404, `No server-side tool is called ${name}.`);
        try {
          const result = await client(server).request('tools/call', { name: match[2], arguments: body['args'] });
          const content = Array.isArray(result['content']) ? result['content'].filter(isRecord).map((part) => (part['type'] === 'text' ? String(part['text'] ?? '') : `[${String(part['type'])} omitted]`)).join('\n') : '';
          context.audit('broker/tool', { user: who.identity.user, tool: name, isError: result['isError'] === true });
          sendJson(response, 200, { ok: result['isError'] !== true, text: content });
        } catch (error) {
          sendJson(response, 200, { ok: false, text: sanitizeForDisplay(error instanceof Error ? error.message : String(error)) });
        }
      },
    },
  ];
  return { routes };
}
