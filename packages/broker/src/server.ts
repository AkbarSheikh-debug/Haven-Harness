import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { sanitizeForDisplay } from '@hn/core';
import type { KeyStore, ModelProvider } from '@hn/provider';
import { layersFor, verifyPolicyTree, type Identity, type PolicySeen, type PolicySet, type PolicyTree } from '@hn/security';
import type { BrokerConfig, Upstream } from './config.ts';
import { HttpRefusal, header, readJson, refusal, sendJson } from './http.ts';
import { Ledger, RateWindow } from './ledger.ts';
import { ModelRouteError, governedCall, makeUpstreamProvider, parseModelRequest, toolRule, upstreamFor } from './model-route.ts';
import { OidcClient, type DeviceStart } from './oidc-client.ts';
import { TokenBook, type Authenticated, type TokenKind } from './tokens.ts';
import { serverTools } from './server-tools.ts';
import { brokerApprovals } from './approvals.ts';
import { openBrokerAudit, type BrokerAuditSink } from './audit-sink.ts';
import { openTeamMemory } from './team-memory.ts';

/**
 * `hn broker`: one Node process holding everything a laptop must not hold. Each route authenticates
 * the token it is given, works out the person's policy from the signed tree, and decides on the server. Later
 * tasks add routes (server-side tools, approvals, audit anchors, memory) through `routes`, so this file stays
 * the core: login, session tokens, the policy and governed model calls.
 */

export type BrokerAudit = (type: string, data: Record<string, unknown>) => void;

export interface BrokerContext {
  readonly config: BrokerConfig;
  readonly tokens: TokenBook;
  readonly ledger: Ledger;
  readonly now: () => number;
  /** The tree in force. Replaced only by a newer signed bundle. */
  tree(): PolicyTree;
  policyFor(identity: Identity): PolicySet;
  audit: BrokerAudit;
  /** Authenticates a request or answers it with a refusal and returns null. */
  auth(request: IncomingMessage, response: ServerResponse, kind: TokenKind, scope?: { tool?: string }): Authenticated | null;
}

export interface Route {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  handle(context: BrokerContext, request: IncomingMessage, response: ServerResponse): Promise<void>;
}

export interface BrokerOptions {
  readonly config: BrokerConfig;
  /** Keys the broker holds, captured from its own environment. */
  readonly keys: KeyStore;
  readonly now?: () => number;
  readonly fetch?: typeof fetch;
  readonly providerFor?: (upstream: Upstream) => ModelProvider;
  readonly routes?: readonly Route[];
  readonly audit?: BrokerAudit;
  /** Decides an action that needs an approval (a push to a protected ref): null when approved, else why not. */
  readonly approve?: (context: BrokerContext, who: Authenticated, action: string) => Promise<string | null>;
}

export interface Broker {
  readonly url: string;
  readonly context: BrokerContext;
  readonly audit: BrokerAuditSink;
  reloadPolicy(): Promise<void>;
  close(): Promise<void>;
}

const SESSION_ID = /^[A-Za-z0-9_-]{1,100}$/;
const MODEL_BODY = 32 * 1024 * 1024;

async function loadTree(config: BrokerConfig, statePath: string): Promise<{ tree: PolicyTree; seen: PolicySeen }> {
  let last: PolicySeen | null = null;
  try {
    last = JSON.parse(await readFile(statePath, 'utf8')) as PolicySeen;
  } catch {
    // First start.
  }
  const bundle: unknown = JSON.parse(await readFile(config.policy.bundle, 'utf8'));
  const loaded = verifyPolicyTree(bundle, new Map(Object.entries(config.policy.keys)), last);
  await writeFile(statePath, JSON.stringify(loaded.seen), { mode: 0o600 });
  return loaded;
}

export async function startBroker(options: BrokerOptions): Promise<Broker> {
  const { config } = options;
  const now = options.now ?? Date.now;
  const tokens = await TokenBook.open(config.state, config.url, now);
  const ledger = new Ledger(join(config.state, 'ledger'), now);
  const rate = new RateWindow(config.limits?.requestsPerMinute ?? 120, now);
  const oidc = new OidcClient(config.oidc, { ...(options.fetch === undefined ? {} : { fetch: options.fetch }), now });
  const seenPath = join(config.state, 'policy-seen.json');
  let tree = (await loadTree(config, seenPath)).tree;
  const providers = new Map<string, ModelProvider>();
  const providerFor = (upstream: Upstream): ModelProvider => {
    let provider = providers.get(upstream.name);
    if (provider === undefined) providers.set(upstream.name, (provider = options.providerFor?.(upstream) ?? makeUpstreamProvider(upstream, options.keys)));
    return provider;
  };
  const logins = new Map<string, { start: DeviceStart; interval: number; polled: number }>();
  // Calls in flight per person. The budget is checked before a call and charged after, so this caps how far
  // parallel calls can carry a person past their budget.
  const inFlight = new Map<string, number>();
  const maxInFlight = config.limits?.concurrent ?? 4;
  const otlp = config.audit?.otlp;
  const sink = await openBrokerAudit(config.state, otlp === undefined ? undefined : { url: otlp.url, headers: Object.fromEntries(Object.entries(otlp.headers).map(([header, variable]) => [header, config.secrets.get(variable) ?? ''])) });

  const context: BrokerContext = {
    config,
    tokens,
    ledger,
    now,
    tree: () => tree,
    policyFor: (identity) => layersFor(tree, identity),
    // Every decision goes into the broker's own chain; a caller's tap (tests, a console) sees the same rows.
    audit: (type, data) => {
      sink.record(type, data);
      options.audit?.(type, data);
    },
    auth(request, response, kind, scope = {}) {
      const result = tokens.authenticate(header(request, 'authorization'), header(request, 'x-hn-session'), kind, scope);
      if (!result.ok) {
        context.audit('broker/auth-refused', { path: request.url ?? '', reason: result.reason });
        refusal(response, 401, result.reason);
        return null;
      }
      if (!rate.take(result.who.identity.user)) {
        refusal(response, 429, 'Too many requests from this person in the last minute.');
        return null;
      }
      return result.who;
    },
  };

  const core: Route[] = [
    {
      method: 'POST',
      path: '/v1/login/start',
      async handle(_context, _request, response) {
        // Anyone can start a login, so pending logins expire and are capped: starting thousands cannot exhaust memory.
        for (const [id, item] of logins) if (item.start.expiresAt <= now()) logins.delete(id);
        if (logins.size >= 1000) return refusal(response, 503, 'Too many logins are waiting. Try again in a few minutes.');
        const start = await oidc.startDevice();
        const loginId = randomBytes(16).toString('hex');
        logins.set(loginId, { start, interval: start.interval, polled: 0 });
        sendJson(response, 200, { loginId, userCode: start.userCode, verificationUri: start.verificationUri, interval: start.interval, expiresAt: start.expiresAt });
      },
    },
    {
      method: 'POST',
      path: '/v1/login/poll',
      async handle(_context, request, response) {
        const body = await readJson(request, 4096);
        const loginId = typeof body === 'object' && body !== null ? (body as Record<string, unknown>)['loginId'] : undefined;
        const login = typeof loginId === 'string' ? logins.get(loginId) : undefined;
        if (login === undefined) return refusal(response, 404, 'No such login.');
        // The provider is asked at most once per interval, however often a client polls.
        if (now() - login.polled < login.interval * 1000) return sendJson(response, 200, { state: 'pending', interval: login.interval });
        login.polled = now();
        const result = await oidc.pollDevice(login.start, login.interval);
        if (result.state === 'pending') {
          login.interval = result.interval;
          return sendJson(response, 200, { state: 'pending', interval: result.interval });
        }
        logins.delete(loginId as string);
        if (result.state === 'failed') {
          context.audit('broker/login-failed', { reason: result.reason });
          return refusal(response, 401, result.reason);
        }
        const issued = await tokens.issueLogin(result.identity, result.subject, (config.limits?.loginHours ?? 8) * 3600_000);
        context.audit('broker/login', { user: result.identity.user, ou: result.identity.ou, roles: result.identity.roles });
        // The client names this sid when it uses the login token, as every token's session must be named.
        const caveats = (JSON.parse(Buffer.from(issued.token, 'base64url').toString('utf8')) as { caveats: string[] }).caveats;
        sendJson(response, 200, { state: 'done', token: issued.token, expires: issued.expires, sid: caveats.find((item) => item.startsWith('sid='))?.slice(4), identity: result.identity, policyKeys: config.policy.keys });
      },
    },
    {
      method: 'POST',
      path: '/v1/session',
      async handle(context_, request, response) {
        const login = context_.auth(request, response, 'login');
        if (login === null) return;
        const body = await readJson(request, 4096);
        const session = typeof body === 'object' && body !== null ? (body as Record<string, unknown>)['session'] : undefined;
        if (typeof session !== 'string' || !SESSION_ID.test(session)) return refusal(response, 400, 'session must be an id of letters, digits, - and _.');
        const issued = await tokens.issueSession(login, session, (config.limits?.sessionMinutes ?? 60) * 60_000);
        context_.audit('broker/session', { user: login.identity.user, session });
        sendJson(response, 200, { token: issued.token, expires: issued.expires });
      },
    },
    {
      method: 'GET',
      path: '/v1/policy',
      async handle(context_, request, response) {
        if (context_.auth(request, response, 'session') === null) return;
        sendJson(response, 200, JSON.parse(await readFile(config.policy.bundle, 'utf8')));
      },
    },
    {
      method: 'GET',
      path: '/v1/whoami',
      async handle(context_, request, response) {
        const who = context_.auth(request, response, 'session');
        if (who === null) return;
        const policy = context_.policyFor(who.identity);
        sendJson(response, 200, { identity: who.identity, layers: policy.layers.map((layer) => layer.name ?? '(unnamed)'), maxMode: policy.maxMode(), spent: await ledger.spent(who.identity.user), budget: policy.budget() });
      },
    },
    {
      method: 'POST',
      path: '/v1/model',
      async handle(context_, request, response) {
        const who = context_.auth(request, response, 'session');
        if (who === null) return;
        const modelRequest = parseModelRequest(await readJson(request, MODEL_BODY));
        const policy = context_.policyFor(who.identity);
        const user = who.identity.user;
        if (!policy.modelAllowed(modelRequest.model)) {
          context_.audit('broker/model-refused', { user, model: modelRequest.model, reason: 'policy' });
          return refusal(response, 403, `The policy does not allow ${user} to use ${modelRequest.model}.`);
        }
        const over = await ledger.check(user, policy.budget());
        if (over !== null) {
          context_.audit('broker/model-refused', { user, model: modelRequest.model, reason: 'budget' });
          return refusal(response, 402, over);
        }
        const upstream = upstreamFor(config.upstreams, modelRequest.model);
        if (upstream === null) return refusal(response, 404, `No upstream serves ${modelRequest.model}.`);
        if ((inFlight.get(user) ?? 0) >= maxInFlight) return refusal(response, 429, `${user} already has ${maxInFlight} model calls running.`);
        inFlight.set(user, (inFlight.get(user) ?? 0) + 1);
        let released = false;
        const release = (): void => {
          if (released) return;
          released = true;
          inFlight.set(user, Math.max(0, (inFlight.get(user) ?? 1) - 1));
        };
        response.on('close', release);
        const abort = new AbortController();
        response.on('close', () => abort.abort());
        response.writeHead(200, { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store' });
        const line = (value: unknown): void => {
          if (!response.writableEnded) response.write(`${JSON.stringify(value)}\n`);
        };
        try {
          const result = await governedCall({ request: modelRequest, provider: providerFor(upstream), rule: toolRule(policy, (tool) => tokens.covers(who, tool)), signal: abort.signal, onEvent: (event) => line({ type: 'event', event }) });
          await ledger.add(user, result.usd, result.tokens);
          context_.audit('broker/model', { user, session: who.sid, model: modelRequest.model, upstream: upstream.name, usd: result.usd, tokens: result.tokens, removedTools: result.removedTools, stripped: result.stripped });
          line({ type: 'reply', reply: result.reply });
        } catch (error) {
          const kind = typeof error === 'object' && error !== null && 'reason' in error ? String((error as { reason: unknown }).reason) : 'server_error';
          line({ type: 'error', error: { kind, message: sanitizeForDisplay(error instanceof Error ? error.message : String(error)) } });
        } finally {
          release();
        }
        response.end();
      },
    },
  ];
  const approvals = brokerApprovals();
  const memory = await openTeamMemory(config.state);
  const routes = [...core, ...sink.routes, ...memory.routes, ...approvals.routes, ...serverTools({ config }, options.approve ?? approvals.hook).routes, ...(options.routes ?? [])];

  const handler = (request: IncomingMessage, response: ServerResponse): void => {
    const path = new URL(request.url ?? '/', 'http://broker').pathname;
    const route = routes.find((item) => item.path === path && item.method === request.method);
    if (route === undefined) return refusal(response, 404, 'No such route.');
    route.handle(context, request, response).catch((error: unknown) => {
      if (error instanceof HttpRefusal || error instanceof ModelRouteError) return refusal(response, error.status, error.message);
      context.audit('broker/error', { path, message: error instanceof Error ? error.message : String(error) });
      refusal(response, 500, 'The broker failed on this request.');
    });
  };
  const server: Server = config.tls === undefined ? createHttpServer(handler) : createHttpsServer({ cert: await readFile(config.tls.cert), key: await readFile(config.tls.key), minVersion: 'TLSv1.2' }, handler);
  server.requestTimeout = 15 * 60_000;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.listen.port, config.listen.host, resolve);
  });
  const port = (server.address() as AddressInfo).port;
  return {
    url: `${config.tls === undefined ? 'http' : 'https'}://${config.listen.host.includes(':') ? `[${config.listen.host}]` : config.listen.host}:${port}`,
    context,
    async reloadPolicy() {
      tree = (await loadTree(config, seenPath)).tree;
    },
    audit: sink,
    async close() {
      await new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      });
      await sink.flush();
      sink.close();
    },
  };
}
