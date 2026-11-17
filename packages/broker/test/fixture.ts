import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseBrokerConfig, startBroker, type Broker, type Route } from '@hn/broker';
import { KeyStore } from '@hn/provider';
import { signPolicyTree } from '@hn/security';
import { startFakeIdp, startFakeOpenAI, type FakeIdp, type FakeOpenAI, type FakeOpenAIReply, type FakeOpenAIRequest } from '@hn/testkit';

/** A whole team on loopback for tests: an identity provider, a model upstream, a signed policy and a broker. */

export const UPSTREAM_KEY = 'sk-broker-held-key-0123456789';

export const baseTree = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  format: 1,
  serial: 1,
  issued: '2026-11-17T00:00:00Z',
  org: { version: 1, name: 'org', models: { allow: ['team-*'] }, approvers: { roles: ['lead'] } },
  ou: { eng: { version: 1, name: 'eng' }, hr: { version: 1, name: 'hr', tools: { deny: ['bash'] } } },
  roles: { intern: { version: 1, name: 'intern', models: { allow: ['team-small'] } } },
  users: {},
  ...extra,
});

export interface Person {
  readonly loginToken: string;
  readonly sid: string;
  session(id: string): Promise<string>;
}

export interface Team {
  readonly broker: Broker;
  readonly idp: FakeIdp;
  readonly upstream: FakeOpenAI;
  readonly dir: string;
  readonly audit: { type: string; data: Record<string, unknown> }[];
  /** Logs a person in through the device flow with these claims. */
  login(claims: Record<string, unknown>): Promise<Person>;
  /** Writes and signs a new policy tree and reloads it. */
  setPolicy(tree: Record<string, unknown>): Promise<void>;
  /** A raw request, as a modified client would send it. */
  raw(path: string, init: { method?: string; token?: string; session?: string; body?: unknown; headers?: Record<string, string> }): Promise<Response>;
  close(): Promise<void>;
}

export interface TeamOptions {
  readonly tree?: Record<string, unknown>;
  readonly decide?: (request: FakeOpenAIRequest) => FakeOpenAIReply | Promise<FakeOpenAIReply>;
  readonly now?: () => number;
  readonly routes?: (dir: string) => readonly Route[];
  readonly limits?: Record<string, number>;
  readonly tools?: Record<string, unknown>;
  readonly audit?: Record<string, unknown>;
  readonly env?: NodeJS.ProcessEnv;
  readonly approve?: Parameters<typeof startBroker>[0]['approve'];
}

export async function startTeam(options: TeamOptions = {}): Promise<Team> {
  const dir = await mkdtemp(join(tmpdir(), 'hn-team-'));
  const signer = generateKeyPairSync('ed25519');
  const idp = await startFakeIdp();
  const upstream = await startFakeOpenAI(options.decide ?? (() => ({ text: 'hello from upstream' })));
  const bundlePath = join(dir, 'policy.json');
  const writeTree = (tree: Record<string, unknown>): Promise<void> => writeFile(bundlePath, JSON.stringify(signPolicyTree(tree, 'org-1', signer.privateKey)));
  await writeTree(options.tree ?? baseTree());
  const config = parseBrokerConfig({
    url: 'http://127.0.0.1:7777',
    listen: { host: '127.0.0.1', port: 0 },
    state: join(dir, 'state'),
    oidc: { issuer: idp.issuer, clientId: idp.clientId, claims: { user: 'email', ou: 'department', roles: 'groups' } },
    policy: { bundle: bundlePath, keys: { 'org-1': signer.publicKey.export({ type: 'spki', format: 'pem' }).toString() } },
    upstreams: [{ name: 'fake', kind: 'openai-compatible', baseUrl: upstream.url, key: 'OPENAI_API_KEY', models: ['team-*'] }],
    ...(options.limits === undefined ? {} : { limits: options.limits }),
    ...(options.tools === undefined ? {} : { tools: options.tools }),
    ...(options.audit === undefined ? {} : { audit: options.audit }),
  }, { ...(options.env ?? {}) });
  const audit: { type: string; data: Record<string, unknown> }[] = [];
  const broker = await startBroker({
    config,
    keys: KeyStore.capture({ OPENAI_API_KEY: UPSTREAM_KEY }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.routes === undefined ? {} : { routes: options.routes(dir) }),
    audit: (type, data) => audit.push({ type, data }),
    ...(options.approve === undefined ? {} : { approve: options.approve }),
  });
  const raw: Team['raw'] = (path, init) =>
    fetch(`${broker.url}${path}`, {
      method: init.method ?? (init.body === undefined ? 'GET' : 'POST'),
      headers: { ...(init.body === undefined ? {} : { 'content-type': 'application/json' }), ...(init.token === undefined ? {} : { authorization: `Bearer ${init.token}` }), ...(init.session === undefined ? {} : { 'x-hn-session': init.session }), ...init.headers },
      ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    });
  return {
    broker,
    idp,
    upstream,
    dir,
    audit,
    raw,
    async login(claims) {
      idp.user = { sub: `sub-${String(claims['email'])}`, ...claims };
      const start = (await (await raw('/v1/login/start', { body: {} })).json()) as { loginId: string; userCode: string };
      idp.decide(start.userCode, true);
      const done = (await (await raw('/v1/login/poll', { body: { loginId: start.loginId } })).json()) as { token: string; sid: string };
      if (typeof done.token !== 'string') throw new Error(`login failed: ${JSON.stringify(done)}`);
      return {
        loginToken: done.token,
        sid: done.sid,
        async session(id) {
          const issued = (await (await raw('/v1/session', { token: done.token, session: done.sid, body: { session: id } })).json()) as { token: string };
          return issued.token;
        },
      };
    },
    async setPolicy(tree) {
      await writeTree(tree);
      await broker.reloadPolicy();
    },
    async close() {
      await broker.close();
      await upstream.close();
      await idp.close();
      await rm(dir, { recursive: true, force: true });
    },
  };
}
