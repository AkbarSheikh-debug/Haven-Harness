import { readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { HnError } from '@hn/core';
import { KEY_ENV_NAMES, type KeyName } from '@hn/provider';
import type { ClaimMapping } from '@hn/security';
import type { OidcConfig } from './oidc-client.ts';

/**
 * The broker's own configuration, written by its operator. Nothing here comes from a client. Unknown fields are
 * errors, so a misspelt rule cannot quietly be left out.
 */

export type UpstreamKind = 'anthropic' | 'openai-compatible' | 'ollama';

export interface Upstream {
  readonly name: string;
  readonly kind: UpstreamKind;
  readonly baseUrl?: string;
  /** Which held key this upstream uses. The broker captured it from its own environment at start. */
  readonly key?: KeyName;
  /** Model name patterns this upstream serves (`*` matches any run). */
  readonly models: readonly string[];
}

export interface BrokerConfig {
  /** The address clients use. It is the audience of every token, so a token for another broker is refused here. */
  readonly url: string;
  readonly listen: { readonly host: string; readonly port: number };
  /** PEM files. Required unless the broker listens on loopback only. */
  readonly tls?: { readonly cert: string; readonly key: string };
  /** A folder only the broker's account can read: its token key, token book, ledgers and audit chain. */
  readonly state: string;
  readonly oidc: OidcConfig;
  readonly policy: { readonly bundle: string; readonly keys: Readonly<Record<string, string>> };
  readonly upstreams: readonly Upstream[];
  readonly limits?: { readonly requestsPerMinute?: number; readonly loginHours?: number; readonly sessionMinutes?: number; readonly concurrent?: number };
  /** Server-side tools: MCP servers over HTTP and git remotes, each with credentials only the broker holds. */
  readonly tools?: { readonly mcp?: readonly McpUpstream[]; readonly git?: readonly GitRemote[] };
  /** Credentials named in `tools`, taken from the broker's environment at start and removed from it. Never sent to a client. */
  readonly secrets: ReadonlyMap<string, string>;
  /** Where audit rows are shipped, as OTLP/HTTP JSON logs. Header values name environment variables, like the tools. */
  readonly audit?: { readonly otlp?: { readonly url: string; readonly headers: Readonly<Record<string, string>> } };
}

export interface McpUpstream {
  /** Lowercase letters, digits, `_` and `-`: it becomes part of every tool name. */
  readonly name: string;
  readonly url: string;
  /** Header name to the environment variable holding its value, such as `{"Authorization": "DOCS_MCP_TOKEN"}`. */
  readonly headers: Readonly<Record<string, string>>;
}

export interface GitRemote {
  /** The name policy and clients use, such as `acme/app`. */
  readonly repo: string;
  readonly remote: string;
  /** The environment variable holding a token, sent as HTTP basic auth. */
  readonly tokenEnv?: string;
}

export class BrokerConfigError extends HnError {
  constructor(message: string) {
    super('BROKER_CONFIG', message);
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

function only(value: unknown, keys: readonly string[], where: string): Record<string, unknown> {
  if (!isRecord(value)) throw new BrokerConfigError(`${where} must be an object.`);
  for (const key of Object.keys(value)) if (!keys.includes(key)) throw new BrokerConfigError(`${where} has an unknown field "${key}".`);
  return value;
}

const str = (value: unknown, where: string): string => {
  if (typeof value !== 'string' || value === '') throw new BrokerConfigError(`${where} must be a non-empty string.`);
  return value;
};

export const isLoopbackHost = (host: string): boolean => host === '127.0.0.1' || host === '::1' || host === 'localhost';

export function parseBrokerConfig(value: unknown, env: NodeJS.ProcessEnv = process.env): BrokerConfig {
  const root = only(value, ['url', 'listen', 'tls', 'state', 'oidc', 'policy', 'upstreams', 'limits', 'tools', 'audit'], 'broker config');
  const url = new URL(str(root['url'], 'url'));
  const listen = only(root['listen'], ['host', 'port'], 'listen');
  const host = str(listen['host'], 'listen.host');
  const port = listen['port'];
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 0 || port > 65535) throw new BrokerConfigError('listen.port must be a port number.');
  let tls: BrokerConfig['tls'];
  if (root['tls'] !== undefined) {
    const t = only(root['tls'], ['cert', 'key'], 'tls');
    tls = { cert: str(t['cert'], 'tls.cert'), key: str(t['key'], 'tls.key') };
  }
  // Tokens and model traffic must never cross a network in the clear.
  if (tls === undefined && !isLoopbackHost(host)) throw new BrokerConfigError('A broker that listens beyond loopback needs tls.');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackHost(url.hostname.replace(/^\[|\]$/g, '')))) throw new BrokerConfigError('url must be https unless the broker is on loopback.');
  const state = str(root['state'], 'state');
  if (!isAbsolute(state)) throw new BrokerConfigError('state must be an absolute path.');
  const o = only(root['oidc'], ['issuer', 'clientId', 'clientSecretEnv', 'claims', 'scope'], 'oidc');
  const c = only(o['claims'], ['user', 'ou', 'roles'], 'oidc.claims');
  const claims: ClaimMapping = { user: str(c['user'], 'oidc.claims.user'), ...(c['ou'] === undefined ? {} : { ou: str(c['ou'], 'oidc.claims.ou') }), ...(c['roles'] === undefined ? {} : { roles: str(c['roles'], 'oidc.claims.roles') }) };
  const secretEnv = o['clientSecretEnv'] === undefined ? undefined : str(o['clientSecretEnv'], 'oidc.clientSecretEnv');
  const secret = secretEnv === undefined ? undefined : process.env[secretEnv];
  if (secretEnv !== undefined) delete process.env[secretEnv];
  const oidc: OidcConfig = { issuer: str(o['issuer'], 'oidc.issuer'), clientId: str(o['clientId'], 'oidc.clientId'), claims, ...(secret === undefined ? {} : { clientSecret: secret }), ...(o['scope'] === undefined ? {} : { scope: str(o['scope'], 'oidc.scope') }) };
  const p = only(root['policy'], ['bundle', 'keys'], 'policy');
  const keys = only(p['keys'], Object.keys(isRecord(p['keys']) ? p['keys'] : {}), 'policy.keys');
  for (const [id, pem] of Object.entries(keys)) str(pem, `policy.keys.${id}`);
  if (Object.keys(keys).length === 0) throw new BrokerConfigError('policy.keys must pin at least one key.');
  if (!Array.isArray(root['upstreams']) || root['upstreams'].length === 0) throw new BrokerConfigError('upstreams must list at least one model provider.');
  const upstreams = root['upstreams'].map((item, index): Upstream => {
    const u = only(item, ['name', 'kind', 'baseUrl', 'key', 'models'], `upstreams[${index}]`);
    const kind = u['kind'];
    if (kind !== 'anthropic' && kind !== 'openai-compatible' && kind !== 'ollama') throw new BrokerConfigError(`upstreams[${index}].kind must be anthropic, openai-compatible or ollama.`);
    const key = u['key'];
    if (key !== undefined && !(KEY_ENV_NAMES as readonly unknown[]).includes(key)) throw new BrokerConfigError(`upstreams[${index}].key must be one of ${KEY_ENV_NAMES.join(', ')}.`);
    const models = u['models'];
    if (!Array.isArray(models) || models.length === 0 || !models.every((model) => typeof model === 'string' && model !== '')) throw new BrokerConfigError(`upstreams[${index}].models must list model patterns.`);
    if (kind !== 'anthropic' && u['baseUrl'] === undefined) throw new BrokerConfigError(`upstreams[${index}] needs a baseUrl.`);
    return { name: str(u['name'], `upstreams[${index}].name`), kind, models: models as string[], ...(u['baseUrl'] === undefined ? {} : { baseUrl: new URL(str(u['baseUrl'], 'baseUrl')).href.replace(/\/$/, '') }), ...(key === undefined ? {} : { key: key as KeyName }) };
  });
  let limits: BrokerConfig['limits'];
  if (root['limits'] !== undefined) {
    const l = only(root['limits'], ['requestsPerMinute', 'loginHours', 'sessionMinutes', 'concurrent'], 'limits');
    for (const [name, item] of Object.entries(l)) if (typeof item !== 'number' || !(item > 0)) throw new BrokerConfigError(`limits.${name} must be a positive number.`);
    limits = l as BrokerConfig['limits'];
  }
  const secrets = new Map<string, string>();
  const takeSecret = (name: string, where: string): string => {
    if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(name)) throw new BrokerConfigError(`${where} must name an environment variable.`);
    const found = secrets.get(name) ?? env[name];
    if (found === undefined || found === '') throw new BrokerConfigError(`${where}: ${name} is not set in the broker's environment.`);
    secrets.set(name, found);
    delete env[name];
    return name;
  };
  let tools: BrokerConfig['tools'];
  if (root['tools'] !== undefined) {
    const t = only(root['tools'], ['mcp', 'git'], 'tools');
    const list = (item: unknown, where: string): unknown[] => {
      if (item === undefined) return [];
      if (!Array.isArray(item)) throw new BrokerConfigError(`${where} must be a list.`);
      return item;
    };
    const mcp = list(t['mcp'], 'tools.mcp').map((item, index): McpUpstream => {
      const m = only(item, ['name', 'url', 'headers'], `tools.mcp[${index}]`);
      const name = str(m['name'], `tools.mcp[${index}].name`);
      if (!/^[a-z0-9_-]{1,32}$/.test(name)) throw new BrokerConfigError(`tools.mcp[${index}].name must be lowercase letters, digits, _ or -.`);
      const target = new URL(str(m['url'], `tools.mcp[${index}].url`));
      if (target.protocol !== 'https:' && !(target.protocol === 'http:' && isLoopbackHost(target.hostname))) throw new BrokerConfigError(`tools.mcp[${index}].url must be https.`);
      const headers = m['headers'] === undefined ? {} : only(m['headers'], Object.keys(isRecord(m['headers']) ? m['headers'] : {}), `tools.mcp[${index}].headers`);
      for (const [header, variable] of Object.entries(headers)) {
        if (!/^[A-Za-z0-9-]{1,64}$/.test(header)) throw new BrokerConfigError(`tools.mcp[${index}].headers has a bad header name.`);
        takeSecret(str(variable, `tools.mcp[${index}].headers.${header}`), `tools.mcp[${index}].headers.${header}`);
      }
      return { name, url: target.href, headers: headers as Record<string, string> };
    });
    const git = list(t['git'], 'tools.git').map((item, index): GitRemote => {
      const g = only(item, ['repo', 'remote', 'tokenEnv'], `tools.git[${index}]`);
      const repo = str(g['repo'], `tools.git[${index}].repo`);
      if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repo)) throw new BrokerConfigError(`tools.git[${index}].repo must look like owner/name.`);
      const remote = str(g['remote'], `tools.git[${index}].remote`);
      if (!/^(https:\/\/|file:\/\/)/.test(remote)) throw new BrokerConfigError(`tools.git[${index}].remote must be https (or file:// for a local mirror).`);
      return { repo, remote, ...(g['tokenEnv'] === undefined ? {} : { tokenEnv: takeSecret(str(g['tokenEnv'], `tools.git[${index}].tokenEnv`), `tools.git[${index}].tokenEnv`) }) };
    });
    tools = { mcp, git };
  }
  let audit: BrokerConfig['audit'];
  if (root['audit'] !== undefined) {
    const a = only(root['audit'], ['otlp'], 'audit');
    if (a['otlp'] !== undefined) {
      const o2 = only(a['otlp'], ['url', 'headers'], 'audit.otlp');
      const target = new URL(str(o2['url'], 'audit.otlp.url'));
      if (target.protocol !== 'https:' && !(target.protocol === 'http:' && isLoopbackHost(target.hostname))) throw new BrokerConfigError('audit.otlp.url must be https.');
      const headers = o2['headers'] === undefined ? {} : only(o2['headers'], Object.keys(isRecord(o2['headers']) ? o2['headers'] : {}), 'audit.otlp.headers');
      for (const [header, variable] of Object.entries(headers)) takeSecret(str(variable, `audit.otlp.headers.${header}`), `audit.otlp.headers.${header}`);
      audit = { otlp: { url: target.href, headers: headers as Record<string, string> } };
    } else audit = {};
  }
  return { secrets, ...(tools === undefined ? {} : { tools }), ...(audit === undefined ? {} : { audit }), url: url.href.replace(/\/$/, ''), listen: { host, port }, state, oidc, policy: { bundle: str(p['bundle'], 'policy.bundle'), keys: keys as Record<string, string> }, upstreams, ...(tls === undefined ? {} : { tls }), ...(limits === undefined ? {} : { limits }) };
}

export async function loadBrokerConfig(path: string): Promise<BrokerConfig> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new BrokerConfigError(`Could not read ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parseBrokerConfig(parsed);
}

/** A `*` pattern, matched whole and ignoring case. No regular expression syntax gets through. */
export const globMatch = (pattern: string, value: string): boolean =>
  new RegExp(`^${pattern.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 'i').test(value);
