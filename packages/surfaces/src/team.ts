import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { createBrokerProvider, type ModelProvider } from '@hn/provider';
import { PolicySet, RosterError, activeKeys, layersFor, loadLocalPolicy, loadTrust, offerRoster, verifyPolicyTree, type AuditEntry, type AuditFile, type Identity, type PolicySeen, type RootKey, type TrustSource } from '@hn/security';
import { loadOrCreateLogKey } from '@hn/session';

/**
 * Team mode on the laptop (Phase 8). `hn login <broker>` runs the device flow through the broker and keeps a login
 * token in `~/.hn/team.json`; a session started with `--team` asks the broker for a token of its own, sends every
 * model call there, and applies the signed policy tree to its local gate as well. Locally the tree is advisory,
 * like any policy file; what binds is the broker, which decides again on every call.
 */

export interface TeamLogin {
  readonly url: string;
  readonly loginToken: string;
  readonly sid: string;
  readonly expires: number;
  readonly identity: Identity;
  /** Pinned on first login. A later bundle signed by any other key is refused here. */
  readonly policyKeys: Readonly<Record<string, string>>;
  /**
   * The root key that signs the broker's key rosters (Phase 15), pinned at the first login to a broker and never
   * taken from a broker you were already logged in to. Without it the keys above never change.
   */
  readonly policyRoot?: RootKey;
  readonly seen: PolicySeen | null;
}

const trustDir = (home: string): string => join(home, 'trust');

/** Where the policy keys this machine trusts come from, or null when the broker pins no root. */
export async function policyTrustSource(home: string): Promise<TrustSource | null> {
  const login = await loadTeamLogin(home, 0).catch(() => null);
  if (login === null || login.policyRoot === undefined) return null;
  return { purpose: 'policy', root: login.policyRoot, pins: login.policyKeys };
}

/**
 * The policy keys to trust now. With a pinned root the broker's roster is fetched and applied first: a roster that
 * does not check out (another root, an older serial, a changed one) is an error, never ignored; a broker that
 * cannot be reached for it leaves the last roster in force, revocations included.
 */
async function currentPolicyKeys(login: TeamLogin, home: string, fetcher: typeof fetch): Promise<{ keys: Map<string, string>; revoked: ReadonlySet<string> }> {
  const source = await policyTrustSource(home);
  if (source === null || login.policyRoot === undefined) return { keys: new Map(Object.entries(login.policyKeys)), revoked: new Set() };
  const folder = trustDir(home);
  const key = await loadOrCreateLogKey(join(home, 'log.key'));
  let state = await loadTrust(folder, key, source);
  const offered = await call(fetcher, `${login.url}/v1/trust/policy`, {}).catch(() => null);
  if (offered !== null && offered['roster'] !== undefined) {
    try {
      state = (await offerRoster(folder, key, source, offered)).state;
    } catch (error) {
      if (error instanceof RosterError) throw new HnError('POLICY_ROSTER_REFUSED', `The broker's key roster was refused: ${sanitizeForDisplay(error.message)}`);
      throw error;
    }
  }
  return { keys: activeKeys(state), revoked: new Set(Object.keys(state.revoked)) };
}

const teamFile = (home: string): string => join(home, 'team.json');

export async function loadTeamLogin(home: string, now = Date.now()): Promise<TeamLogin> {
  let login: TeamLogin;
  try {
    login = JSON.parse(await readFile(teamFile(home), 'utf8')) as TeamLogin;
  } catch {
    throw new HnError('TEAM_NOT_LOGGED_IN', 'Not logged in to a broker. Run: hn login <broker address>');
  }
  if (login.expires <= now) throw new HnError('TEAM_LOGIN_EXPIRED', 'The broker login has expired. Run hn login again.');
  return login;
}

async function saveTeamLogin(home: string, login: TeamLogin): Promise<void> {
  await mkdir(home, { recursive: true });
  await writeFile(teamFile(home), JSON.stringify(login), { mode: 0o600 });
  await chmod(teamFile(home), 0o600).catch(() => undefined);
}

async function call(fetcher: typeof fetch, url: string, init: { token?: string; session?: string; body?: unknown }): Promise<Record<string, unknown>> {
  const response = await fetcher(url, {
    method: init.body === undefined ? 'GET' : 'POST',
    redirect: 'error',
    headers: { ...(init.body === undefined ? {} : { 'content-type': 'application/json' }), ...(init.token === undefined ? {} : { authorization: `Bearer ${init.token}` }), ...(init.session === undefined ? {} : { 'x-hn-session': init.session }) },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) throw new HnError('BROKER_REFUSED', `The broker refused: ${sanitizeForDisplay(String(body['error'] ?? response.status))}`);
  return body;
}

export interface LoginContext {
  readonly positionals: readonly string[];
  readonly home: string;
  readonly out: (text: string) => void;
  readonly fetch?: typeof fetch;
  readonly wait?: (ms: number) => Promise<void>;
}

/** `hn login <broker>` and `hn logout`. Returns null for any other command. */
export async function runLoginCommand(context: LoginContext): Promise<number | null> {
  const [command, address] = context.positionals;
  if (command === 'logout' && address === undefined) {
    await rm(teamFile(context.home), { force: true });
    context.out('Logged out of the broker.\n');
    return 0;
  }
  if (command !== 'login') return null;
  if (address === undefined) throw new HnError('BAD_COMMAND', 'hn login <broker address>');
  const url = new URL(address);
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) throw new HnError('BAD_COMMAND', 'The broker address must be https.');
  const base = url.href.replace(/\/$/, '');
  const fetcher = context.fetch ?? fetch;
  const wait = context.wait ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const start = await call(fetcher, `${base}/v1/login/start`, { body: {} });
  // The code and address come from far away, so they are shown cleaned.
  context.out(`To log in, open ${sanitizeForDisplay(String(start['verificationUri']))} and enter the code ${sanitizeForDisplay(String(start['userCode']))}\n`);
  let interval = Number(start['interval']) || 5;
  for (;;) {
    await wait(interval * 1000);
    const poll = await call(fetcher, `${base}/v1/login/poll`, { body: { loginId: start['loginId'] } });
    if (poll['state'] === 'pending') {
      interval = Number(poll['interval']) || interval;
      continue;
    }
    const previous = await loadTeamLogin(context.home, 0).catch(() => null);
    const identity = poll['identity'] as Identity;
    // Keys are pinned the first time this broker is used, and kept after that, so a broker cannot swap them later.
    const again = previous !== null && previous.url === base;
    const policyKeys = again ? previous.policyKeys : (poll['policyKeys'] as Record<string, string>);
    // The root is pinned the same way, and only at the first login: a broker you are already using cannot hand you a new one.
    const offeredRoot = poll['policyRoot'] as { keyId?: unknown; publicKey?: unknown } | undefined;
    const policyRoot: RootKey | undefined = again ? previous.policyRoot : typeof offeredRoot?.keyId === 'string' && typeof offeredRoot.publicKey === 'string' ? { keyId: offeredRoot.keyId, publicKey: offeredRoot.publicKey } : undefined;
    await saveTeamLogin(context.home, { url: base, loginToken: String(poll['token']), sid: String(poll['sid']), expires: Number(poll['expires']), identity, policyKeys, ...(policyRoot === undefined ? {} : { policyRoot }), seen: again ? previous.seen : null });
    context.out(`Logged in as ${sanitizeForDisplay(identity.user)}${identity.ou.length === 0 ? '' : ` (${sanitizeForDisplay(identity.ou.join('/'))})`}.\n`);
    return 0;
  }
}

/** One hn session's link to the broker: its own token, fetched once and renewed shortly before it expires. */
class TeamSession {
  #token: { value: string; expires: number } | null = null;
  readonly login: TeamLogin;
  readonly session: string;
  readonly fetcher: typeof fetch;
  constructor(login: TeamLogin, session: string, fetcher: typeof fetch) {
    this.login = login;
    this.session = session;
    this.fetcher = fetcher;
  }

  async token(): Promise<string> {
    if (this.#token !== null && this.#token.expires - 60_000 > Date.now()) return this.#token.value;
    const issued = await call(this.fetcher, `${this.login.url}/v1/session`, { token: this.login.loginToken, session: this.login.sid, body: { session: this.session } });
    this.#token = { value: String(issued['token']), expires: Number(issued['expires']) };
    return this.#token.value;
  }
}

const sessions = new Map<string, TeamSession>();

function teamSession(login: TeamLogin, session: string, fetcher: typeof fetch = fetch): TeamSession {
  const key = `${login.url}\u0000${session}`;
  let found = sessions.get(key);
  if (found === undefined) sessions.set(key, (found = new TeamSession(login, session, fetcher)));
  return found;
}

/** This session's broker token, shared with the model route. */
export const teamToken = (login: TeamLogin, session: string): Promise<string> => teamSession(login, session).token();

export function teamProvider(login: TeamLogin, session: string): ModelProvider {
  const team = teamSession(login, session);
  return createBrokerProvider({ url: login.url, session, token: () => team.token() });
}

/**
 * The policy and identity for a session. Without `--team`: the local file (advisory) and the OS user. With it: the
 * broker's signed tree for the logged-in person, checked against the pinned keys and the newest serial seen, plus
 * the local file's layers, so the local file can still narrow.
 */
export async function sessionPolicy(options: { team?: TeamLogin }, home: string, session: string): Promise<{ policy: PolicySet; identity: Identity }> {
  const local = await loadLocalPolicy(home);
  if (options.team === undefined) return { policy: local, identity: { user: userInfo().username, ou: [], roles: [] } };
  const login = options.team;
  const team = teamSession(login, session);
  const bundle = await call(team.fetcher, `${login.url}/v1/policy`, { token: await team.token(), session });
  const trusted = await currentPolicyKeys(login, home, team.fetcher);
  const signer = typeof bundle['keyId'] === 'string' ? bundle['keyId'] : '';
  if (trusted.revoked.has(signer)) throw new HnError('POLICY_KEY_REVOKED', `The broker's policy is signed with the key "${sanitizeForDisplay(signer)}", which has been revoked. It is not applied. Tell whoever runs the broker to sign the policy with a current key.`);
  const { tree, seen } = verifyPolicyTree(bundle, trusted.keys, login.seen);
  if (login.seen === null || seen.serial !== login.seen.serial) await saveTeamLogin(home, { ...login, seen });
  return { policy: new PolicySet([...layersFor(tree, login.identity).layers, ...local.layers]), identity: login.identity };
}

/** `hn approvals` lists the requests this person may decide; `hn approvals approve|deny <id>` decides one. */
export async function runApprovalsCommand(context: LoginContext): Promise<number | null> {
  const [command, verb, id] = context.positionals;
  if (command !== 'approvals') return null;
  const login = await loadTeamLogin(context.home);
  const session = `approvals-${process.pid}-${Date.now()}`;
  const team = teamSession(login, session, context.fetch ?? fetch);
  const token = await team.token();
  if (verb === undefined) {
    const listed = await call(team.fetcher, `${login.url}/v1/approvals`, { token, session });
    const requests = Array.isArray(listed['requests']) ? (listed['requests'] as { id: string; requester: string; action: string }[]) : [];
    context.out(requests.length === 0 ? 'Nothing is waiting for you.\n' : requests.map((item) => `${sanitizeForDisplay(item.id)}  ${sanitizeForDisplay(item.requester)}  ${sanitizeForDisplay(item.action)}\n`).join(''));
    return 0;
  }
  if ((verb !== 'approve' && verb !== 'deny') || id === undefined) throw new HnError('BAD_COMMAND', 'hn approvals [approve|deny <id>]');
  const decided = await call(team.fetcher, `${login.url}/v1/approvals/decide`, { token, session, body: { id, decision: verb } });
  context.out(`Request ${sanitizeForDisplay(String(decided['id']))} is ${sanitizeForDisplay(String(decided['state']))}.\n`);
  return 0;
}

/**
 * In team mode every row the session's audit file writes is followed by its head (n, mac) being anchored on the
 * broker, newest only and in order, so a tail cut or edited later on this machine no longer matches the anchor.
 * Anchoring is best effort: a broker that cannot be reached never stops a tool call.
 */
export function anchoredAudit(file: AuditFile, team: TeamLogin | undefined, session: string): AuditFile {
  if (team === undefined) return file;
  let latest: AuditEntry | null = null;
  let sending: Promise<void> = Promise.resolve();
  const send = (): void => {
    sending = sending.then(async () => {
      const entry = latest;
      if (entry === null) return;
      latest = null;
      await call(fetch, `${team.url}/v1/audit/anchor`, { token: await teamToken(team, session), session, body: { n: entry.n, mac: entry.mac } }).catch(() => undefined);
    });
  };
  return {
    chain: file.chain,
    async record(type, data) {
      const entry = await file.record(type, data);
      latest = entry;
      send();
      return entry;
    },
  };
}
