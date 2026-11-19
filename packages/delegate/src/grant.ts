import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdir, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { MODES, type Mode } from '@hn/security';

/** How long a signed grant may wait before the child presents it. A child starts in well under a second. */
export const GRANT_TTL_MS = 2 * 60_000;

/**
 * Tools a child never gets, whatever its role says: memory (the plan blocks it), delegation (depth 1), asking the
 * user (children cannot), scheduling, and the script runners that could start children of their own.
 */
export const BLOCKED_IN_CHILDREN: ReadonlySet<string> = new Set([
  'memory', 'memory_search', 'memory_get',
  'subagent', 'spawn_agent', 'send_message', 'interrupt_agent', 'list_agents', 'wait_agent',
  'ask_user_question', 'exit_plan_mode',
  'workflow', 'run_code', 'ralph',
  'schedule_create', 'schedule_edit', 'schedule_list', 'schedule_view', 'schedule_delete',
  'team_create', 'team_spawn', 'team_task', 'team_message',
]);

/** Tools a child of an unattended `yolo` parent may run without a box: file edits only. A shell below tier 3 is refused anyway. */
export const UNATTENDED_CHILD_ALLOW: readonly string[] = ['write_file', 'edit_file'];

/** What a parent hands its child. Everything here can only narrow what the parent itself has. */
export interface GrantBody {
  readonly v: 1;
  readonly parent: string;
  readonly child: string;
  readonly mode: Mode;
  /** The dont-ask allowlist: never wider than the parent's own. */
  readonly allow: readonly string[];
  /** Tool names the child is offered. Null means every tool a child may have. */
  readonly tools: readonly string[] | null;
  readonly maxIterations: number;
  readonly tokenBudget: number;
  readonly role: { readonly name: string; readonly hash: string; readonly body: string };
  /** Set when the child must send approval cards and rate-limit requests to its parent over the channel. */
  readonly channel: boolean;
  /** The parent's project key: a child working in a clone still files its log beside its parent's. */
  readonly project?: string;
  /** Set for a team member: its name on the roster, so its team tools speak for it and nobody else. */
  readonly team?: { readonly name: string };
  readonly expires: number;
  readonly nonce: string;
}

const B64 = /^[A-Za-z0-9_-]+$/;

function mac(payload: string, key: Uint8Array): string {
  return createHmac('sha256', key).update(`hn-grant-v1\n${payload}`).digest('base64url');
}

export function newNonce(): string {
  return randomBytes(18).toString('base64url');
}

/** `payload.mac`, both base64url. Only a holder of the log key can make one. */
export function signGrant(body: GrantBody, key: Uint8Array): string {
  const payload = Buffer.from(JSON.stringify(body), 'utf8').toString('base64url');
  return `${payload}.${mac(payload, key)}`;
}

export type GrantCheck = { readonly ok: true; readonly grant: GrantBody } | { readonly ok: false; readonly why: string };

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(item));
}

function shapeProblem(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return 'not an object';
  const body = value as Record<string, unknown>;
  const keys = ['v', 'parent', 'child', 'mode', 'allow', 'tools', 'maxIterations', 'tokenBudget', 'role', 'channel', 'project', 'team', 'expires', 'nonce'];
  if (Object.keys(body).some((name) => !keys.includes(name))) return 'unknown field';
  if (body['v'] !== 1) return 'unknown version';
  for (const name of ['parent', 'child']) if (typeof body[name] !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(body[name] as string)) return `bad ${name}`;
  if (typeof body['mode'] !== 'string' || !(MODES as readonly string[]).includes(body['mode'])) return 'bad mode';
  if (!isStringList(body['allow'])) return 'bad allow';
  if (body['tools'] !== null && !isStringList(body['tools'])) return 'bad tools';
  for (const name of ['maxIterations', 'tokenBudget', 'expires']) if (!Number.isSafeInteger(body[name]) || (body[name] as number) < 1) return `bad ${name}`;
  const role = body['role'] as Record<string, unknown> | null;
  if (typeof role !== 'object' || role === null || typeof role['name'] !== 'string' || typeof role['hash'] !== 'string' || typeof role['body'] !== 'string') return 'bad role';
  if (typeof body['channel'] !== 'boolean') return 'bad channel';
  if (body['project'] !== undefined && (typeof body['project'] !== 'string' || !/^[0-9a-f]{16}$/.test(body['project']))) return 'bad project';
  const team = body['team'] as Record<string, unknown> | undefined;
  if (team !== undefined && (typeof team !== 'object' || team === null || typeof team['name'] !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(team['name']) || Object.keys(team).length !== 1)) return 'bad team';
  if (typeof body['nonce'] !== 'string' || !B64.test(body['nonce']) || body['nonce'].length < 16) return 'bad nonce';
  return null;
}

export interface VerifyOptions {
  readonly key: Uint8Array;
  readonly now?: number;
  /** The parent session this child was started by, from its environment. A grant for another parent is refused. */
  readonly parent: string;
  /** Records the nonce once. Resolves false when it was used before. */
  readonly useNonce: (nonce: string) => Promise<boolean>;
}

/** Checks a grant fully before anything in it is believed: signature, shape, parent, expiry, then the one-time nonce. */
export async function verifyGrant(text: string, options: VerifyOptions): Promise<GrantCheck> {
  const [payload, signature, extra] = text.split('.');
  if (payload === undefined || signature === undefined || extra !== undefined || !B64.test(payload) || !B64.test(signature)) return { ok: false, why: 'it is not a grant' };
  const expected = Buffer.from(mac(payload, options.key));
  const given = Buffer.from(signature);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return { ok: false, why: 'its signature does not verify' };
  let body: unknown;
  try {
    body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, why: 'it is not readable' };
  }
  const problem = shapeProblem(body);
  if (problem !== null) return { ok: false, why: `it is malformed (${problem})` };
  const grant = body as GrantBody;
  if (grant.parent !== options.parent) return { ok: false, why: 'it was made for a different parent session' };
  if (grant.expires <= (options.now ?? Date.now())) return { ok: false, why: 'it has expired' };
  if (!(await options.useNonce(grant.nonce))) return { ok: false, why: 'it was already used' };
  return { ok: true, grant };
}

/**
 * The one-time nonce store: one empty file per nonce, created exclusively, so two children racing with one grant
 * cannot both win. Files older than a day are swept, since a grant is dead after two minutes anyway.
 */
export function nonceStore(directory: string): (nonce: string) => Promise<boolean> {
  return async (nonce) => {
    if (!B64.test(nonce)) return false;
    await mkdir(directory, { recursive: true, mode: 0o700 });
    try {
      await writeFile(join(directory, nonce), '', { flag: 'wx', mode: 0o600 });
    } catch {
      return false;
    }
    void sweep(directory).catch(() => undefined);
    return true;
  };
}

async function sweep(directory: string): Promise<void> {
  const cutoff = Date.now() - 86_400_000;
  for (const name of await readdir(directory)) {
    const path = join(directory, name);
    if ((await stat(path)).mtimeMs < cutoff) await rm(path, { force: true });
  }
}

type Chain = 'read-only' | 'safe' | 'accept-edits';
const CHAIN: readonly Chain[] = ['read-only', 'safe', 'accept-edits'];

export interface Narrowed {
  readonly mode: Mode;
  readonly allow: readonly string[];
}

/**
 * The child's mode: never more than the parent's, never more than the role's ceiling (invariant 4). Plan becomes
 * read-only, because leaving plan mode needs a person and a child cannot ask. `smart` becomes `safe`, because the
 * guardian stays with the parent. Under `dont-ask` a child never asks either, so it keeps the parent's allowlist (cut
 * to the role's tools) or, for a role that would ask, `safe`, whose asks reach a parent that answers no one. Below
 * tier 3 there is no `yolo`.
 */
export function narrowMode(parent: Mode, ceiling: Mode, options: { readonly tier: number; readonly parentAllow: readonly string[]; readonly roleTools: readonly string[] | null }): Narrowed {
  const cut = (names: readonly string[]): string[] => names.filter((name) => (options.roleTools === null || options.roleTools.includes(name)) && !BLOCKED_IN_CHILDREN.has(name));
  if (parent === 'read-only' || parent === 'plan' || ceiling === 'read-only' || ceiling === 'plan') return { mode: 'read-only', allow: [] };
  if (parent === 'dont-ask') {
    if (ceiling === 'dont-ask' || ceiling === 'yolo') return { mode: 'dont-ask', allow: cut(options.parentAllow) };
    return { mode: 'safe', allow: [] };
  }
  if (parent === 'yolo') {
    if (ceiling === 'yolo') return options.tier >= 3 ? { mode: 'yolo', allow: [] } : { mode: 'dont-ask', allow: cut(UNATTENDED_CHILD_ALLOW) };
    if (ceiling === 'dont-ask') return { mode: 'dont-ask', allow: cut(UNATTENDED_CHILD_ALLOW) };
    return { mode: ceiling === 'smart' ? 'safe' : ceiling, allow: [] };
  }
  // safe, accept-edits and smart parents: the lower of the two on read-only < safe < accept-edits.
  const p: Chain = parent === 'smart' ? 'safe' : (parent as Chain);
  const c: Chain = ceiling === 'smart' ? 'safe' : ceiling === 'dont-ask' || ceiling === 'yolo' ? 'accept-edits' : (ceiling as Chain);
  return { mode: CHAIN[Math.min(CHAIN.indexOf(p), CHAIN.indexOf(c))] as Mode, allow: [] };
}

/** The child's tools: what the parent has, cut to the role's list, minus everything children never get. */
export function childTools(parentTools: readonly string[], roleTools: readonly string[] | null): string[] {
  return parentTools.filter((name) => !BLOCKED_IN_CHILDREN.has(name) && (roleTools === null || roleTools.includes(name)));
}
