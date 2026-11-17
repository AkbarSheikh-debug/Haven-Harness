import { createHmac, createPublicKey, sign, timingSafeEqual, verify, type KeyObject } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import { canonicalForRules } from './rules.ts';
import type { GateCall, Mode } from './gate.ts';

/**
 * Policy and identity. A policy file on a laptop does not bind the laptop's owner, so what is advisory and
 * what is enforced depends on where the credential lives: this file is the local, advisory half (it stops the
 * agent, and mistakes, not the person at the keyboard), and the signing and capability types below are what the
 * team-mode broker enforces later. Layers are org, then OU, team, role, user, and a call must be allowed by
 * every one of them, so a lower layer can only narrow what a higher one allows.
 */

export class PolicyError extends HnError {
  constructor(message: string) {
    super('POLICY_INVALID', message);
  }
}

export interface Identity {
  readonly user: string;
  /** The organisational path, outermost first. */
  readonly ou: readonly string[];
  readonly roles: readonly string[];
}

export interface Policy {
  readonly version: 1;
  readonly name?: string;
  readonly tools?: { readonly allow?: readonly string[]; readonly deny?: readonly string[] };
  /** Project-relative path patterns that may never be read or written. */
  readonly paths?: { readonly deny?: readonly string[] };
  readonly mcp?: { readonly allow?: readonly string[] };
  readonly models?: { readonly allow?: readonly string[] };
  /** The most permissive mode this layer allows. */
  readonly maxMode?: Mode;
  readonly budget?: { readonly maxCostUsd?: number; readonly maxTokens?: number };
  /** Who may answer an approval. Others can still ask, but their answer does not count. */
  readonly approvers?: { readonly users?: readonly string[]; readonly roles?: readonly string[] };
}

const MODE_RANK: Readonly<Record<Mode, number>> = { 'read-only': 0, plan: 1, safe: 2, 'accept-edits': 3, smart: 4, 'dont-ask': 5, yolo: 6 };
const KEYS = new Set(['version', 'name', 'tools', 'paths', 'mcp', 'models', 'maxMode', 'budget', 'approvers']);
const MAX_BYTES = 256 * 1024;

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

function strings(value: unknown, where: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item === '' || item.length > 200)) throw new PolicyError(`${where} must be a list of short non-empty strings.`);
  return value as string[];
}

function only(value: unknown, keys: readonly string[], where: string): Record<string, unknown> {
  if (!isRecord(value)) throw new PolicyError(`${where} must be an object.`);
  for (const key of Object.keys(value)) if (!keys.includes(key)) throw new PolicyError(`${where} has an unknown field "${key}".`);
  return value;
}

/** Checks one layer. Anything unknown is an error, never ignored, so a typo cannot quietly leave a rule off. */
export function parsePolicy(value: unknown): Policy {
  if (!isRecord(value)) throw new PolicyError('A policy must be an object.');
  for (const key of Object.keys(value)) if (!KEYS.has(key)) throw new PolicyError(`A policy has an unknown field "${key}".`);
  if (value['version'] !== 1) throw new PolicyError('A policy needs "version": 1.');
  const out: { -readonly [K in keyof Policy]: Policy[K] } = { version: 1 };
  if (value['name'] !== undefined) {
    if (typeof value['name'] !== 'string') throw new PolicyError('name must be a string.');
    out.name = value['name'];
  }
  if (value['tools'] !== undefined) {
    const tools = only(value['tools'], ['allow', 'deny'], 'tools');
    out.tools = { ...(tools['allow'] === undefined ? {} : { allow: strings(tools['allow'], 'tools.allow') as string[] }), ...(tools['deny'] === undefined ? {} : { deny: strings(tools['deny'], 'tools.deny') as string[] }) };
  }
  if (value['paths'] !== undefined) out.paths = { deny: strings(only(value['paths'], ['deny'], 'paths')['deny'], 'paths.deny') ?? [] };
  if (value['mcp'] !== undefined) out.mcp = { allow: strings(only(value['mcp'], ['allow'], 'mcp')['allow'], 'mcp.allow') ?? [] };
  if (value['models'] !== undefined) out.models = { allow: strings(only(value['models'], ['allow'], 'models')['allow'], 'models.allow') ?? [] };
  if (value['maxMode'] !== undefined) {
    if (typeof value['maxMode'] !== 'string' || !(value['maxMode'] in MODE_RANK)) throw new PolicyError(`maxMode must be one of: ${Object.keys(MODE_RANK).join(', ')}.`);
    out.maxMode = value['maxMode'] as Mode;
  }
  if (value['budget'] !== undefined) {
    const budget = only(value['budget'], ['maxCostUsd', 'maxTokens'], 'budget');
    for (const [key, item] of Object.entries(budget)) if (typeof item !== 'number' || !Number.isFinite(item) || item < 0) throw new PolicyError(`budget.${key} must be a number of zero or more.`);
    out.budget = budget as Policy['budget'] & object;
  }
  if (value['approvers'] !== undefined) {
    const approvers = only(value['approvers'], ['users', 'roles'], 'approvers');
    out.approvers = { ...(approvers['users'] === undefined ? {} : { users: strings(approvers['users'], 'approvers.users') as string[] }), ...(approvers['roles'] === undefined ? {} : { roles: strings(approvers['roles'], 'approvers.roles') as string[] }) };
  }
  return out;
}

/** A pattern where `*` matches any run of characters and, for paths, `**` also crosses folders. No regular expression syntax gets through. */
function matcher(pattern: string, kind: 'name' | 'path'): RegExp {
  // `dir/**` means the folder and everything in it, so naming the folder itself is covered too.
  const folder = kind === 'path' && pattern.endsWith('/**');
  const body = folder ? pattern.slice(0, -3) : pattern;
  const parts = body.split(/(\*\*|\*)/).map((part) => (part === '**' ? '.*' : part === '*' ? (kind === 'path' ? '[^/]*' : '.*') : part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')));
  return new RegExp(`^${parts.join('')}${folder ? '(?:/.*)?' : ''}$`, 'i');
}

const hits = (patterns: readonly string[] | undefined, value: string, kind: 'name' | 'path'): boolean => (patterns ?? []).some((pattern) => matcher(pattern, kind).test(value));

/** The layers that apply to one person, outermost first. Every question is answered by asking every layer. */
export class PolicySet {
  readonly layers: readonly Policy[];

  constructor(layers: readonly Policy[]) {
    this.layers = layers;
  }

  /** Allowed only if no layer denies the tool and every layer that lists allowed tools lists it. */
  toolReason(tool: string): string | null {
    for (const layer of this.layers) {
      if (hits(layer.tools?.deny, tool, 'name')) return `${tool} is denied by policy${layer.name === undefined ? '' : ` (${layer.name})`}.`;
      if (layer.tools?.allow !== undefined && !hits(layer.tools.allow, tool, 'name')) return `${tool} is not on the tool list${layer.name === undefined ? '' : ` of ${layer.name}`}.`;
    }
    return null;
  }

  /** A path as the model wrote it, relative to the project. Spelled the way the rules see it: slashes, case, NTFS tricks. */
  pathReason(path: string): string | null {
    const spelled = canonicalForRules(path).join('/');
    for (const layer of this.layers) if (hits(layer.paths?.deny, spelled, 'path')) return `${path} is denied by policy${layer.name === undefined ? '' : ` (${layer.name})`}.`;
    return null;
  }

  mcpAllowed(server: string): boolean {
    return this.layers.every((layer) => layer.mcp?.allow === undefined || hits(layer.mcp.allow, server, 'name'));
  }

  modelAllowed(model: string): boolean {
    return this.layers.every((layer) => layer.models?.allow === undefined || hits(layer.models.allow, model, 'name'));
  }

  /** The most permissive mode every layer allows. */
  maxMode(): Mode {
    let highest: Mode = 'yolo';
    for (const layer of this.layers) if (layer.maxMode !== undefined && MODE_RANK[layer.maxMode] < MODE_RANK[highest]) highest = layer.maxMode;
    return highest;
  }

  modeAllowed(mode: Mode): boolean {
    return MODE_RANK[mode] <= MODE_RANK[this.maxMode()];
  }

  budget(): { maxCostUsd?: number; maxTokens?: number } {
    const out: { maxCostUsd?: number; maxTokens?: number } = {};
    for (const layer of this.layers) {
      if (layer.budget?.maxCostUsd !== undefined) out.maxCostUsd = Math.min(out.maxCostUsd ?? Infinity, layer.budget.maxCostUsd);
      if (layer.budget?.maxTokens !== undefined) out.maxTokens = Math.min(out.maxTokens ?? Infinity, layer.budget.maxTokens);
    }
    return out;
  }

  /** Whether this person's answer to an approval counts. Every layer that names approvers must include them. */
  mayApprove(identity: Identity): boolean {
    return this.layers.every((layer) => {
      const approvers = layer.approvers;
      if (approvers === undefined) return true;
      return (approvers.users ?? []).includes(identity.user) || (approvers.roles ?? []).some((role) => identity.roles.includes(role));
    });
  }

  /** The deny-only check for gate step 1. It can stop a call and can never allow one. */
  guard(): (call: GateCall) => string | null {
    return (call) => {
      const tool = this.toolReason(call.tool);
      if (tool !== null) return tool;
      for (const use of call.paths) {
        const path = this.pathReason(use.path);
        if (path !== null) return path;
      }
      return null;
    };
  }
}

/** Reads `<home>/policy.json`: one layer, or `{"layers": [...]}`. Missing means no policy. Advisory: it binds the agent, not the owner. */
export async function loadLocalPolicy(home: string): Promise<PolicySet> {
  let text: string;
  try {
    text = await readFile(join(home, 'policy.json'), 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new PolicySet([]);
    throw error;
  }
  if (Buffer.byteLength(text) > MAX_BYTES) throw new PolicyError('policy.json is too large.');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new PolicyError('policy.json is not valid JSON.');
  }
  if (isRecord(parsed) && 'layers' in parsed) {
    if (Object.keys(parsed).length !== 1 || !Array.isArray(parsed['layers'])) throw new PolicyError('Expected {"layers": [...]} and nothing else.');
    return new PolicySet(parsed['layers'].map(parsePolicy));
  }
  return new PolicySet([parsePolicy(parsed)]);
}

export interface SignedPolicy {
  readonly policy: Policy;
  readonly keyId: string;
  /** Base64 ed25519 signature over the canonical policy text. */
  readonly signature: string;
}

const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
};

export function signPolicy(policy: Policy, keyId: string, privateKey: KeyObject): SignedPolicy {
  return { policy, keyId, signature: sign(null, Buffer.from(canonical(policy)), privateKey).toString('base64') };
}

/** Checks a signed bundle against the public keys the operator pinned. An unknown key id, a bad signature or a changed policy all fail. */
export function verifySignedPolicy(bundle: unknown, pinned: ReadonlyMap<string, KeyObject | string>): Policy {
  if (!isRecord(bundle) || typeof bundle['keyId'] !== 'string' || typeof bundle['signature'] !== 'string' || !isRecord(bundle['policy'])) throw new PolicyError('Not a signed policy.');
  const pinnedKey = pinned.get(bundle['keyId']);
  if (pinnedKey === undefined) throw new PolicyError(`The signing key "${bundle['keyId']}" is not one this machine trusts.`);
  const key = typeof pinnedKey === 'string' ? createPublicKey(pinnedKey) : pinnedKey;
  if (!verify(null, Buffer.from(canonical(bundle['policy'])), key, Buffer.from(bundle['signature'], 'base64'))) throw new PolicyError('The signature does not match the policy, so it was changed or signed by someone else.');
  return parsePolicy(bundle['policy']);
}

/**
 * Capability tokens, macaroon style. The signature is a chain of HMACs, one per caveat, so a holder can add a
 * caveat (narrow the token) but cannot remove one or widen it, because that would need the key. Every token must
 * name its audience and session, so a stolen one is useless anywhere else, and must carry an expiry.
 */
export interface Capability {
  readonly id: string;
  readonly caveats: readonly string[];
  readonly sig: string;
}

const link = (key: Uint8Array | string, data: string): string => createHmac('sha256', key).update(data).digest('hex');

export function mintCapability(rootKey: Uint8Array, id: string, caveats: readonly string[]): Capability {
  let sig = link(rootKey, id);
  for (const caveat of caveats) sig = link(sig, caveat);
  return { id, caveats, sig };
}

/** Adds a restriction. This is the only thing a holder can do to a token, and it can only narrow it. */
export function attenuateCapability(capability: Capability, caveat: string): Capability {
  return { id: capability.id, caveats: [...capability.caveats, caveat], sig: link(capability.sig, caveat) };
}

export interface CapabilityContext {
  readonly audience: string;
  readonly session: string;
  readonly now: number;
  readonly tool?: string;
  readonly path?: string;
  /** Nonces already used. A token id seen before is refused, and a fresh one is added. */
  readonly seen?: Set<string>;
}

export type CapabilityVerdict = { readonly ok: true } | { readonly ok: false; readonly reason: string };

const refuse = (reason: string): CapabilityVerdict => ({ ok: false, reason });

export function verifyCapability(rootKey: Uint8Array, capability: Capability, context: CapabilityContext): CapabilityVerdict {
  let sig = link(rootKey, capability.id);
  for (const caveat of capability.caveats) sig = link(sig, caveat);
  const expected = Buffer.from(sig, 'hex');
  const given = Buffer.from(capability.sig, 'hex');
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return refuse('The token was changed, or was not issued by this key.');

  const values = (name: string): string[] => capability.caveats.filter((caveat) => caveat.startsWith(`${name}=`)).map((caveat) => caveat.slice(name.length + 1));
  for (const required of ['aud', 'sid', 'exp']) if (values(required).length === 0) return refuse(`The token has no ${required} restriction, so it is not bound to one audience, one session and a time.`);
  if (!values('aud').every((aud) => aud === context.audience)) return refuse('The token was issued for a different audience.');
  if (!values('sid').every((sid) => sid === context.session)) return refuse('The token belongs to a different session.');
  if (!values('exp').every((exp) => Number(exp) > context.now)) return refuse('The token has expired.');
  const tools = values('tool');
  if (context.tool !== undefined && tools.length > 0 && !tools.every((list) => list.split(',').some((pattern) => matcher(pattern, 'name').test(context.tool as string)))) return refuse('The token does not cover this tool.');
  const paths = values('path');
  if (context.path !== undefined && paths.length > 0 && !paths.every((prefix) => context.path === prefix || (context.path as string).startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))) return refuse('The token does not cover this path.');
  for (const caveat of capability.caveats) if (!/^(aud|sid|exp|tool|path)=/.test(caveat)) return refuse(`The token has a restriction this version does not understand (${caveat.split('=')[0]}), so it is refused.`);
  if (context.seen !== undefined) {
    if (context.seen.has(capability.id)) return refuse('This token was already used.');
    context.seen.add(capability.id);
  }
  return { ok: true };
}
