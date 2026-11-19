import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import { PolicyError, PolicySet, canonicalJson, parsePolicy, type Identity, type Policy } from './policy.ts';

/**
 * The signed policy tree (Phase 8, decision 4). One bundle holds every layer an organisation writes: the org layer,
 * a layer per OU path, per role and per person. The broker picks the ones that apply to an identity and every one
 * must allow, so a deeper OU, an extra role or a personal layer can only narrow. A role widens nothing by being
 * held; it matters only where a rule names it (for example, who may approve).
 *
 * The serial only grows. A bundle older than one already seen is refused, and so is a different bundle with the
 * same serial, so an old, looser policy cannot be replayed to a broker or a client that has seen a newer one.
 */

export interface PolicyTree {
  readonly format: 1;
  readonly serial: number;
  readonly issued: string;
  readonly org: Policy;
  /** Keyed by OU path, outermost first, joined with `/`: `eng`, `eng/platform`. */
  readonly ou: ReadonlyMap<string, Policy>;
  readonly roles: ReadonlyMap<string, Policy>;
  readonly users: ReadonlyMap<string, Policy>;
}

export interface SignedPolicyTree {
  readonly tree: unknown;
  readonly keyId: string;
  /** Base64 ed25519 signature over the canonical text of `tree`. */
  readonly signature: string;
}

/** What a broker or client remembers about the newest bundle it accepted. */
export interface PolicySeen {
  readonly serial: number;
  readonly hash: string;
}

const TREE_KEYS = ['format', 'serial', 'issued', 'org', 'ou', 'roles', 'users'];
const SEGMENT = /^[^\u0000-\u001f\u007f-\u009f/\\]{1,200}$/;
const NAME = /^[^\u0000-\u001f\u007f-\u009f]{1,200}$/;
const MAX_LAYERS = 10_000;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

function layerMap(value: unknown, where: string, key: (name: string) => boolean): Map<string, Policy> {
  const out = new Map<string, Policy>();
  if (value === undefined) return out;
  if (!isRecord(value)) throw new PolicyError(`${where} must be an object of layers.`);
  const entries = Object.entries(value);
  if (entries.length > MAX_LAYERS) throw new PolicyError(`${where} has too many layers.`);
  for (const [name, layer] of entries) {
    if (!key(name)) throw new PolicyError(`${where} has a name that is not allowed: ${JSON.stringify(name)}.`);
    try {
      out.set(name, parsePolicy(layer));
    } catch (error) {
      throw new PolicyError(`${where}.${name}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return out;
}

/** Checks the shape of a tree. Unknown fields are errors, as in a single layer. */
export function parsePolicyTree(value: unknown): PolicyTree {
  if (!isRecord(value)) throw new PolicyError('A policy tree must be an object.');
  for (const key of Object.keys(value)) if (!TREE_KEYS.includes(key)) throw new PolicyError(`A policy tree has an unknown field "${key}".`);
  if (value['format'] !== 1) throw new PolicyError('A policy tree needs "format": 1.');
  const serial = value['serial'];
  if (typeof serial !== 'number' || !Number.isSafeInteger(serial) || serial < 1) throw new PolicyError('serial must be a whole number of 1 or more.');
  if (typeof value['issued'] !== 'string' || Number.isNaN(Date.parse(value['issued']))) throw new PolicyError('issued must be a date.');
  if (value['org'] === undefined) throw new PolicyError('A policy tree needs an org layer.');
  return {
    format: 1,
    serial,
    issued: value['issued'],
    org: parsePolicy(value['org']),
    ou: layerMap(value['ou'], 'ou', (name) => name.split('/').every((part) => SEGMENT.test(part))),
    roles: layerMap(value['roles'], 'roles', (name) => NAME.test(name)),
    users: layerMap(value['users'], 'users', (name) => NAME.test(name)),
  };
}

/** The layers for one person, outermost first: org, each OU from the top down, each role they hold, then their own. */
export function layersFor(tree: PolicyTree, identity: Identity): PolicySet {
  const layers: Policy[] = [tree.org];
  for (let depth = 1; depth <= identity.ou.length; depth += 1) {
    const layer = tree.ou.get(identity.ou.slice(0, depth).join('/'));
    if (layer !== undefined) layers.push(layer);
  }
  for (const role of [...identity.roles].sort()) {
    const layer = tree.roles.get(role);
    if (layer !== undefined) layers.push(layer);
  }
  const own = tree.users.get(identity.user);
  if (own !== undefined) layers.push(own);
  return new PolicySet(layers);
}

export const policyTreeHash = (tree: unknown): string => createHash('sha256').update(canonicalJson(tree)).digest('hex');

export function signPolicyTree(tree: unknown, keyId: string, privateKey: KeyObject): SignedPolicyTree {
  parsePolicyTree(tree);
  return { tree, keyId, signature: sign(null, Buffer.from(canonicalJson(tree)), privateKey).toString('base64') };
}

/**
 * Checks a bundle against the pinned keys and against the newest bundle already seen. Returns the tree and what
 * to remember; the caller stores `seen` only after it has started using the tree.
 */
export function verifyPolicyTree(bundle: unknown, pinned: ReadonlyMap<string, KeyObject | string>, last: PolicySeen | null): { tree: PolicyTree; seen: PolicySeen } {
  if (!isRecord(bundle) || Object.keys(bundle).length !== 3 || typeof bundle['keyId'] !== 'string' || typeof bundle['signature'] !== 'string' || !isRecord(bundle['tree'])) throw new PolicyError('Not a signed policy tree.');
  const pinnedKey = pinned.get(bundle['keyId']);
  if (pinnedKey === undefined) throw new PolicyError(`The signing key "${bundle['keyId']}" is not one this machine trusts.`);
  const key = typeof pinnedKey === 'string' ? createPublicKey(pinnedKey) : pinnedKey;
  if (!verify(null, Buffer.from(canonicalJson(bundle['tree'])), key, Buffer.from(bundle['signature'], 'base64'))) throw new PolicyError('The signature does not match the policy tree, so it was changed or signed by someone else.');
  const tree = parsePolicyTree(bundle['tree']);
  const hash = policyTreeHash(bundle['tree']);
  if (last !== null) {
    if (tree.serial < last.serial) throw new PolicyError(`This policy is serial ${tree.serial}, older than serial ${last.serial} already in use, so it is refused (an old policy cannot be replayed).`);
    if (tree.serial === last.serial && hash !== last.hash) throw new PolicyError(`A different policy with the same serial ${tree.serial} was already in use, so this one is refused.`);
  }
  return { tree, seen: { serial: tree.serial, hash } };
}
