import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { resolvePaths } from '@hn/config';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { auditWindows, keyFingerprint, loadTrust, offerRoster, parseRoster, readTrustRecord, signRoster, type KeyTrust, type RosterPurpose, type TrustSource } from '@hn/security';
import { loadOrCreateLogKey } from '@hn/session';
import { readPinnedRoot } from './helper.ts';
import { policyTrustSource } from './team.ts';

/**
 * `hn trust` (Phase 15, decision 9): the one place to see and change which signing keys this machine trusts.
 *
 *   hn trust keygen-root <folder>                                writes root-key.pem (keep it offline) and root-public.pem
 *   hn trust sign <draft.json> <root-key.pem> <root key id> <out.json>   signs a roster
 *   hn trust show [--purpose release|policy|audit]               what is trusted now, from which roster
 *   hn trust update <roster file or https URL>                   applies a roster (a revocation does not wait for a release)
 *
 * Only a person's command line runs it (the door refuses it inside a session). A roster is checked against the root
 * this machine already pins, never one the roster brings.
 */

export interface TrustContext {
  readonly positionals: readonly string[];
  readonly purpose?: string;
  readonly env: NodeJS.ProcessEnv;
  readonly out: (text: string) => void;
  readonly fetch?: typeof fetch;
}

const MAX_ROSTER = 1024 * 1024;
const PURPOSES: readonly RosterPurpose[] = ['release', 'policy', 'audit'];

export const trustFolder = (home: string): string => join(home, 'trust');

/** Where a purpose's pinned root and keys come from on this machine, or why there are none. */
export async function locateTrust(purpose: RosterPurpose, env: NodeJS.ProcessEnv): Promise<{ folder: string; key: Buffer; source: TrustSource } | { missing: string }> {
  const paths = resolvePaths(env);
  const key = await loadOrCreateLogKey(paths.logKey);
  const folder = trustFolder(paths.home);
  if (purpose === 'release') {
    const releaseRoot = env['HN_RELEASE_ROOT'];
    if (releaseRoot === undefined || releaseRoot === '') return { missing: 'this copy runs from source, so there is no installed release to hold a release roster' };
    const pinned = await readPinnedRoot(releaseRoot);
    if (pinned === null) return { missing: 'this release pins no root key (it was built without --root), so its signing keys never change' };
    const pins = JSON.parse(await readFile(join(releaseRoot, 'RELEASE-KEY.json'), 'utf8')) as Record<string, string>;
    return { folder, key, source: { purpose, root: pinned.root, pins, ...(pinned.shipped === undefined ? {} : { shipped: pinned.shipped }) } };
  }
  if (purpose === 'policy') {
    const source = await policyTrustSource(paths.home);
    return source === null ? { missing: 'you are not logged in to a team broker that pins a root key (hn login <broker>)' } : { folder, key, source };
  }
  return { missing: 'audit rosters are held by the auditor: use hn audit pin --root, and hn audit verify' };
}

async function loadRoster(source: string, fetcher: typeof fetch): Promise<unknown> {
  let text: string;
  if (/^[a-z]+:\/\//i.test(source)) {
    if (!source.startsWith('https://')) throw new HnError('TRUST_REFUSED', 'A roster is fetched over https only.');
    const response = await fetcher(source, { redirect: 'follow', signal: AbortSignal.timeout(60_000) });
    if (!response.ok) throw new HnError('TRUST_REFUSED', `Fetching ${sanitizeForDisplay(source)} answered ${response.status}.`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > MAX_ROSTER) throw new HnError('TRUST_REFUSED', 'The roster is too large.');
    text = bytes.toString('utf8');
  } else {
    const bytes = await readFile(source);
    if (bytes.length > MAX_ROSTER) throw new HnError('TRUST_REFUSED', 'The roster is too large.');
    text = bytes.toString('utf8');
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HnError('TRUST_REFUSED', 'The roster is not JSON.');
  }
}

const shortId = (pem: string): string => `root-${keyFingerprint(pem).slice(0, 16)}`;

/** Turns a draft (key files named by path) into a roster with the public keys inline. */
async function readDraft(path: string): Promise<Record<string, unknown>> {
  const base = dirname(resolve(path));
  const draft = JSON.parse(await readFile(path, 'utf8')) as Record<string, unknown>;
  const pem = async (entry: Record<string, unknown>, where: string): Promise<string> => {
    if (typeof entry['publicKey'] === 'string') return entry['publicKey'];
    if (typeof entry['publicKeyFile'] !== 'string') throw new HnError('BAD_COMMAND', `${where} needs a publicKey or a publicKeyFile.`);
    const file = isAbsolute(entry['publicKeyFile']) ? entry['publicKeyFile'] : join(base, entry['publicKeyFile']);
    return readFile(file, 'utf8');
  };
  const inline = async (list: unknown, name: string, optional: boolean): Promise<unknown> => {
    if (list === undefined && optional) return undefined;
    if (!Array.isArray(list)) throw new HnError('BAD_COMMAND', `The draft's ${name} must be a list.`);
    const out: unknown[] = [];
    for (const [index, item] of list.entries()) {
      if (typeof item !== 'object' || item === null) throw new HnError('BAD_COMMAND', `${name}[${index}] must be an object.`);
      const entry = item as Record<string, unknown>;
      const { publicKeyFile: _file, ...rest } = entry;
      void _file;
      const hasKey = entry['publicKey'] !== undefined || entry['publicKeyFile'] !== undefined;
      out.push(hasKey ? { ...rest, publicKey: await pem(entry, `${name}[${index}]`) } : rest);
    }
    return out;
  };
  const roster: Record<string, unknown> = { format: 1, purpose: draft['purpose'], serial: draft['serial'], issued: draft['issued'] ?? new Date().toISOString(), keys: await inline(draft['keys'], 'keys', false), revoked: (await inline(draft['revoked'], 'revoked', true)) ?? [] };
  if (draft['fromRow'] !== undefined) throw new HnError('BAD_COMMAND', 'fromRow belongs inside a key entry.');
  if (draft['successor'] !== undefined) {
    const next = draft['successor'] as Record<string, unknown>;
    roster['successor'] = { keyId: next['keyId'], publicKey: await pem(next, 'successor') };
  }
  return roster;
}

function describe(state: KeyTrust, purpose: RosterPurpose, out: (text: string) => void): void {
  const when = state.serial === 0 ? 'no roster applied yet: only the keys the package or login pinned' : `roster serial ${state.serial}`;
  out(`${purpose}: ${when}\n  root: ${sanitizeForDisplay(state.root.keyId)}\n`);
  if (purpose === 'audit') {
    for (const item of auditWindows(state)) out(`  audit key ${sanitizeForDisplay(item.keyId)}: rows ${item.from} to ${item.to === Number.MAX_SAFE_INTEGER ? 'now' : item.to}\n`);
  } else {
    for (const [id, item] of Object.entries(state.keys)) if (state.revoked[id] === undefined) out(`  trusted: ${sanitizeForDisplay(id)} (${keyFingerprint(item.publicKey).slice(0, 16)})\n`);
  }
  for (const [id, item] of Object.entries(state.revoked)) out(`  REVOKED: ${sanitizeForDisplay(id)}${item.afterRow === undefined ? '' : ` after row ${item.afterRow}`}: ${sanitizeForDisplay(item.reason)}\n`);
}

export async function runTrustCommand(context: TrustContext): Promise<number | null> {
  const [command, ...rest] = context.positionals;
  if (command !== 'trust') return null;
  const [verb, first, second, third, fourth] = rest;
  const { out } = context;
  if (verb === 'keygen-root') {
    if (first === undefined) throw new HnError('BAD_COMMAND', 'hn trust keygen-root <folder>');
    const pair = generateKeyPairSync('ed25519');
    const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    await mkdir(first, { recursive: true });
    await writeFile(join(first, 'root-key.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    await writeFile(join(first, 'root-public.pem'), publicPem, { flag: 'wx' });
    out(`Wrote ${join(first, 'root-key.pem')} (the root key: keep it offline and never commit it) and root-public.pem.\nSuggested root key id: ${shortId(publicPem)}. Tell people this id some other way than by the file you ship.\n`);
    return 0;
  }
  if (verb === 'sign') {
    if (first === undefined || second === undefined || third === undefined || fourth === undefined) throw new HnError('BAD_COMMAND', 'hn trust sign <draft.json> <root-key.pem> <root key id> <out.json>');
    const roster = await readDraft(first);
    const parsed = parseRoster(roster);
    const signed = signRoster(roster, third, createPrivateKey(await readFile(second)));
    await writeFile(fourth, `${JSON.stringify(signed, null, 2)}\n`);
    out(`Signed a ${parsed.purpose} roster, serial ${parsed.serial}, with ${parsed.keys.length} key(s) and ${parsed.revoked.length} revoked, in ${fourth}.\n`);
    return 0;
  }
  if (verb === 'show') {
    const wanted = context.purpose === undefined ? PURPOSES : PURPOSES.filter((item) => item === context.purpose);
    if (wanted.length === 0) throw new HnError('BAD_COMMAND', '--purpose is release, policy or audit.');
    for (const purpose of wanted) {
      const found = await locateTrust(purpose, context.env);
      if ('missing' in found) {
        if (context.purpose !== undefined) out(`${purpose}: ${found.missing}\n`);
        continue;
      }
      const record = await readTrustRecord(found.folder, purpose, found.key);
      const state = await loadTrust(found.folder, found.key, found.source);
      if (record === null) out(`${purpose}: there was no trust record on this machine, so it starts from the pinned keys. A revocation seen before would have been forgotten: fetch the roster again.\n`);
      describe(state, purpose, out);
    }
    return 0;
  }
  if (verb === 'update') {
    if (first === undefined) throw new HnError('BAD_COMMAND', 'hn trust update <roster file or https URL>');
    const signed = await loadRoster(first, context.fetch ?? fetch);
    const purpose = (signed as { roster?: { purpose?: unknown } } | null)?.roster?.purpose;
    if (typeof purpose !== 'string' || !PURPOSES.includes(purpose as RosterPurpose)) throw new HnError('TRUST_REFUSED', 'That file is not a signed roster.');
    const found = await locateTrust(purpose as RosterPurpose, context.env);
    if ('missing' in found) throw new HnError('TRUST_REFUSED', `This is a ${purpose} roster, but ${found.missing}.`);
    const result = await offerRoster(found.folder, found.key, found.source, signed);
    out(result.changed ? `Applied the ${purpose} roster (serial ${result.state.serial}).\n` : `The ${purpose} roster (serial ${result.state.serial}) was already in force.\n`);
    describe(result.state, purpose as RosterPurpose, out);
    return 0;
  }
  throw new HnError('BAD_COMMAND', 'hn trust keygen-root <folder> | sign <draft.json> <root-key.pem> <root key id> <out.json> | show [--purpose p] | update <roster file or https URL>');
}
