import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { findHelper } from '@hn/operations';
import { downloadHelper, verifyCachedHelper, type HelperInstall } from '@hn/release';
import { loadOrCreateLogKey } from '@hn/session';
import { activeKeys, loadTrust, type KeyTrust } from '@hn/security';
import { resolvePaths } from '@hn/config';

/**
 * Where the sandbox helper comes from (Phase 9, decisions 3 to 5). From a source checkout it is the one built in the
 * repository, as before. From an installed release it is a verified download kept in `~/.hn/bin/<version>`: fetched
 * the first time a session needs it, checked against the key pinned in the installed package, and checked again
 * every time it is used. `HN_SANDBOX_BIN` still names one explicitly. A helper that fails its check is never run.
 */

/** Where releases are published; `HN_RELEASE_URL` names a mirror instead. Integrity does not depend on the host. */
export const DEFAULT_RELEASE_HOST = 'https://github.com/AkbarSheikh-debug/Haven-Harness/releases/download';

export interface ReleaseInfo {
  readonly root: string;
  readonly version: string;
  /** Key id to public key PEM, from the installed package's RELEASE-KEY.json. */
  readonly pinned: ReadonlyMap<string, string>;
  /** Ids of keys a root-signed roster revoked on this machine (Phase 15). Empty when the release has no root. */
  readonly revoked: ReadonlySet<string>;
  /** The trust state behind `pinned`, or null for a release that pins no root (its keys never change). */
  readonly trust: KeyTrust | null;
}

/** The root an installed release pins and the roster it shipped, or null when it pins no root (the keys then never change). */
export async function readPinnedRoot(root: string): Promise<{ root: { keyId: string; publicKey: string }; shipped?: unknown } | null> {
  let text: string;
  try {
    text = await readFile(join(root, 'RELEASE-ROOT.json'), 'utf8');
  } catch {
    return null;
  }
  let parsed: { keyId?: unknown; publicKey?: unknown };
  try {
    parsed = JSON.parse(text) as { keyId?: unknown; publicKey?: unknown };
  } catch {
    throw new HnError('TRUST_ROOT_DAMAGED', 'RELEASE-ROOT.json is not valid JSON, so this release cannot say which keys to trust.');
  }
  if (typeof parsed.keyId !== 'string' || typeof parsed.publicKey !== 'string') throw new HnError('TRUST_ROOT_DAMAGED', 'RELEASE-ROOT.json is not a root key, so this release cannot say which keys to trust.');
  const shipped = await readFile(join(root, 'RELEASE-ROSTER.json'), 'utf8').then((roster) => JSON.parse(roster) as unknown, () => undefined);
  return { root: { keyId: parsed.keyId, publicKey: parsed.publicKey }, ...(shipped === undefined ? {} : { shipped }) };
}

/** The installed release this process runs from, or null when it runs from source. */
export async function readReleaseInfo(env: NodeJS.ProcessEnv): Promise<ReleaseInfo | null> {
  const root = env['HN_RELEASE_ROOT'];
  if (root === undefined || root === '') return null;
  try {
    const version = (JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8')) as { version?: unknown }).version;
    const keys = JSON.parse(await readFile(join(root, 'RELEASE-KEY.json'), 'utf8')) as Record<string, unknown>;
    let pinned = new Map<string, string>();
    for (const [id, pem] of Object.entries(keys)) if (typeof pem === 'string') pinned.set(id, pem);
    if (typeof version !== 'string' || pinned.size === 0) return null;
    const trusted = await readPinnedRoot(root);
    if (trusted === null) return { root, version, pinned, revoked: new Set(), trust: null };
    // A damaged trust record throws here on purpose: nothing is trusted until it is repaired.
    const paths = resolvePaths(env);
    const trust = await loadTrust(join(paths.home, 'trust'), await loadOrCreateLogKey(paths.logKey), { purpose: 'release', root: trusted.root, pins: Object.fromEntries(pinned), ...(trusted.shipped === undefined ? {} : { shipped: trusted.shipped }) });
    pinned = activeKeys(trust);
    return { root, version, pinned, revoked: new Set(Object.keys(trust.revoked)), trust };
  } catch (error) {
    if (error instanceof HnError && (error.code.startsWith('TRUST_') || error.code === 'ROSTER_REFUSED')) throw error;
    return null;
  }
}

const platformName = (): string => `${process.platform}-${process.arch}`;

export const helperInstall = (info: ReleaseInfo, home: string): HelperInstall => ({ dir: join(home, 'bin', info.version), version: info.version, platform: platformName(), pinned: info.pinned });

export interface ResolveOptions {
  readonly env: NodeJS.ProcessEnv;
  readonly repoRoot?: string;
  readonly home: string;
  /** False for `hn doctor`, which reports and never fetches. */
  readonly download?: boolean;
  readonly log?: (text: string) => void;
  readonly fetch?: typeof fetch;
}

export const releaseBaseUrl = (env: NodeJS.ProcessEnv, version: string): string => (env['HN_RELEASE_URL'] !== undefined && env['HN_RELEASE_URL'] !== '' ? env['HN_RELEASE_URL'] : `${DEFAULT_RELEASE_HOST}/v${version}`);

/**
 * The helper to use, or null when there is none and none can be had (a source checkout that did not build it).
 * Throws when an installed release has no verified helper and cannot get one: nothing unverified is ever returned.
 */
export async function resolveHelper(options: ResolveOptions): Promise<string | null> {
  const { env, home } = options;
  const info = await readReleaseInfo(env);
  if (info === null) return findHelper({ env, home, ...(options.repoRoot === undefined ? {} : { repoRoot: options.repoRoot }) });
  // An explicit path is the person's own choice (their shell set it); everything else must be verified.
  const explicit = env['HN_SANDBOX_BIN'] === undefined ? null : await findHelper({ env: { HN_SANDBOX_BIN: env['HN_SANDBOX_BIN'] } });
  if (explicit !== null) return explicit;
  const install = helperInstall(info, home);
  const cached = await verifyCachedHelper(install);
  if (cached.ok) return cached.path;
  const log = options.log ?? ((text: string): void => void process.stderr.write(text));
  if (options.download === false) return null;
  if (env['HN_NO_DOWNLOAD'] !== undefined && env['HN_NO_DOWNLOAD'] !== '') throw new HnError('SANDBOX_HELPER_MISSING', `hn-sandbox ${info.version} for ${install.platform} is not installed and HN_NO_DOWNLOAD is set. Install it with: hn setup --from <folder holding the release's hn-sandbox files>`);
  if (cached.reason === 'refused') log(`hn: the stored hn-sandbox failed its check (${sanitizeForDisplay(cached.detail)}), so a fresh one is fetched.\n`);
  let base: string;
  try {
    base = releaseBaseUrl(env, info.version);
    log(`hn: fetching hn-sandbox ${info.version} for ${install.platform} from ${sanitizeForDisplay(new URL(base).origin)} (first use; the signature and SHA-256 are checked before it is kept or run).\n`);
  } catch {
    throw new HnError('SANDBOX_HELPER_MISSING', 'HN_RELEASE_URL is not an address.');
  }
  try {
    const path = await downloadHelper({ ...install, baseUrl: base, ...(options.fetch === undefined ? {} : { fetch: options.fetch }), onFetch: (what) => log(`hn: ${sanitizeForDisplay(what)}\n`) });
    log('hn: hn-sandbox verified and installed.\n');
    return path;
  } catch (error) {
    // Another hn may have installed it while this one tried.
    const again = await verifyCachedHelper(install);
    if (again.ok) return again.path;
    const reason = error instanceof Error ? error.message : String(error);
    throw new HnError('SANDBOX_HELPER_MISSING', `hn-sandbox ${info.version} for ${install.platform} could not be installed, and nothing was run: ${sanitizeForDisplay(reason)} Try again with a connection, or run: hn setup --from <folder holding the release's hn-sandbox files>`);
  }
}
