import { createHash, createPublicKey, randomBytes, sign, verify, type KeyObject } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { canonicalJson } from '@hn/security';
import { ReleaseError, type ReleaseSignature } from './manifest.ts';

/**
 * The sandbox helper's manifest (Phase 9, decisions 2 and 4). `hn-sandbox` is native code, so it is not in the npm
 * package; each release carries one binary per platform and one manifest naming them, with a size and a SHA-256
 * each, signed with the same ed25519 key as the release itself. The installed copy pins the public key. A helper
 * is accepted only when the manifest verifies, names this exact version, lists this platform, and the bytes match;
 * and a cached helper is checked again every time it is about to be used.
 */

export const HELPER_PLATFORMS = ['win32-x64', 'win32-arm64', 'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'] as const;
export type HelperPlatform = (typeof HELPER_PLATFORMS)[number];

/** A helper is a few megabytes; nothing near this cap is real. */
export const MAX_HELPER_BYTES = 64 * 1024 * 1024;

export interface HelperEntry {
  readonly file: string;
  readonly size: number;
  readonly sha256: string;
}

export interface HelperManifest {
  readonly format: 1;
  readonly name: 'hn-sandbox';
  readonly version: string;
  readonly created: string;
  readonly binaries: Readonly<Record<string, HelperEntry>>;
}

const VERSION = /^\d{1,6}\.\d{1,6}\.\d{1,6}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const sha256 = (data: Buffer): string => createHash('sha256').update(data).digest('hex');

export const helperAssetName = (version: string, platform: string): string => `hn-sandbox-${version}-${platform}${platform.startsWith('win32') ? '.exe' : ''}`;
export const helperManifestName = (version: string): string => `hn-sandbox-manifest-${version}.json`;
export const helperSignatureName = (version: string): string => `hn-sandbox-manifest-${version}.sig.json`;
/** What a cached helper is called inside its folder. */
export const cachedHelperName = (platform: string): string => (platform.startsWith('win32') ? 'hn-sandbox.exe' : 'hn-sandbox');

export const helperManifestBytes = (manifest: HelperManifest): Buffer => Buffer.from(`${canonicalJson(manifest)}\n`);

export function buildHelperManifest(binaries: readonly { platform: string; data: Buffer }[], meta: { version: string; created: string }): HelperManifest {
  if (!VERSION.test(meta.version)) throw new ReleaseError('A version is three whole numbers, such as 0.9.0.');
  const listed: Record<string, HelperEntry> = {};
  for (const { platform, data } of [...binaries].sort((a, b) => (a.platform < b.platform ? -1 : 1))) {
    if (!(HELPER_PLATFORMS as readonly string[]).includes(platform)) throw new ReleaseError(`${platform} is not a platform hn-sandbox is built for.`);
    if (listed[platform] !== undefined) throw new ReleaseError(`${platform} is listed twice.`);
    if (data.length === 0 || data.length > MAX_HELPER_BYTES) throw new ReleaseError(`The ${platform} helper has an impossible size.`);
    listed[platform] = { file: helperAssetName(meta.version, platform), size: data.length, sha256: sha256(data) };
  }
  if (Object.keys(listed).length === 0) throw new ReleaseError('A helper manifest lists at least one binary.');
  return { format: 1, name: 'hn-sandbox', version: meta.version, created: meta.created, binaries: listed };
}

export function signHelperManifest(manifest: HelperManifest, keyId: string, privateKey: KeyObject): ReleaseSignature {
  return { keyId, signature: sign(null, helperManifestBytes(manifest), privateKey).toString('base64') };
}

/**
 * Checks a helper manifest: the signature against a pinned key, the exact signed form, the version the running copy
 * expects (an older manifest cannot be replayed to pull an older helper), and every entry's shape, so a file name
 * can never be a path.
 */
export function verifyHelperManifest(bytes: Buffer, signature: unknown, pinned: ReadonlyMap<string, KeyObject | string>, expectVersion: string): HelperManifest {
  if (typeof signature !== 'object' || signature === null || typeof (signature as ReleaseSignature).keyId !== 'string' || typeof (signature as ReleaseSignature).signature !== 'string') throw new ReleaseError('The helper manifest has no signature.');
  const { keyId, signature: sig } = signature as ReleaseSignature;
  const pinnedKey = pinned.get(keyId);
  if (pinnedKey === undefined) throw new ReleaseError(`The helper manifest is signed with key "${keyId}", which this installation does not trust.`);
  let manifest: HelperManifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8')) as HelperManifest;
  } catch {
    throw new ReleaseError('The helper manifest is not JSON.');
  }
  if (typeof manifest !== 'object' || manifest === null) throw new ReleaseError('The helper manifest is malformed.');
  if (!bytes.equals(helperManifestBytes(manifest))) throw new ReleaseError('The helper manifest is not in its signed form.');
  const key = typeof pinnedKey === 'string' ? createPublicKey(pinnedKey) : pinnedKey;
  if (!verify(null, bytes, key, Buffer.from(sig, 'base64'))) throw new ReleaseError('The helper manifest signature does not match, so it was changed or signed by someone else.');
  if (manifest.format !== 1 || manifest.name !== 'hn-sandbox' || !VERSION.test(String(manifest.version)) || typeof manifest.binaries !== 'object' || manifest.binaries === null) throw new ReleaseError('The helper manifest is malformed.');
  if (manifest.version !== expectVersion) throw new ReleaseError(`The helper manifest is for ${manifest.version}, but this is ${expectVersion}, so it is refused.`);
  for (const [platform, entry] of Object.entries(manifest.binaries)) {
    if (!(HELPER_PLATFORMS as readonly string[]).includes(platform)) throw new ReleaseError(`The helper manifest lists ${platform}, which is not a platform hn-sandbox is built for.`);
    if (entry === null || typeof entry !== 'object' || entry.file !== helperAssetName(manifest.version, platform) || !Number.isInteger(entry.size) || entry.size < 1 || entry.size > MAX_HELPER_BYTES || !HEX64.test(String(entry.sha256))) throw new ReleaseError(`The helper manifest entry for ${platform} is malformed.`);
  }
  return manifest;
}

/** The manifest's entry for a platform, or an error that says which platforms the release does cover. */
export function helperEntry(manifest: HelperManifest, platform: string): HelperEntry {
  const entry = Object.hasOwn(manifest.binaries, platform) ? manifest.binaries[platform] : undefined;
  if (entry === undefined) throw new ReleaseError(`This release has no hn-sandbox for ${platform} (it has ${Object.keys(manifest.binaries).join(', ')}).`);
  return entry;
}

export function checkHelperBytes(entry: HelperEntry, data: Buffer): void {
  if (data.length !== entry.size) throw new ReleaseError(`The helper is ${data.length} bytes, but the signed manifest says ${entry.size}, so it is refused.`);
  if (sha256(data) !== entry.sha256) throw new ReleaseError('The helper does not match its signed SHA-256, so it is refused and not run.');
}

export interface HelperInstall {
  /** `~/.hn/bin/<version>`: one folder per version. */
  readonly dir: string;
  readonly version: string;
  readonly platform: string;
  readonly pinned: ReadonlyMap<string, KeyObject | string>;
}

const MANIFEST_FILE = 'manifest.json';
const SIGNATURE_FILE = 'manifest.sig.json';

async function putAtomic(path: string, data: Buffer, mode: number): Promise<void> {
  const staging = `${path}.${randomBytes(6).toString('hex')}.part`;
  try {
    await writeFile(staging, data, { flag: 'wx', mode });
    if (mode & 0o111) await chmod(staging, mode).catch(() => undefined);
    await rename(staging, path);
  } catch (error) {
    await rm(staging, { force: true });
    throw error;
  }
}

/**
 * Verifies a downloaded helper completely, and only then writes it: the manifest and signature first, the binary
 * last, each through a temporary name, so a failure leaves no helper under its final name.
 */
export async function installHelper(install: HelperInstall, manifestBytes: Buffer, signature: unknown, binary: Buffer): Promise<string> {
  const manifest = verifyHelperManifest(manifestBytes, signature, install.pinned, install.version);
  checkHelperBytes(helperEntry(manifest, install.platform), binary);
  await mkdir(install.dir, { recursive: true });
  const target = join(install.dir, cachedHelperName(install.platform));
  await rm(target, { force: true });
  await putAtomic(join(install.dir, MANIFEST_FILE), manifestBytes, 0o644);
  await putAtomic(join(install.dir, SIGNATURE_FILE), Buffer.from(JSON.stringify(signature)), 0o644);
  await putAtomic(target, binary, 0o755);
  return target;
}

export type CachedHelper = { readonly ok: true; readonly path: string } | { readonly ok: false; readonly reason: 'absent' | 'refused'; readonly detail: string };

/**
 * The cached helper, checked again: the stored manifest must still verify against the pinned key and the binary's
 * bytes must still match it. A binary swapped or edited after the download is refused here, before anything runs it.
 */
export async function verifyCachedHelper(install: HelperInstall): Promise<CachedHelper> {
  const path = join(install.dir, cachedHelperName(install.platform));
  let manifestBytes: Buffer;
  let signature: Buffer;
  let binary: Buffer;
  try {
    [manifestBytes, signature, binary] = await Promise.all([readFile(join(install.dir, MANIFEST_FILE)), readFile(join(install.dir, SIGNATURE_FILE)), readFile(path)]);
  } catch {
    return { ok: false, reason: 'absent', detail: `no verified helper in ${install.dir}` };
  }
  try {
    const manifest = verifyHelperManifest(manifestBytes, JSON.parse(signature.toString('utf8')) as unknown, install.pinned, install.version);
    checkHelperBytes(helperEntry(manifest, install.platform), binary);
    return { ok: true, path };
  } catch (error) {
    return { ok: false, reason: 'refused', detail: error instanceof Error ? error.message : String(error) };
  }
}
