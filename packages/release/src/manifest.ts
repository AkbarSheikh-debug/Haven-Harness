import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import { HnError } from '@hn/core';
import { canonicalJson } from '@hn/security';
import { readTar, type TarFile } from './tar.ts';

/**
 * The release manifest: every file in the archive with its SHA-256, signed with ed25519. The signature
 * travels beside the archive; the manifest travels inside it. A release is accepted only when the signature checks
 * against a key the installed copy pins, and the archive holds exactly the files the manifest names, byte for byte.
 */

export class ReleaseError extends HnError {
  constructor(message: string) {
    super('RELEASE_INVALID', message);
  }
}

export interface ReleaseManifest {
  readonly format: 1;
  readonly name: string;
  readonly version: string;
  readonly platform: string;
  readonly created: string;
  readonly files: Readonly<Record<string, string>>;
}

export interface ReleaseSignature {
  readonly keyId: string;
  readonly signature: string;
}

export const MANIFEST_PATH = 'manifest.json';
const VERSION = /^(\d{1,6})\.(\d{1,6})\.(\d{1,6})$/;
const sha256 = (data: Buffer): string => createHash('sha256').update(data).digest('hex');

export function buildManifest(files: readonly TarFile[], meta: { name: string; version: string; platform: string; created: string }): ReleaseManifest {
  if (!VERSION.test(meta.version)) throw new ReleaseError('A version is three whole numbers, such as 0.8.0.');
  const listed: Record<string, string> = {};
  for (const file of [...files].sort((a, b) => (a.path < b.path ? -1 : 1))) {
    if (file.path === MANIFEST_PATH) throw new ReleaseError(`${MANIFEST_PATH} is reserved.`);
    listed[file.path] = sha256(file.data);
  }
  return { format: 1, ...meta, files: listed };
}

export const manifestBytes = (manifest: ReleaseManifest): Buffer => Buffer.from(`${canonicalJson(manifest)}\n`);

export function signManifest(manifest: ReleaseManifest, keyId: string, privateKey: KeyObject): ReleaseSignature {
  return { keyId, signature: sign(null, manifestBytes(manifest), privateKey).toString('base64') };
}

/** Compares two versions; negative when `a` is older. Anything that is not three whole numbers is an error. */
export function compareVersions(a: string, b: string): number {
  const left = VERSION.exec(a);
  const right = VERSION.exec(b);
  if (left === null || right === null) throw new ReleaseError(`Not a version: ${left === null ? a : b}.`);
  for (let index = 1; index <= 3; index += 1) {
    const diff = Number(left[index]) - Number(right[index]);
    if (diff !== 0) return diff;
  }
  return 0;
}

export interface VerifiedRelease {
  readonly manifest: ReleaseManifest;
  readonly files: readonly TarFile[];
}

/**
 * Checks an archive and its signature against pinned keys. The manifest is read from inside the archive, its
 * canonical bytes are what the signature covers, and then every file must match it exactly: none missing, none
 * extra, no hash different.
 */
export function verifyRelease(archive: Buffer, signature: unknown, pinned: ReadonlyMap<string, KeyObject | string>): VerifiedRelease {
  if (typeof signature !== 'object' || signature === null || typeof (signature as ReleaseSignature).keyId !== 'string' || typeof (signature as ReleaseSignature).signature !== 'string') throw new ReleaseError('The release has no signature.');
  const { keyId, signature: sig } = signature as ReleaseSignature;
  const pinnedKey = pinned.get(keyId);
  if (pinnedKey === undefined) throw new ReleaseError(`The release is signed with key "${keyId}", which this installation does not trust.`);
  const entries = readTar(archive);
  const manifestFile = entries.find((entry) => entry.path === MANIFEST_PATH);
  if (manifestFile === undefined) throw new ReleaseError('The archive has no manifest.');
  let manifest: ReleaseManifest;
  try {
    manifest = JSON.parse(manifestFile.data.toString('utf8')) as ReleaseManifest;
  } catch {
    throw new ReleaseError('The manifest is not JSON.');
  }
  // The signature covers the canonical form; the stored bytes must be exactly that form, so nothing hides in spacing.
  if (!manifestFile.data.equals(manifestBytes(manifest))) throw new ReleaseError('The manifest is not in its signed form.');
  const key = typeof pinnedKey === 'string' ? createPublicKey(pinnedKey) : pinnedKey;
  if (!verify(null, manifestFile.data, key, Buffer.from(sig, 'base64'))) throw new ReleaseError('The signature does not match the manifest, so the release was changed or signed by someone else.');
  if (manifest.format !== 1 || typeof manifest.files !== 'object' || manifest.files === null || !VERSION.test(String(manifest.version))) throw new ReleaseError('The manifest is malformed.');
  const files = entries.filter((entry) => entry.path !== MANIFEST_PATH);
  const listed = new Map(Object.entries(manifest.files));
  for (const file of files) {
    const want = listed.get(file.path);
    if (want === undefined) throw new ReleaseError(`The archive holds ${file.path}, which the manifest does not list.`);
    if (sha256(file.data) !== want) throw new ReleaseError(`${file.path} does not match its hash in the manifest.`);
    listed.delete(file.path);
  }
  if (listed.size > 0) throw new ReleaseError(`The archive is missing ${[...listed.keys()][0]}, which the manifest lists.`);
  return { manifest, files };
}

export interface SbomComponent {
  readonly name: string;
  readonly version: string;
  readonly license?: string;
  /** SHA-256 of the component's files as vendored, in path order. */
  readonly hash: string;
}

/** A CycloneDX 1.5 SBOM listing every vendored package, with a hash of exactly what was vendored. */
export function cycloneDx(meta: { name: string; version: string; created: string }, components: readonly SbomComponent[]): Record<string, unknown> {
  const purl = (component: SbomComponent): string => `pkg:npm/${component.name.startsWith('@') ? `%40${component.name.slice(1)}` : component.name}@${component.version}`;
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { timestamp: meta.created, component: { type: 'application', name: meta.name, version: meta.version } },
    components: [...components]
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .map((component) => ({ type: 'library', name: component.name, version: component.version, purl: purl(component), hashes: [{ alg: 'SHA-256', content: component.hash }], ...(component.license === undefined ? {} : { licenses: [{ license: { id: component.license } }] }) })),
  };
}
