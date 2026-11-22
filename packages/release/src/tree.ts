import { createHash, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { MANIFEST_PATH, manifestBytes, type ReleaseManifest, type ReleaseSignature } from './manifest.ts';
import { safeArchivePath } from './tar.ts';

/**
 * Checks an installed copy against the manifest it shipped with (Phase 9, decision 7). The npm package carries its
 * manifest and the signature over it; this verifies the signature with the key the package pins, then every listed
 * file's hash. Because the key travels with the package, this proves the files are what was signed, not who put
 * the package there: that is npm's job (and, from the first release, its provenance statement). Extra files are not
 * judged inside the third-party packages (npm adds its own lock file there), but nothing may be added to the launcher
 * folder, the package's top level or our own `@hn` code: a file there that the manifest does not list is reported.
 */

export interface TreeCheck {
  readonly ok: boolean;
  readonly version: string;
  readonly checked: number;
  readonly problems: readonly string[];
}

export const SIGNATURE_PATH = 'manifest.sig.json';

/** Keys as this machine trusts them now, when a root-signed roster may have changed the package's own pins (Phase 15). */
export interface TreeTrust {
  readonly keys: ReadonlyMap<string, string>;
  readonly revoked: ReadonlySet<string>;
}

export async function verifyInstalledTree(root: string, trust?: TreeTrust): Promise<TreeCheck> {
  const fail = (problem: string, version = 'unknown'): TreeCheck => ({ ok: false, version, checked: 0, problems: [problem] });
  let bytes: Buffer;
  let signature: ReleaseSignature;
  let keys: Record<string, string>;
  try {
    [bytes, signature, keys] = await Promise.all([readFile(join(root, MANIFEST_PATH)), readFile(join(root, SIGNATURE_PATH), 'utf8').then((text) => JSON.parse(text) as ReleaseSignature), readFile(join(root, 'RELEASE-KEY.json'), 'utf8').then((text) => JSON.parse(text) as Record<string, string>)]);
  } catch {
    return fail('the manifest, its signature or the pinned key is missing or unreadable');
  }
  let manifest: ReleaseManifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8')) as ReleaseManifest;
  } catch {
    return fail('the manifest is not JSON');
  }
  if (trust !== undefined && typeof signature?.keyId === 'string' && trust.revoked.has(signature.keyId)) return fail(`the manifest is signed with the key "${signature.keyId}", which has been revoked. Install a release signed by a current key (hn update), then run: hn trust show`, String(manifest.version));
  const pem = typeof signature?.keyId === 'string' ? (trust === undefined ? keys[signature.keyId] : trust.keys.get(signature.keyId)) : undefined;
  if (pem === undefined || typeof signature.signature !== 'string') return fail('the manifest is signed with a key this copy does not pin', String(manifest.version));
  if (!bytes.equals(manifestBytes(manifest))) return fail('the manifest is not in its signed form', String(manifest.version));
  let good = false;
  try {
    good = verify(null, bytes, createPublicKey(pem), Buffer.from(signature.signature, 'base64'));
  } catch {
    good = false;
  }
  if (!good) return fail('the manifest signature does not match', String(manifest.version));
  const problems: string[] = [];
  let checked = 0;
  for (const [path, want] of Object.entries(manifest.files ?? {})) {
    if (!safeArchivePath(path)) {
      problems.push(`${path} is not a path inside the package`);
      continue;
    }
    checked += 1;
    try {
      if (createHash('sha256').update(await readFile(join(root, ...path.split('/')))).digest('hex') !== want) problems.push(`${path} was changed`);
    } catch {
      problems.push(`${path} is missing`);
    }
  }
  const listed = new Set(Object.keys(manifest.files ?? {}));
  const top = new Set([...listed].map((path) => path.split('/')[0] as string).concat([MANIFEST_PATH, SIGNATURE_PATH, 'node_modules']));
  const extras: string[] = [];
  try {
    for (const entry of await readdir(root)) if (!top.has(entry)) extras.push(entry);
    for (const folder of ['bin', 'node_modules/@hn']) {
      for (const entry of await readdir(join(root, ...folder.split('/')), { recursive: true, withFileTypes: true })) {
        if (!entry.isFile()) continue;
        const path = relative(root, join(entry.parentPath, entry.name)).split(sep).join('/');
        if (!listed.has(path)) extras.push(path);
      }
    }
  } catch {
    problems.push('the package folders could not be listed');
  }
  for (const extra of extras) problems.push(`${extra} is not part of the signed release`);
  return { ok: problems.length === 0, version: manifest.version, checked, problems: problems.slice(0, 5) };
}

/** An npm `integrity` string (`sha512-<base64>`) checked against the bytes of a tarball. */
export function checkNpmIntegrity(bytes: Buffer, integrity: string): boolean {
  const match = /^(sha512|sha256)-([A-Za-z0-9+/]+={0,2})$/.exec(integrity);
  if (match === null) return false;
  const want = Buffer.from(match[2] as string, 'base64');
  const got = createHash(match[1] as string).update(bytes).digest();
  return want.length === got.length && timingSafeEqual(want, got);
}
