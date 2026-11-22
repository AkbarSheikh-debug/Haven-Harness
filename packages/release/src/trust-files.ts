import { readFile } from 'node:fs/promises';
import { applyRoster, initialTrust, keyFingerprint, parseRoster } from '@hn/security';
import type { TarFile } from './tar.ts';

/**
 * The trust files of a release (Phase 15): the root this release pins (`RELEASE-ROOT.json`) and the newest
 * root-signed roster (`RELEASE-ROSTER.json`). Both or neither: a roster without its root could not be checked, and a
 * roster that does not list this release's own signing key would make the release refuse itself.
 */
export async function trustFiles(options: { root?: string; rootId?: string; roster?: string; keyId: string; publicPem: string }): Promise<TarFile[]> {
  const { root, rootId, roster } = options;
  if (root === undefined && rootId === undefined && roster === undefined) return [];
  if (root === undefined || rootId === undefined || roster === undefined) throw new Error('--root, --root-id and --roster go together: a roster needs the root that signed it, and a root alone adds nothing.');
  const rootPem = (await readFile(root, 'utf8')).toString();
  const signed = JSON.parse(await readFile(roster, 'utf8')) as { rootKeyId?: unknown; roster?: unknown };
  const parsed = parseRoster(signed.roster);
  if (parsed.purpose !== 'release') throw new Error(`${roster} is a ${parsed.purpose} roster, not a release roster.`);
  if (signed.rootKeyId !== rootId) throw new Error(`${roster} is signed by root "${String(signed.rootKeyId)}", not "${rootId}".`);
  const listed = parsed.keys.find((key) => key.keyId === options.keyId);
  if (listed === undefined || keyFingerprint(listed.publicKey) !== keyFingerprint(options.publicPem)) throw new Error(`The roster does not list this release's signing key "${options.keyId}", so the release would refuse itself.`);
  if (parsed.revoked.some((item) => item.keyId === options.keyId)) throw new Error(`The roster revokes "${options.keyId}", the key signing this release.`);
  // The signature is checked with the root, so a roster that was edited after signing never ships.
  applyRoster(initialTrust('release', { keyId: rootId, publicKey: rootPem }, { [options.keyId]: options.publicPem }), signed);
  return [
    { path: 'RELEASE-ROOT.json', data: Buffer.from(`${JSON.stringify({ keyId: rootId, publicKey: rootPem }, null, 2)}\n`) },
    { path: 'RELEASE-ROSTER.json', data: Buffer.from(`${JSON.stringify(signed, null, 2)}\n`) },
  ];
}
