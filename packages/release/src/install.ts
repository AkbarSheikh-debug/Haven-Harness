import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { ReleaseError, compareVersions, verifyRelease, type ReleaseManifest } from './manifest.ts';
import { safeArchivePath } from './tar.ts';

/**
 * The update verifier. A release is installed only when its signature checks against a key the
 * installed copy pins, every file matches the manifest, it is for this platform, and its version is newer than the
 * highest version ever installed here. That highest version is kept with an HMAC under a key only this machine
 * holds, so a downgrade cannot be forced by deleting or editing the record. Nothing here is started by a project:
 * `hn update` is the only caller, and only from a person's command line.
 */

export interface InstallOptions {
  /** The gzipped archive, already read. */
  readonly archive: Buffer;
  readonly signature: unknown;
  /** Key id to public key, from the installed copy's RELEASE-KEY.json. */
  readonly pinned: ReadonlyMap<string, string>;
  /** `~/.hn/app`: one folder per version, plus the record of the highest version installed. */
  readonly appDir: string;
  /** The machine's own key, for the record's HMAC. */
  readonly key: Uint8Array;
  /** The version running now, the floor when no record exists yet. */
  readonly running: string;
  readonly platform?: string;
}

interface Highest {
  readonly version: string;
  readonly mac: string;
}

const recordMac = (key: Uint8Array, version: string): string => createHmac('sha256', key).update(`hn-highest-installed\u0000${version}`).digest('hex');

async function highest(appDir: string, key: Uint8Array, running: string): Promise<string> {
  let text: string;
  try {
    text = await readFile(join(appDir, 'highest.json'), 'utf8');
  } catch {
    return running;
  }
  let record: Highest;
  try {
    record = JSON.parse(text) as Highest;
  } catch {
    throw new ReleaseError('The record of the highest installed version is damaged, so no update is installed.');
  }
  const want = Buffer.from(recordMac(key, String(record.version)), 'hex');
  const got = Buffer.from(String(record.mac), 'hex');
  if (want.length !== got.length || !timingSafeEqual(want, got)) throw new ReleaseError('The record of the highest installed version was changed, so no update is installed.');
  return compareVersions(record.version, running) >= 0 ? record.version : running;
}

export async function installRelease(options: InstallOptions): Promise<{ manifest: ReleaseManifest; root: string }> {
  let tar: Buffer;
  try {
    tar = gunzipSync(options.archive, { maxOutputLength: 2 * 1024 * 1024 * 1024 });
  } catch {
    throw new ReleaseError('The archive is not a gzip file, or it is too large.');
  }
  const { manifest, files } = verifyRelease(tar, options.signature, options.pinned);
  const platform = options.platform ?? `${process.platform}-${process.arch}`;
  if (manifest.platform !== platform) throw new ReleaseError(`This release is for ${manifest.platform}, not ${platform}.`);
  const floor = await highest(options.appDir, options.key, options.running);
  if (compareVersions(manifest.version, floor) <= 0) throw new ReleaseError(`This release is ${manifest.version}, and ${floor} is already installed or was installed before, so it is refused (no downgrade, no reinstall).`);
  const root = join(options.appDir, manifest.version);
  const staging = join(options.appDir, `.staging-${randomBytes(6).toString('hex')}`);
  await mkdir(staging, { recursive: true });
  try {
    for (const file of files) {
      if (!safeArchivePath(file.path)) throw new ReleaseError(`Refusing to write ${file.path}.`);
      const target = join(staging, ...file.path.split('/'));
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, file.data, { flag: 'wx' });
      if (file.executable === true) await chmod(target, 0o755).catch(() => undefined);
    }
    await writeFile(join(staging, 'manifest.json'), JSON.stringify(manifest), { flag: 'wx' });
    await rm(root, { recursive: true, force: true });
    await rename(staging, root);
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
  // The record moves only after the files are in place, so a failed install never raises the floor.
  await writeFile(join(options.appDir, 'highest.json'), JSON.stringify({ version: manifest.version, mac: recordMac(options.key, manifest.version) }), { mode: 0o600 });
  await writeFile(join(options.appDir, 'current.json'), JSON.stringify({ version: manifest.version, root }), { mode: 0o600 });
  return { manifest, root };
}
