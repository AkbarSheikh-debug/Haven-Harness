import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { deflate, inflate } from 'node:zlib';
import { HnError } from '@hn/core';
import { Redactor, isSecretPath } from '@hn/security';
import type { Skipped } from './handback.ts';
import type { SafeFiles } from './safe-files.ts';

const deflateAsync = promisify(deflate);
const inflateAsync = promisify(inflate);

/**
 * Undoing files (11.7). A content-addressed, encrypted store of whole files under `~/.hn/checkpoints/`,
 * with no state in the project. Project ignores are never honoured, because an attacker would decide
 * what gets saved. Secrets are excluded by name and by a content scan, so `.env` never reaches
 * long-term storage. What cannot be saved or restored is reported on every checkpoint and rollback,
 * so "yolo has undo" is never quietly false. No git runs here, so there is no git config to attack.
 */

export class RollbackRefused extends HnError {
  constructor(message: string) {
    super('ROLLBACK_REFUSED', message);
  }
}

export interface CheckpointOptions {
  /** Where the store lives, for example `~/.hn/checkpoints/<project>`. */
  readonly dir: string;
  /** The log key. Objects are encrypted under a key derived from it. */
  readonly key: Uint8Array;
  readonly files: SafeFiles;
  readonly maxCheckpoints?: number;
  readonly maxStoreBytes?: number;
  readonly maxFileBytes?: number;
  readonly now?: () => Date;
}

interface Entry {
  readonly obj: string;
  readonly mode: number;
  readonly size: number;
}

interface Manifest {
  readonly v: 1;
  readonly seq: number;
  readonly session: string;
  readonly ts: string;
  readonly reason: string;
  readonly files: Readonly<Record<string, Entry>>;
  readonly skipped: readonly Skipped[];
}

export interface CheckpointInfo {
  readonly seq: number;
  readonly session: string;
  readonly ts: string;
  readonly reason: string;
  /** Hash of the saved tree. Logged as `checkpoint/create {seq, treeHash, ref}`. */
  readonly treeHash: string;
  readonly ref: string;
  readonly fileCount: number;
  readonly bytes: number;
  readonly skipped: readonly Skipped[];
}

export interface RestoreReport {
  readonly restored: readonly string[];
  readonly deleted: readonly string[];
  /** Not saved in the checkpoint, so not restorable. Reported every time. */
  readonly skipped: readonly Skipped[];
  /** Restores that were attempted and refused or failed. */
  readonly failed: readonly Skipped[];
}

export interface RestoreOptions {
  /** Called first. A box that is still running could race the restore with a link swap. */
  readonly boxAlive: () => boolean | Promise<boolean>;
  /** Restore only these paths. Leave out to restore everything the checkpoint holds (`--all`). */
  readonly paths?: readonly string[];
  /** Also delete files that did not exist at the checkpoint. */
  readonly deleteNew?: boolean;
}

const DEFAULT_MAX_CHECKPOINTS = 100;
const DEFAULT_MAX_STORE_BYTES = 500 * 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_FILES = 100_000;
/** The harness's own choice, not the project's: a dependency folder is too big to store and can be reinstalled. */
const NOT_STORED = new Set(['node_modules']);

const seqName = (seq: number): string => `${String(seq).padStart(8, '0')}.bin`;
const posix = (path: string): string => path.replaceAll('\\', '/');

export class CheckpointStore {
  readonly #options: Required<Omit<CheckpointOptions, 'key' | 'files'>> & Pick<CheckpointOptions, 'files'>;
  readonly #key: Buffer;
  readonly #nameKey: Buffer;
  readonly #redactor = new Redactor();

  constructor(options: CheckpointOptions) {
    this.#options = {
      dir: options.dir,
      files: options.files,
      maxCheckpoints: options.maxCheckpoints ?? DEFAULT_MAX_CHECKPOINTS,
      maxStoreBytes: options.maxStoreBytes ?? DEFAULT_MAX_STORE_BYTES,
      maxFileBytes: options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES,
      now: options.now ?? (() => new Date()),
    };
    this.#key = Buffer.from(hkdfSync('sha256', options.key, Buffer.alloc(0), 'hn checkpoint encryption v1', 32));
    // Object names are keyed, so a known file's name cannot be computed from its content by someone who reads the folder.
    this.#nameKey = Buffer.from(hkdfSync('sha256', options.key, Buffer.alloc(0), 'hn checkpoint names v1', 32));
  }

  #seal(plain: Buffer, label: string): Buffer {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, nonce);
    cipher.setAAD(Buffer.from(label));
    const body = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([nonce, cipher.getAuthTag(), body]);
  }

  #open(sealed: Buffer, label: string): Buffer {
    const decipher = createDecipheriv('aes-256-gcm', this.#key, sealed.subarray(0, 12));
    decipher.setAAD(Buffer.from(label));
    decipher.setAuthTag(sealed.subarray(12, 28));
    return Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]);
  }

  #objectName(bytes: Buffer): string {
    return createHmac('sha256', this.#nameKey).update(bytes).digest('hex');
  }

  async #nextSeq(): Promise<number> {
    const names = await readdir(join(this.#options.dir, 'manifests')).catch(() => [] as string[]);
    return names.reduce((max, name) => Math.max(max, Number.parseInt(name, 10) || 0), 0) + 1;
  }

  async #store(bytes: Buffer): Promise<string> {
    const name = this.#objectName(bytes);
    const path = join(this.#options.dir, 'objects', name);
    try {
      await lstat(path);
      return name;
    } catch {
      // Not stored yet.
    }
    const temp = `${path}.${process.pid}.tmp`;
    await writeFile(temp, this.#seal(await deflateAsync(bytes), name), { mode: 0o600 });
    await rename(temp, path);
    return name;
  }

  async #load(obj: string): Promise<Buffer> {
    return inflateAsync(this.#open(await readFile(join(this.#options.dir, 'objects', obj)), obj));
  }

  async #manifest(seq: number): Promise<Manifest> {
    const label = `manifest-${seq}`;
    const plain = this.#open(await readFile(join(this.#options.dir, 'manifests', seqName(seq))), label);
    return JSON.parse(plain.toString('utf8')) as Manifest;
  }

  /**
   * Saves the project as it is now. Returns what was saved and, just as important, what was not.
   * `root` is the folder the box can change: the host tree for a direct bind, the copy for a box.
   */
  async create(root: string, meta: { session: string; reason: string }): Promise<CheckpointInfo> {
    await mkdir(join(this.#options.dir, 'objects'), { recursive: true, mode: 0o700 });
    await mkdir(join(this.#options.dir, 'manifests'), { recursive: true, mode: 0o700 });
    await mkdir(join(this.#options.dir, 'refs'), { recursive: true, mode: 0o700 });

    const files: Record<string, Entry> = {};
    const skipped: Skipped[] = [];
    let bytes = 0;

    const walk = async (relativeDir: string): Promise<void> => {
      for (const entry of await readdir(join(root, relativeDir), { withFileTypes: true })) {
        const relative = posix(join(relativeDir, entry.name));
        const lower = entry.name.toLowerCase();
        if (lower === '.git') skipped.push({ path: relative, why: 'git internals are not checkpointed' });
        else if (NOT_STORED.has(lower)) skipped.push({ path: relative, why: 'a dependency folder is too large to store; reinstall it after a rollback' });
        else if (isSecretPath(relative)) skipped.push({ path: relative, why: 'it may hold secrets, so it is never stored' });
        else {
          const info = await lstat(join(root, relative)).catch(() => null);
          if (info === null) skipped.push({ path: relative, why: 'it cannot be inspected' });
          else if (info.isSymbolicLink()) skipped.push({ path: relative, why: 'a symbolic link is not checkpointed' });
          else if (info.isDirectory()) await walk(relative);
          else if (!info.isFile()) skipped.push({ path: relative, why: 'a special file is not checkpointed' });
          else if (info.size > this.#options.maxFileBytes) skipped.push({ path: relative, why: `the file is over ${this.#options.maxFileBytes} bytes` });
          else if (Object.keys(files).length >= MAX_FILES) skipped.push({ path: relative, why: 'the project has too many files' });
          else if (bytes + info.size > this.#options.maxStoreBytes) skipped.push({ path: relative, why: 'the project is over the size cap' });
          else {
            const data = await this.#options.files.read(root, join(root, relative), this.#options.maxFileBytes).catch(() => null);
            if (data === null) skipped.push({ path: relative, why: 'it could not be read safely' });
            // A secret scan before anything is committed, so a key inside an ordinary-looking file never reaches storage.
            else if (!data.includes(0) && this.#redactor.redact(data.toString('utf8')) !== data.toString('utf8')) skipped.push({ path: relative, why: 'it looks like it holds a secret, so it is not stored' });
            else {
              files[relative] = { obj: await this.#store(data), mode: info.mode & 0o777, size: data.length };
              bytes += data.length;
            }
          }
        }
      }
    };
    await walk('');

    const seq = await this.#nextSeq();
    const manifest: Manifest = { v: 1, seq, session: meta.session, ts: this.#options.now().toISOString(), reason: meta.reason, files, skipped };
    const treeHash = createHash('sha256')
      .update(JSON.stringify(Object.keys(files).sort().map((path) => [path, files[path]?.obj, files[path]?.mode])))
      .digest('hex');
    await writeFile(join(this.#options.dir, 'manifests', seqName(seq)), this.#seal(Buffer.from(JSON.stringify(manifest)), `manifest-${seq}`), { mode: 0o600 });
    await this.#addRef(meta.session, seq);
    return { seq, session: meta.session, ts: manifest.ts, reason: meta.reason, treeHash, ref: `${meta.session}/${seq}`, fileCount: Object.keys(files).length, bytes, skipped };
  }

  async #addRef(session: string, seq: number): Promise<void> {
    const path = join(this.#options.dir, 'refs', `${createHash('sha256').update(session).digest('hex').slice(0, 32)}.json`);
    const current = await readFile(path, 'utf8').then((text) => JSON.parse(text) as { session: string; seqs: number[] }, () => ({ session, seqs: [] as number[] }));
    await writeFile(path, JSON.stringify({ session, seqs: [...current.seqs, seq] }), { mode: 0o600 });
  }

  async list(): Promise<CheckpointInfo[]> {
    const names = (await readdir(join(this.#options.dir, 'manifests')).catch(() => [] as string[])).sort();
    const out: CheckpointInfo[] = [];
    for (const name of names) {
      const manifest = await this.#manifest(Number.parseInt(name, 10)).catch(() => null);
      if (manifest === null) continue;
      const paths = Object.keys(manifest.files).sort();
      out.push({
        seq: manifest.seq,
        session: manifest.session,
        ts: manifest.ts,
        reason: manifest.reason,
        treeHash: createHash('sha256').update(JSON.stringify(paths.map((path) => [path, manifest.files[path]?.obj, manifest.files[path]?.mode]))).digest('hex'),
        ref: `${manifest.session}/${manifest.seq}`,
        fileCount: paths.length,
        bytes: paths.reduce((sum, path) => sum + (manifest.files[path]?.size ?? 0), 0),
        skipped: manifest.skipped,
      });
    }
    return out;
  }

  /**
   * Puts files back. Refuses while the box is alive. Restores only `paths` when given, so a person's own
   * edits survive unless everything was asked for. Writes go through the safe-file helper.
   */
  async restore(root: string, seq: number, options: RestoreOptions): Promise<RestoreReport> {
    if (await options.boxAlive()) throw new RollbackRefused('The box is still running. Stop it first, so a live job cannot race the restore with a link swap.');
    const manifest = await this.#manifest(seq).catch(() => {
      throw new RollbackRefused(`There is no checkpoint ${seq}.`);
    });
    const wanted = options.paths === undefined ? null : new Set(options.paths.map(posix));
    const restored: string[] = [];
    const deleted: string[] = [];
    const failed: Skipped[] = [];
    const { files } = this.#options;

    for (const [path, entry] of Object.entries(manifest.files)) {
      if (wanted !== null && !wanted.has(path)) continue;
      try {
        const data = await this.#load(entry.obj);
        const current = await files.read(root, join(root, path), this.#options.maxFileBytes).catch(() => null);
        if (current !== null && this.#objectName(current) === entry.obj) continue;
        await files.write(root, join(root, path), data, { mkdir: true });
        restored.push(path);
      } catch (error) {
        failed.push({ path, why: error instanceof Error ? error.message : String(error) });
      }
    }

    if (options.deleteNew === true || wanted !== null) {
      for (const path of await this.#currentFiles(root)) {
        if (path in manifest.files || manifest.skipped.some((entry) => entry.path === path || path.startsWith(`${entry.path}/`))) continue;
        if (wanted !== null && !wanted.has(path)) continue;
        try {
          await files.delete(root, join(root, path));
          deleted.push(path);
        } catch (error) {
          failed.push({ path, why: error instanceof Error ? error.message : String(error) });
        }
      }
    }
    return { restored, deleted, skipped: manifest.skipped, failed };
  }

  async #currentFiles(root: string): Promise<string[]> {
    const found: string[] = [];
    const walk = async (relativeDir: string): Promise<void> => {
      for (const entry of await readdir(join(root, relativeDir), { withFileTypes: true })) {
        const relative = posix(join(relativeDir, entry.name));
        if (entry.name.toLowerCase() === '.git' || NOT_STORED.has(entry.name.toLowerCase()) || isSecretPath(relative)) continue;
        const info = await lstat(join(root, relative)).catch(() => null);
        if (info?.isDirectory() === true) await walk(relative);
        else if (info?.isFile() === true) found.push(relative);
      }
    };
    await walk('');
    return found;
  }

  /**
   * Keeps the newest checkpoints and the ones a live session still references, then removes objects nothing points to.
   * A ref a live session can see is never deleted, however old.
   */
  async prune(liveSessions: ReadonlySet<string> = new Set()): Promise<{ removedCheckpoints: number; removedObjects: number }> {
    const dir = this.#options.dir;
    const names = (await readdir(join(dir, 'manifests')).catch(() => [] as string[])).sort();
    const protectedSeqs = new Set<number>();
    for (const name of await readdir(join(dir, 'refs')).catch(() => [] as string[])) {
      const ref = await readFile(join(dir, 'refs', name), 'utf8').then((text) => JSON.parse(text) as { session: string; seqs: number[] }, () => null);
      if (ref !== null && liveSessions.has(ref.session)) for (const seq of ref.seqs) protectedSeqs.add(seq);
    }
    const keep = new Set(names.slice(-this.#options.maxCheckpoints).map((name) => Number.parseInt(name, 10)));
    let removedCheckpoints = 0;
    for (const name of names) {
      const seq = Number.parseInt(name, 10);
      if (keep.has(seq) || protectedSeqs.has(seq)) continue;
      await rm(join(dir, 'manifests', name), { force: true });
      removedCheckpoints += 1;
    }

    const referenced = new Set<string>();
    for (const name of await readdir(join(dir, 'manifests')).catch(() => [] as string[])) {
      const manifest = await this.#manifest(Number.parseInt(name, 10)).catch(() => null);
      if (manifest !== null) for (const entry of Object.values(manifest.files)) referenced.add(entry.obj);
    }
    let removedObjects = 0;
    for (const name of await readdir(join(dir, 'objects')).catch(() => [] as string[])) {
      if (referenced.has(name)) continue;
      await rm(join(dir, 'objects', name), { force: true });
      removedObjects += 1;
    }
    return { removedCheckpoints, removedObjects };
  }
}

export interface PolicyOptions {
  readonly everySteps?: number;
  readonly everyMs?: number;
  readonly now?: () => number;
}

/**
 * When to snapshot: before the first mutating step in each directory (bash included), then at most once
 * per 50 steps or 10 minutes, so a long unattended run still has many restore points but not one per step.
 */
export class CheckpointPolicy {
  readonly #everySteps: number;
  readonly #everyMs: number;
  readonly #now: () => number;
  readonly #seen = new Set<string>();
  #lastStep = Number.NEGATIVE_INFINITY;
  #lastTime = Number.NEGATIVE_INFINITY;

  constructor(options: PolicyOptions = {}) {
    this.#everySteps = options.everySteps ?? 50;
    this.#everyMs = options.everyMs ?? 10 * 60_000;
    this.#now = options.now ?? Date.now;
  }

  /** Call before a mutating step. Returns true when a snapshot should be taken now, and counts it as taken. */
  shouldSnapshot(directory: string, step: number): boolean {
    const now = this.#now();
    const first = !this.#seen.has(directory);
    const due = step - this.#lastStep >= this.#everySteps || now - this.#lastTime >= this.#everyMs;
    this.#seen.add(directory);
    if (!first && !due) return false;
    this.#lastStep = step;
    this.#lastTime = now;
    return true;
  }
}
