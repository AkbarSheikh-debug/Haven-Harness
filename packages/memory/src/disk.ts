import { randomBytes } from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

/** The file's text, or `null` when it does not exist. Any other error is thrown. */
export async function readOrNull(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

/** Writes beside the target and renames over it, with the data flushed first, so a reader sees the old file or the new one. */
export async function atomicWrite(path: string, text: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    await writeFile(temp, text, { mode: 0o600, flush: true });
    await renameRetrying(temp, path);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
}

/** Antivirus and indexers on Windows hold files briefly, which makes a rename fail with EPERM or EBUSY. */
async function renameRetrying(from: string, to: string): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      await rename(from, to);
      return;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (attempt >= 20 || (code !== 'EPERM' && code !== 'EBUSY' && code !== 'EACCES')) throw error;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
}

export async function removeIfPresent(path: string): Promise<void> {
  await rm(path, { force: true });
}

const LOCK_WAIT_MS = 5_000;
const LOCK_STALE_MS = 30_000;

/**
 * Two sessions on one project write the same files, so each write holds `<file>.lock`. A lock
 * older than 30 seconds was left by a crash and is taken over.
 */
export async function withLock<T>(path: string, run: () => Promise<T>): Promise<T> {
  const lock = `${path}.lock`;
  await mkdir(dirname(lock), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const handle = await open(lock, 'wx', 0o600);
      await handle.writeFile(`${process.pid} ${new Date().toISOString()}\n`);
      await handle.close();
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      const age = await stat(lock).then((info) => Date.now() - info.mtimeMs, () => 0);
      if (age > LOCK_STALE_MS) await rm(lock, { force: true });
      else if (Date.now() > deadline) throw new Error(`Another session is writing ${basename(path)}. Try again in a moment.`);
      else await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  try {
    return await run();
  } finally {
    await rm(lock, { force: true });
  }
}

/** The file's state before a write: both files' exact text, or `null` where a file did not exist. */
export interface HistoryItem {
  readonly seq: number;
  readonly when: string;
  readonly sidecar: string | null;
  readonly markdown: string | null;
}

const historyDir = (path: string): string => join(dirname(path), '.history', basename(path));
const ITEM = /^(\d{6,})\.json$/;

export async function listHistory(path: string): Promise<number[]> {
  const names = await readdir(historyDir(path)).catch(() => [] as string[]);
  return names.flatMap((name) => {
    const match = ITEM.exec(name);
    return match === null ? [] : [Number(match[1])];
  }).sort((a, b) => a - b);
}

export async function readHistory(path: string, seq: number): Promise<HistoryItem | null> {
  const text = await readOrNull(join(historyDir(path), `${String(seq).padStart(6, '0')}.json`));
  if (text === null) return null;
  try {
    const raw = JSON.parse(text) as Record<string, unknown>;
    const { v, when, sidecar, markdown } = raw;
    if (v !== 1 || typeof when !== 'string') return null;
    if (!(sidecar === null || typeof sidecar === 'string') || !(markdown === null || typeof markdown === 'string')) return null;
    return { seq, when, sidecar, markdown };
  } catch {
    return null;
  }
}

/** Saves the state before a write, then keeps only the newest `limit` items. */
export async function pushHistory(path: string, item: Omit<HistoryItem, 'seq'>, limit: number): Promise<void> {
  const existing = await listHistory(path);
  const seq = (existing.at(-1) ?? 0) + 1;
  await atomicWrite(join(historyDir(path), `${String(seq).padStart(6, '0')}.json`), JSON.stringify({ v: 1, ...item }));
  for (const old of existing.slice(0, Math.max(0, existing.length + 1 - limit))) await dropHistory(path, old);
}

export async function dropHistory(path: string, seq: number): Promise<void> {
  await rm(join(historyDir(path), `${String(seq).padStart(6, '0')}.json`), { force: true });
}
