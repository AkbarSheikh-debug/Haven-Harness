import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const KEY_BYTES = 32;

/**
 * The per-install key that signs session logs. A same-user process can read this
 * file, so forged-log protection is weaker here than with the key in the OS keychain.
 */
export async function loadOrCreateLogKey(path: string): Promise<Buffer> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try {
    const key = await readFile(path);
    if (key.length === KEY_BYTES) return key;
    throw new Error(`${path} is not a ${KEY_BYTES} byte key.`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const key = randomBytes(KEY_BYTES);
  // `wx` loses cleanly if another process created the key first.
  await writeFile(path, key, { flag: 'wx', mode: 0o600 }).catch(async (error: NodeJS.ErrnoException) => {
    if (error.code !== 'EEXIST') throw error;
  });
  return readFile(path);
}
