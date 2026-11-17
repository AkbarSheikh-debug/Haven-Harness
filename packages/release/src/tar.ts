import { HnError } from '@hn/core';

/**
 * A deterministic tar (POSIX ustar, with a PAX header only for long paths). The same files always give the same
 * bytes: entries are sorted, times, owners and names are fixed, and only regular files are written, so two builds
 * of one commit can be compared byte for byte. The reader is the update path's first line of defence:
 * it accepts only regular files with plain relative paths, refuses links, devices, absolute paths, `..`, drive
 * letters and backslashes, and caps sizes, so a hostile archive cannot write outside the folder it is unpacked into.
 */

export class TarError extends HnError {
  constructor(message: string) {
    super('TAR_INVALID', message);
  }
}

export interface TarFile {
  readonly path: string;
  readonly data: Buffer;
  readonly executable?: boolean;
}

const BLOCK = 512;
const MAX_ENTRY = 512 * 1024 * 1024;
const MAX_TOTAL = 2 * 1024 * 1024 * 1024;

/** A path the archive may hold: forward slashes, relative, no empty, `.` or `..` parts, no drive, no control characters. */
export function safeArchivePath(path: string): boolean {
  if (path === '' || path.length > 4096 || path.startsWith('/') || path.includes('\\') || /^[A-Za-z]:/.test(path) || /[\u0000-\u001f\u007f]/.test(path)) return false;
  return path.split('/').every((part) => part !== '' && part !== '.' && part !== '..');
}

function octal(value: number, width: number): string {
  return `${value.toString(8).padStart(width - 1, '0')}\0`;
}

function header(name: string, size: number, mode: number, type: '0' | 'x', prefix = ''): Buffer {
  const block = Buffer.alloc(BLOCK, 0);
  block.write(name, 0, 100, 'utf8');
  block.write(octal(mode, 8), 100, 'ascii');
  block.write(octal(0, 8), 108, 'ascii');
  block.write(octal(0, 8), 116, 'ascii');
  block.write(octal(size, 12), 124, 'ascii');
  block.write(octal(0, 12), 136, 'ascii');
  block.write('        ', 148, 'ascii');
  block.write(type, 156, 'ascii');
  block.write('ustar\0', 257, 'ascii');
  block.write('00', 263, 'ascii');
  block.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (const byte of block) sum += byte;
  block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
  return block;
}

const pad = (size: number): Buffer => Buffer.alloc((BLOCK - (size % BLOCK)) % BLOCK, 0);

/** One PAX record: "<length> path=<value>\n", where the length counts its own digits. */
function paxRecord(key: string, value: string): Buffer {
  const body = ` ${key}=${value}\n`;
  const base = Buffer.byteLength(body);
  let length = base + String(base).length;
  if (String(length).length !== String(base).length) length = base + String(length).length;
  return Buffer.from(`${length}${body}`, 'utf8');
}

export function writeTar(files: readonly TarFile[]): Buffer {
  const seen = new Set<string>();
  const parts: Buffer[] = [];
  for (const file of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    if (!safeArchivePath(file.path)) throw new TarError(`${JSON.stringify(file.path)} is not a path an archive may hold.`);
    if (seen.has(file.path.toLowerCase())) throw new TarError(`${file.path} is in the archive twice (or differs only in case).`);
    seen.add(file.path.toLowerCase());
    const mode = file.executable === true ? 0o755 : 0o644;
    const bytes = Buffer.byteLength(file.path);
    if (bytes > 100) {
      const record = paxRecord('path', file.path);
      parts.push(header('PaxHeader', record.length, 0o644, 'x'), record, pad(record.length));
    }
    parts.push(header(bytes > 100 ? Buffer.from(file.path).subarray(0, 99).toString('latin1') : file.path, file.data.length, mode, '0'), file.data, pad(file.data.length));
  }
  parts.push(Buffer.alloc(BLOCK * 2, 0));
  return Buffer.concat(parts);
}

function readOctal(block: Buffer, offset: number, width: number): number {
  const text = block.subarray(offset, offset + width).toString('ascii').replace(/[\0 ]+$/, '').trim();
  if (text === '') return 0;
  if (!/^[0-7]+$/.test(text)) throw new TarError('A header field is not octal.');
  return parseInt(text, 8);
}

export function readTar(archive: Buffer): TarFile[] {
  const out: TarFile[] = [];
  const seen = new Set<string>();
  let offset = 0;
  let total = 0;
  let longPath: string | null = null;
  while (offset + BLOCK <= archive.length) {
    const block = archive.subarray(offset, offset + BLOCK);
    if (block.every((byte) => byte === 0)) break;
    let sum = 0;
    for (let index = 0; index < BLOCK; index += 1) sum += index >= 148 && index < 156 ? 32 : (block[index] as number);
    if (sum !== readOctal(block, 148, 8)) throw new TarError('A header checksum does not match.');
    const size = readOctal(block, 124, 12);
    if (size > MAX_ENTRY) throw new TarError('An entry is too large.');
    total += size;
    if (total > MAX_TOTAL) throw new TarError('The archive is too large.');
    const type = String.fromCharCode(block[156] as number);
    const dataStart = offset + BLOCK;
    if (dataStart + size > archive.length) throw new TarError('The archive is cut short.');
    const data = archive.subarray(dataStart, dataStart + size);
    offset = dataStart + size + ((BLOCK - (size % BLOCK)) % BLOCK);
    if (type === 'x') {
      const match = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(data.toString('utf8'));
      longPath = match?.[1] ?? null;
      continue;
    }
    if (type !== '0' && type !== '\0') throw new TarError(`The archive holds an entry of type ${JSON.stringify(type)}; only regular files are accepted.`);
    const name = block.subarray(0, 100).toString('utf8').replace(/\0.*$/s, '');
    const prefix = block.subarray(345, 500).toString('utf8').replace(/\0.*$/s, '');
    const path = longPath ?? (prefix === '' ? name : `${prefix}/${name}`);
    longPath = null;
    if (!safeArchivePath(path)) throw new TarError(`The archive holds a path that is not allowed: ${JSON.stringify(path)}.`);
    const key = path.toLowerCase();
    if (seen.has(key)) throw new TarError(`${path} is in the archive twice (or differs only in case).`);
    seen.add(key);
    out.push({ path, data: Buffer.from(data), executable: (readOctal(block, 100, 8) & 0o111) !== 0 });
  }
  return out;
}
