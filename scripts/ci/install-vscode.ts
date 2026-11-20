// Downloads the pinned VS Code for this machine, checks its SHA-256 against scripts/ci/vscode-pins.json, unpacks it, and
// prints the path of its executable. CI sets that path as HN_VSCODE so the extension's tests drive a real VS Code. A
// developer tool; it changes nothing outside the folder it is given.
//
//   node --disable-proto=throw scripts/ci/install-vscode.ts <folder>

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { arch, platform } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

interface Pins {
  readonly version: string;
  readonly platforms: Readonly<Record<string, { readonly url: string; readonly sha256: string; readonly executable: string }>>;
}

export function platformKey(os: string = platform(), cpu: string = arch()): string {
  return `${os}-${cpu}`;
}

export async function installVsCode(folder: string): Promise<string> {
  const pins = JSON.parse(await readFile(new URL('./vscode-pins.json', import.meta.url), 'utf8')) as Pins;
  const key = platformKey();
  const pin = pins.platforms[key];
  if (pin === undefined) throw new Error(`No VS Code is pinned for ${key}. Pinned: ${Object.keys(pins.platforms).join(', ')}.`);
  const target = join(folder, `vscode-${pins.version}`);
  const executable = join(target, pin.executable);
  if (existsSync(executable)) return executable;
  await mkdir(target, { recursive: true });
  const archive = join(folder, pin.url.endsWith('.zip') ? 'vscode.zip' : 'vscode.tar.gz');
  const sha = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
  // An archive already here is used only if it is the pinned build.
  const have = existsSync(archive) ? await readFile(archive) : null;
  if (have === null || sha(have) !== pin.sha256) {
    const response = await fetch(pin.url, { redirect: 'follow', signal: AbortSignal.timeout(10 * 60_000) });
    if (!response.ok) throw new Error(`Downloading VS Code ${pins.version} answered ${response.status}.`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (sha(bytes) !== pin.sha256) throw new Error(`The VS Code download is not the pinned build (sha256 ${sha(bytes)}, expected ${pin.sha256}).`);
    await writeFile(archive, bytes);
  }
  // Each platform's own unpacker. The `tar` on a PATH can be GNU tar, which reads "C:" as a remote host.
  const unpack =
    process.platform === 'win32'
      ? spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', 'Expand-Archive -LiteralPath $env:HN_ARCHIVE -DestinationPath $env:HN_TARGET -Force'], { stdio: 'inherit', env: { ...process.env, HN_ARCHIVE: archive, HN_TARGET: target } })
      : process.platform === 'darwin'
        ? spawnSync('ditto', ['-x', '-k', archive, target], { stdio: 'inherit' })
        : spawnSync('tar', ['-xzf', archive, '-C', target], { stdio: 'inherit' });
  if (unpack.status !== 0) throw new Error('Unpacking VS Code failed.');
  if (!existsSync(executable)) throw new Error(`VS Code unpacked, but ${pin.executable} is not in it.`);
  return executable;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const folder = process.argv[2];
  if (folder === undefined) throw new Error('Usage: install-vscode.ts <folder>');
  console.log(await installVsCode(folder));
}
