// Compiles the VS Code extension (packages/vscode/src) to JavaScript in packages/vscode/dist. A developer tool.
//
//   node --disable-proto=throw scripts/build-vscode.ts
//
// The extension is plain ES modules with no runtime dependency (only the `vscode` module the editor supplies), so a
// compile is the whole build: no bundler, no install script. dist/ is not committed.

import { spawnSync } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = join(import.meta.dirname, '..');
export const EXTENSION_DIR = join(ROOT, 'packages', 'vscode');

/**
 * Compiles the extension and returns the folder the JavaScript is in. Throws with the compiler's words if it fails.
 * With no folder it builds `packages/vscode/dist`, which the editor tests load and which one process at a time should
 * build. Anything else that only wants the compiled files (the packer) names a folder of its own, so it cannot delete
 * the one a test is loading.
 */
export async function buildExtension(into?: string): Promise<string> {
  const dist = into ?? join(EXTENSION_DIR, 'dist');
  await rm(dist, { recursive: true, force: true });
  const tsc = spawnSync(process.execPath, [join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(EXTENSION_DIR, 'tsconfig.build.json'), '--outDir', dist], { cwd: ROOT, encoding: 'utf8' });
  if (tsc.status !== 0) throw new Error(`The extension did not compile:\n${tsc.stdout}${tsc.stderr}`);
  return dist;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  console.log(`Built ${await buildExtension()}`);
}
