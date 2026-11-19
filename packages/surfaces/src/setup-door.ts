import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { helperAssetName, helperEntry, helperManifestName, helperSignatureName, installHelper, verifyHelperManifest } from '@hn/release';
import { helperInstall, readReleaseInfo, resolveHelper } from './helper.ts';

/**
 * `hn setup [--from <folder>]` (Phase 9, decision 5). Fetches and verifies the sandbox helper now instead of at first
 * use, or installs it from a folder holding the release's helper files (an air-gapped machine). Only a person's
 * command line starts it. The same checks run either way: nothing is kept that the pinned key did not sign.
 */

export interface SetupContext {
  readonly positionals: readonly string[];
  readonly from?: string;
  readonly home: string;
  readonly env: NodeJS.ProcessEnv;
  readonly out: (text: string) => void;
  readonly fetch?: typeof fetch;
}

export async function runSetupCommand(context: SetupContext): Promise<number | null> {
  if (context.positionals[0] !== 'setup') return null;
  const info = await readReleaseInfo(context.env);
  if (info === null) {
    context.out('hn setup applies to an installed release. This copy runs from source: build the helper with pnpm build:sandbox.\n');
    return 0;
  }
  const install = helperInstall(info, context.home);
  if (context.from !== undefined) {
    const folder = context.from;
    // A file is read only up to the size it must have, so a huge file in the folder is never pulled into memory.
    const read = async (name: string, max: number): Promise<Buffer> => {
      const path = join(folder, name);
      const size = await stat(path).then((found) => (found.isFile() ? found.size : -1), () => -1);
      if (size < 0) throw new HnError('SETUP_REFUSED', `${name} is not in ${sanitizeForDisplay(folder)}.`);
      if (size > max) throw new HnError('SETUP_REFUSED', `${name} is ${size} bytes, more than the ${max} it can be, so it is refused.`);
      return readFile(path);
    };
    const [manifestBytes, signatureBytes] = await Promise.all([read(helperManifestName(info.version), 64 * 1024), read(helperSignatureName(info.version), 16 * 1024)]);
    let signature: unknown;
    try {
      signature = JSON.parse(signatureBytes.toString('utf8'));
    } catch {
      throw new HnError('SETUP_REFUSED', 'The signature file is not JSON.');
    }
    const entry = helperEntry(verifyHelperManifest(manifestBytes, signature, info.pinned, info.version), install.platform);
    const path = await installHelper(install, manifestBytes, signature, await read(helperAssetName(info.version, install.platform), entry.size));
    context.out(`Installed hn-sandbox ${info.version} for ${install.platform} (${entry.size} bytes, sha256 ${entry.sha256.slice(0, 16)}...) at ${path}, after checking its signature and hash.\n`);
    return 0;
  }
  const path = await resolveHelper({ env: context.env, home: context.home, log: context.out, ...(context.fetch === undefined ? {} : { fetch: context.fetch }) });
  context.out(path === null ? 'No helper was installed.\n' : `hn-sandbox ${info.version} for ${install.platform} is ready and verified: ${path}\n`);
  return path === null ? 1 : 0;
}
