import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { installRelease } from '@hn/release';
import { offerRoster } from '@hn/security';
import { loadOrCreateLogKey } from '@hn/session';
import { readReleaseInfo } from './helper.ts';
import { locateTrust } from './trust-cmd.ts';

/**
 * `hn update <archive or https URL> [--sig file]` (decision 12). Only a person at a terminal starts it: the main door
 * refuses it inside a session, and nothing in a project's files can name an update source. The keys it trusts are
 * the ones pinned in the release that is running, never ones the new archive brings.
 */

export interface UpdateContext {
  readonly positionals: readonly string[];
  readonly sig?: string;
  /** A root-signed roster of release keys to apply first (default: `<archive name>.roster.json`, when it exists). */
  readonly roster?: string;
  readonly home: string;
  readonly logKey: string;
  readonly env: NodeJS.ProcessEnv;
  readonly out: (text: string) => void;
  readonly fetch?: typeof fetch;
}

const MAX = 512 * 1024 * 1024;

async function load(source: string, fetcher: typeof fetch): Promise<Buffer> {
  if (/^[a-z]+:\/\//i.test(source)) {
    if (!source.startsWith('https://')) throw new HnError('UPDATE_REFUSED', 'An update is fetched over https only.');
    const response = await fetcher(source, { redirect: 'follow', signal: AbortSignal.timeout(300_000) });
    if (!response.ok) throw new HnError('UPDATE_REFUSED', `Fetching ${source} answered ${response.status}.`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > MAX) throw new HnError('UPDATE_REFUSED', 'The download is too large.');
    return bytes;
  }
  return readFile(source);
}

export async function runUpdateCommand(context: UpdateContext): Promise<number | null> {
  const [command, source] = context.positionals;
  if (command !== 'update') return null;
  if (source === undefined) throw new HnError('BAD_COMMAND', 'hn update <archive .tgz or https URL> [--sig <signature .json>]');
  const first = await readReleaseInfo(context.env);
  if (first === null) throw new HnError('UPDATE_REFUSED', 'hn update works only from an installed release, whose pinned key it checks against. This copy runs from source; update it with git.');
  const fetcher = context.fetch ?? fetch;
  // A roster beside the archive (Phase 15) is how a new signing key, or a revocation, reaches this install before the
  // archive is judged. It is checked against the root this release already pins, never one the roster brings.
  const rosterSource = context.roster ?? source.replace(/\.tgz$/, '.roster.json');
  let info = first;
  if (context.roster !== undefined && first.trust === null) throw new HnError('UPDATE_REFUSED', 'This release pins no root key, so it cannot take a roster.');
  if (first.trust !== null && rosterSource !== source) {
    const offered = await load(rosterSource, fetcher).then((bytes) => JSON.parse(bytes.toString('utf8')) as unknown, (error: unknown) => {
      if (context.roster !== undefined) throw error;
      return null;
    });
    if (offered !== null) {
      const found = await locateTrust('release', context.env);
      if ('missing' in found) throw new HnError('UPDATE_REFUSED', found.missing);
      const applied = await offerRoster(found.folder, found.key, found.source, offered);
      if (applied.changed) context.out(`Applied the release key roster (serial ${applied.state.serial}).\n`);
      info = (await readReleaseInfo(context.env)) ?? first;
    }
  }
  const pinned = info.pinned;
  const running = info.version;
  const sigSource = context.sig ?? source.replace(/\.tgz$/, '.sig.json');
  if (sigSource === source) throw new HnError('BAD_COMMAND', 'Name the signature with --sig.');
  const [archive, signature] = await Promise.all([load(source, fetcher), load(sigSource, fetcher)]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(signature.toString('utf8'));
  } catch {
    throw new HnError('UPDATE_REFUSED', 'The signature file is not JSON.');
  }
  const installed = await installRelease({ archive, signature: parsed, pinned, appDir: join(context.home, 'app'), key: await loadOrCreateLogKey(context.logKey), running });
  context.out(`Installed ${sanitizeForDisplay(installed.manifest.name)} ${sanitizeForDisplay(installed.manifest.version)} in ${installed.root}. Run it with: node ${join(installed.root, 'bin', 'hn.mjs')}\n`);
  return 0;
}
