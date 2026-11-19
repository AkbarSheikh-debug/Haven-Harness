import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { installRelease } from '@hn/release';
import { loadOrCreateLogKey } from '@hn/session';

/**
 * `hn update <archive or https URL> [--sig file]` (decision 12). Only a person at a terminal starts it: the main door
 * refuses it inside a session, and nothing in a project's files can name an update source. The keys it trusts are
 * the ones pinned in the release that is running, never ones the new archive brings.
 */

export interface UpdateContext {
  readonly positionals: readonly string[];
  readonly sig?: string;
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
  const releaseRoot = context.env['HN_RELEASE_ROOT'];
  if (releaseRoot === undefined || releaseRoot === '') throw new HnError('UPDATE_REFUSED', 'hn update works only from an installed release, whose pinned key it checks against. This copy runs from source; update it with git.');
  const pinned = new Map(Object.entries(JSON.parse(await readFile(join(releaseRoot, 'RELEASE-KEY.json'), 'utf8')) as Record<string, string>));
  const running = (JSON.parse(await readFile(join(releaseRoot, 'manifest.json'), 'utf8')) as { version: string }).version;
  const fetcher = context.fetch ?? fetch;
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
