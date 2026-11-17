// Release-age audit. Reads every package in pnpm-lock.yaml, asks the npm registry when that
// version was published, and fails if any is younger than the delay (7 days by default) or not pinned by sha512.
// Networked, so it is run by hand before a release, not in the test suite.
//
//   node --disable-proto=throw scripts/check-release-age.ts [--days 7]

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { lockedPackages, tooYoung, unpinned } from '../packages/release/src/supply.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { days: { type: 'string' } } });
  const days = Number(values.days ?? '7');
  const packages = lockedPackages(await readFile(`${ROOT}pnpm-lock.yaml`, 'utf8'));
  const published = new Map<string, string>();
  for (const name of [...new Set(packages.map((item) => item.name))]) {
    const response = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, { headers: { accept: 'application/json' } });
    if (!response.ok) continue;
    const doc = (await response.json()) as { time?: Record<string, string> };
    for (const [version, time] of Object.entries(doc.time ?? {})) published.set(`${name}@${version}`, time);
  }
  const young = tooYoung(packages, published, Date.now(), days);
  const weak = unpinned(packages);
  process.stdout.write(`${packages.length} packages checked; ${young.length} younger than ${days} days; ${weak.length} not pinned by sha512.\n`);
  for (const item of young) process.stdout.write(`  too young: ${item.name}@${item.version} (published ${published.get(`${item.name}@${item.version}`) ?? 'unknown'})\n`);
  for (const item of weak) process.stdout.write(`  not pinned: ${item.name}@${item.version}\n`);
  if (young.length > 0 || weak.length > 0) process.exitCode = 1;
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
