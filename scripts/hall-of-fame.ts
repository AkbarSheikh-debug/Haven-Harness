// Writes the public hall of fame (docs/guide/hall-of-fame.md) from docs/security/credits.json, or checks that the committed
// page is exactly what the data says. A developer tool, not part of hn. No dependencies.
//
//   node --disable-proto=throw scripts/hall-of-fame.ts            # rewrite the page
//   node --disable-proto=throw scripts/hall-of-fame.ts --check    # exit 1 if the data is invalid or the page is stale
//
// The file is the only source. An entry is accepted only if the reporter agreed to be named, it carries no contact detail,
// and it names the attack in the registry that now guards against what they found: a reported hole has to leave a test
// behind, or it is not credited as fixed.

import { readFileSync, writeFileSync } from 'node:fs';
import { CREDITS_DATA, HALL_PAGE, expectedHallOfFame } from '../packages/testkit/src/hall-of-fame.ts';

if (import.meta.main) {
  const option = (name: string, fallback: string): string => {
    const at = process.argv.indexOf(name);
    return at >= 0 && process.argv[at + 1] !== undefined ? (process.argv[at + 1] as string) : fallback;
  };
  const data = option('--data', CREDITS_DATA);
  const page = option('--page', HALL_PAGE);
  const expected = expectedHallOfFame(data);
  if (expected.errors.length > 0) {
    for (const line of expected.errors) process.stderr.write(`${line}\n`);
    process.exit(1);
  }
  if (process.argv.includes('--check')) {
    if (readFileSync(page, 'utf8').replace(/\r\n/g, '\n') !== expected.page) {
      process.stderr.write('docs/guide/hall-of-fame.md is not what docs/security/credits.json says. Run: node --disable-proto=throw scripts/hall-of-fame.ts\n');
      process.exit(1);
    }
    process.stdout.write('The hall of fame is current.\n');
  } else {
    writeFileSync(page, expected.page);
    process.stdout.write('Wrote docs/guide/hall-of-fame.md.\n');
  }
}
