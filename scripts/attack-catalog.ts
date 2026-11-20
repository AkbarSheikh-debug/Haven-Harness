// Writes the public attack catalog (docs/guide/attacks.md) from the attack registry and the test files, or checks that
// the committed page is exactly what they say. A developer tool, not part of hn. No dependencies.
//
//   node --disable-proto=throw scripts/attack-catalog.ts            # rewrite the page
//   node --disable-proto=throw scripts/attack-catalog.ts --check    # exit 1 if the page is stale, or the registry and the tests disagree
//
// Every registry name must have a test whose title carries it; the page links that test's file. A test titled
// `attack: <name>` for a name that is not in the registry is an error too, so an attack cannot be tested and left off the
// public list, or listed with no test.

import { readFileSync, writeFileSync } from 'node:fs';
import { ATTACKS } from '../packages/testkit/src/attack-registry.ts';
import { ATTACK_PAGE, describeProblems, expectedPage, hasProblems } from '../packages/testkit/src/attack-catalog.ts';

if (import.meta.main) {
  const check = process.argv.includes('--check');
  const { page, problems } = expectedPage();
  if (hasProblems(problems)) {
    for (const line of describeProblems(problems)) process.stderr.write(`${line}\n`);
    process.exit(1);
  }
  if (check) {
    if (readFileSync(ATTACK_PAGE, 'utf8').replace(/\r\n/g, '\n') !== page) {
      process.stderr.write('docs/guide/attacks.md is not what the registry and tests say. Run: node --disable-proto=throw scripts/attack-catalog.ts\n');
      process.exit(1);
    }
    process.stdout.write(`The attack catalog is current (${ATTACKS.length} attacks).\n`);
  } else {
    writeFileSync(ATTACK_PAGE, page);
    process.stdout.write(`Wrote docs/guide/attacks.md (${ATTACKS.length} attacks).\n`);
  }
}
