import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { AREAS, ATTACKS, type Attack } from '@hn/testkit';
import { hasProblems, namesIn, reconcile, renderCatalog } from '../../../scripts/attack-catalog.ts';

const entry = (name: string, area: string = AREAS[0], description = 'Something is tried and must not happen.'): Attack => ({ name, area, description });

describe('the attack catalog checker', () => {
  it('reads the names a test title claims, and stops at the first word that is not a name', () => {
    assert.deepEqual(namesIn('attack: a_b (words after)'), ['a_b']);
    assert.deepEqual(namesIn('attack: a_b c_d - shows things'), ['a_b', 'c_d']);
    assert.deepEqual(namesIn('attack: a_b. is refused on a host'), ['a_b']);
    assert.deepEqual(namesIn('a_b: an approved file that changes'), ['a_b']);
    assert.deepEqual(namesIn('reads a file'), []);
    assert.deepEqual(namesIn('attack: plain words only'), []);
  });

  it('is clean when every registry name has a test and every attack-titled test is registered', () => {
    const { files, problems } = reconcile([{ file: 'packages/x/test/a.test.ts', title: 'attack: one_attack (words)' }], [entry('one_attack')]);
    assert.equal(hasProblems(problems), false);
    assert.equal(files.get('one_attack'), 'packages/x/test/a.test.ts');
  });

  it('reports a registry name with no test', () => {
    const { problems } = reconcile([{ file: 'packages/x/test/a.test.ts', title: 'attack: one_attack' }], [entry('one_attack'), entry('two_attack')]);
    assert.deepEqual(problems.untested, ['two_attack']);
  });

  it('reports a test titled as an attack that the registry does not list', () => {
    const { problems } = reconcile(
      [
        { file: 'packages/x/test/a.test.ts', title: 'attack: one_attack' },
        { file: 'packages/x/test/a.test.ts', title: 'attack: secret_attack - words' },
      ],
      [entry('one_attack')],
    );
    assert.deepEqual(problems.unregistered, ['secret_attack']);
  });

  it('reports a name listed twice, an unknown area and a missing description', () => {
    const { problems } = reconcile([{ file: 'f', title: 'attack: a_b' }], [entry('a_b'), entry('a_b'), entry('c_d', 'Nowhere'), entry('e_f', AREAS[0], 'short')]);
    assert.deepEqual(problems.duplicates, ['a_b']);
    assert.deepEqual(problems.badArea, ['c_d']);
    assert.deepEqual(problems.noDescription, ['e_f']);
  });

  it('writes one row per attack with its description and a link to its test, and says MISSING rather than inventing a link', () => {
    const page = renderCatalog(new Map([['one_attack', 'packages/x/test/a.test.ts']]), [entry('one_attack'), entry('two_attack')]);
    assert.match(page, /\| `one_attack` \| Something is tried and must not happen\. \| \[packages\/x\/test\/a\.test\.ts\]\(\.\.\/\.\.\/packages\/x\/test\/a\.test\.ts\) \|/);
    assert.match(page, /\| `two_attack` \| .* \| MISSING \|/);
    assert.match(page, /^# The attack catalog\n/);
  });

  it('keeps a pipe in a description from breaking the table', () => {
    const page = renderCatalog(new Map(), [entry('one_attack', AREAS[0], 'A | B is tried and must not happen.')]);
    assert.match(page, /A \\\| B is tried/);
  });

  it('has public wording only: no internal planning words in any description or area', () => {
    const planning = /\bphase \d|\bdecision \d|master plan|section \d+\.\d|\binvariant \d/i;
    for (const attack of ATTACKS) assert.doesNotMatch(`${attack.name} ${attack.area} ${attack.description}`, planning, attack.name);
  });

  it('gives every attack a name in the form the tests use', () => {
    for (const attack of ATTACKS) assert.match(attack.name, /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/, attack.name);
  });
});
