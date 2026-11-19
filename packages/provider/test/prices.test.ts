import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { costOf, parsePriceFile, priceOf, priceTableInfo, registerPrices, resetPrices } from '@hn/provider';

afterEach(() => resetPrices());

const USAGE = { input: 1_000_000, output: 500_000, cacheRead: 2_000_000, cacheWrite: 400_000 };
const GOOD = { input: 1, output: 5, cacheRead: 0.1, cacheWrite: 1.25 };
const file = (body: unknown): string => JSON.stringify(body);

describe('prices', () => {
  it('prices a known model by hand: 1M in, 0.5M out, 2M read, 0.4M written is $8.40 on sonnet', () => {
    // 1 * 2 + 0.5 * 10 + 2 * 0.2 + 0.4 * 2.5 = 2 + 5 + 0.4 + 1
    assert.equal(Math.round((costOf('claude-sonnet-5-5', USAGE) as number) * 100) / 100, 8.4);
  });

  it('gives null, never a number, for an unknown model, including names that exist on every object', () => {
    for (const model of ['mystery', '', 'constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      assert.equal(costOf(model, USAGE), null, JSON.stringify(model));
      assert.equal(priceOf(model), null, JSON.stringify(model));
    }
  });

  it('reads a dated price file, and refuses a file nobody dated', () => {
    const parsed = parsePriceFile(file({ checked: '2026-11-19', prices: { 'my-model': GOOD } }));
    assert.deepEqual(parsed.problems, []);
    assert.equal(parsed.checked, '2026-11-19');
    assert.deepEqual(parsed.prices.get('my-model'), GOOD);
    const undated = parsePriceFile(file({ prices: { 'my-model': GOOD } }));
    assert.equal(undated.prices.size, 0, 'a table nobody dated is not used');
    assert.match(undated.problems.join(), /"checked" must be the date/);
    assert.match(parsePriceFile(file({ checked: 'yesterday', prices: {} })).problems.join(), /"checked"/);
  });

  it('refuses each entry that is not exactly four numbers in range, and names it, keeping the good ones', () => {
    const parsed = parsePriceFile(
      file({
        checked: '2026-11-19',
        prices: {
          good: GOOD,
          'missing-field': { input: 1, output: 5, cacheRead: 0.1 },
          'extra-field': { ...GOOD, bonus: 1 },
          negative: { ...GOOD, input: -1 },
          huge: { ...GOOD, output: 10_001 },
          'a-string': { ...GOOD, input: '1' },
          'null-entry': null,
          'array-entry': [1, 2, 3, 4],
        },
      }),
    );
    assert.deepEqual([...parsed.prices.keys()], ['good']);
    for (const name of ['missing-field', 'extra-field', 'negative', 'huge', 'a-string', 'null-entry', 'array-entry']) assert.ok(parsed.problems.some((problem) => problem.startsWith(`${name}:`)), `${name} was not named`);
  });

  it('refuses a file that is not JSON, not an object, or has no price table', () => {
    assert.match(parsePriceFile('{ nope').problems.join(), /not JSON/);
    assert.match(parsePriceFile('[1,2]').problems.join(), /not an object/);
    assert.match(parsePriceFile(file({ checked: '2026-11-19' })).problems.join(), /"prices" must be an object/);
    assert.match(parsePriceFile(file({ checked: '2026-11-19', prices: [1] })).problems.join(), /"prices" must be an object/);
  });

  it('refuses a model name that is empty, huge or has control characters', () => {
    const parsed = parsePriceFile(file({ checked: '2026-11-19', prices: { '': GOOD, ['x'.repeat(201)]: GOOD, 'bad\u0007name': GOOD, fine: GOOD } }));
    assert.deepEqual([...parsed.prices.keys()], ['fine']);
    assert.equal(parsed.problems.length, 3);
  });

  it("lets a person's price win over the built-in one, model by model, and shows where the table came from", () => {
    assert.equal(priceTableInfo().source, 'built-in');
    registerPrices(new Map([['claude-sonnet-5-5', { input: 100, output: 0, cacheRead: 0, cacheWrite: 0 }], ['my-model', GOOD]]), '2026-11-19');
    assert.equal(costOf('claude-sonnet-5-5', { input: 1_000_000, output: 0, cacheRead: 0, cacheWrite: 0 }), 100);
    assert.equal(costOf('claude-opus-5-5', { input: 1_000_000, output: 0, cacheRead: 0, cacheWrite: 0 }), 4, 'the other built-in is untouched');
    assert.equal(costOf('my-model', { input: 1_000_000, output: 0, cacheRead: 0, cacheWrite: 0 }), 1);
    const info = priceTableInfo();
    assert.equal(info.source, 'built-in plus file');
    assert.equal(info.checked, '2026-11-19');
    assert.deepEqual(info.models, ['claude-opus-5-5', 'claude-sonnet-5-5', 'my-model']);
    resetPrices();
    assert.equal(costOf('my-model', USAGE), null);
  });
});
