import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computeBudget,
  fitLoad,
  headroomFor,
  PrefixTooLargeError,
  summaryBudget,
  WindowTooSmallError,
} from '@hn/context';

/** The five rows of the compaction table. "k" is 1,000. */
const GOLDEN = [
  { window: 200_000, output: 32_000, trigger: 102_464, keep: 26_880 },
  { window: 1_000_000, output: 32_000, trigger: 800_000, keep: 154_880 },
  { window: 128_000, output: 32_000, trigger: 64_000, keep: 15_360 },
  { window: 64_000, output: 8_000, trigger: 51_200, keep: 8_960 },
  { window: 32_000, output: 4_000, trigger: 23_904, keep: 4_480 },
] as const;

describe('compaction budget', () => {
  for (const row of GOLDEN) {
    it(`golden: W ${row.window} / O ${row.output} gives T ${row.trigger} and keep ${row.keep}`, () => {
      const budget = computeBudget({ window: row.window, modelMaxOutput: row.output });
      assert.equal(budget.trigger, row.trigger);
      assert.equal(budget.keep, row.keep);
      assert.equal(budget.output, row.output);
    });
  }

  it('matches DSH exactly once W - O reaches 129,536, and never goes negative below it', () => {
    assert.equal(headroomFor(161_536, 32_000), 65_536);
    assert.equal(headroomFor(500_000, 32_000), 65_536);
    for (let window = 16_000; window <= 300_000; window += 997) {
      const budget = computeBudget({ window, modelMaxOutput: Math.floor(window / 8) });
      assert.ok(budget.trigger > 0, `window ${window}`);
      assert.ok(budget.trigger + budget.output + budget.headroom <= window, `window ${window}`);
      assert.ok(budget.keep < budget.trigger, `window ${window}`);
    }
  });

  it('uses the configured output request, never the advertised maximum on its own', () => {
    assert.equal(computeBudget({ window: 1_000_000, modelMaxOutput: 128_000 }).output, 32_000);
    assert.equal(computeBudget({ window: 200_000, modelMaxOutput: 128_000, maxOutput: 16_000 }).output, 16_000);
    assert.equal(computeBudget({ window: 32_000, modelMaxOutput: 4_096, maxOutput: 32_000 }).output, 4_096);
  });

  it('refuses a window under 16k', () => {
    assert.throws(() => computeBudget({ window: 15_999, modelMaxOutput: 2_000 }), WindowTooSmallError);
    assert.throws(() => computeBudget({ window: Number.NaN, modelMaxOutput: 2_000 }), WindowTooSmallError);
  });

  it('takes per-model overrides and rejects nonsense ones', () => {
    const budget = computeBudget({
      window: 200_000,
      modelMaxOutput: 32_000,
      overrides: { thresholdRatio: 0.5, retainRatio: 0.1, headroomTokens: 10_000 },
    });
    assert.equal(budget.trigger, 100_000);
    assert.equal(budget.keep, 16_800);
    assert.throws(() => computeBudget({ window: 200_000, modelMaxOutput: 32_000, overrides: { retainRatio: 1.5 } }));
    assert.throws(() => computeBudget({ window: 200_000, modelMaxOutput: 32_000, overrides: { headroomTokens: -1 } }));
  });

  it('sizes the summary at max(2,000, min(20%, 10,000, 0.1T)) and never over 0.1T', () => {
    const big = computeBudget({ window: 200_000, modelMaxOutput: 32_000 });
    assert.equal(summaryBudget(big, 5_000), 2_000);
    assert.equal(summaryBudget(big, 40_000), 8_000);
    assert.equal(summaryBudget(big, 400_000), 10_000);
    const small = computeBudget({ window: 16_000, modelMaxOutput: 2_000 });
    assert.ok(summaryBudget(small, 400_000) <= small.summaryCap);
  });

  it('passes the load check unchanged when everything fits', () => {
    const budget = computeBudget({ window: 200_000, modelMaxOutput: 32_000 });
    assert.deepEqual(fitLoad(budget, { system: 3_000, tools: 1_000, head: 2_000, summary: 8_000 }), {
      keep: 26_880,
      summary: 8_000,
      scaled: false,
    });
  });

  it('shrinks keep and summary together when the prefix is heavy, and refuses when nothing fits', () => {
    const budget = computeBudget({ window: 32_000, modelMaxOutput: 4_000 });
    const parts = { system: 6_000, tools: 4_000, head: 6_000, summary: 2_000 };
    const fit = fitLoad(budget, parts);
    assert.equal(fit.scaled, true);
    const total = parts.system + parts.tools + parts.head + fit.summary + fit.keep + budget.summaryCap;
    assert.ok(total <= budget.trigger, `${total} > ${budget.trigger}`);
    assert.throws(() => fitLoad(budget, { ...parts, head: 20_000 }), PrefixTooLargeError);
  });
});
