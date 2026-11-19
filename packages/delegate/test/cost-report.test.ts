import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { costReport, chargeData, familySpend, formatCostReport, ROOT_ROLE } from '@hn/delegate';
import { registerPrices, resetPrices, type Usage } from '@hn/provider';
import { withTempDir } from '@hn/testkit';
import { ScriptedProvider, config, fakeTools, open, text, toolCalls } from '../../loop/test/helpers.ts';

/** $3 in, $15 out, $0.30 cache read, $3.75 cache write per million tokens, for the model called `fake`. */
const PRICE = { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 };
const near = (actual: number | null, want: number): void => assert.ok(actual !== null && Math.abs(actual - want) < 1e-9, `${actual} is not ${want}`);
afterEach(() => resetPrices());

// Worked by hand, in millionths of a dollar:
//   turn 1  2000 in, 1000 out, 8000 read        = 6000 + 15000 + 2400          = 23400 -> $0.0234
//   turn 2   500 in,  500 out, 9500 read, 1000 w = 1500 +  7500 + 2850 + 3750  = 15600 -> $0.0156
//   planner 1000 in,  100 out, 3000 read         = 3000 +  1500 +  900          =  5400 -> $0.0054
const TURN_1: Usage = { input: 2_000, output: 1_000, cacheRead: 8_000, cacheWrite: 0 };
const TURN_2: Usage = { input: 500, output: 500, cacheRead: 9_500, cacheWrite: 1_000 };
const PLANNER: Usage = { input: 1_000, output: 100, cacheRead: 3_000, cacheWrite: 0 };
const SCOUT: Usage = { input: 4_000, output: 300, cacheRead: 0, cacheWrite: 0 };

async function sessionWithCrew(dir: string, id: string, withScout: boolean) {
  registerPrices(new Map([['fake', PRICE]]), '2026-11-19');
  const provider = new ScriptedProvider([{ ...toolCalls(['c1', 'read_file']), usage: TURN_1 }, { ...text('done'), usage: TURN_2 }]);
  const agent = await open(dir, config(provider, fakeTools()), id);
  await agent.run('look');
  const crew: [string, string, string, Usage][] = [['c-plan', 'planner', 'fake', PLANNER], ...(withScout ? ([['c-scout', 'scout', 'qwen-local', SCOUT]] as [string, string, string, Usage][]) : [])];
  for (const [child, role, model, usage] of crew) {
    agent.record('subagent/catalog', { kind: 'spawned', child, role, model });
    agent.record('budget/charge', chargeData(child, model, usage, 'settled'));
  }
  return agent;
}

describe('the cost report', () => {
  it('splits a real session and its children by role, with the cache hit ratio and dollars worked out by hand', async () => {
    await withTempDir(async (dir) => {
      const agent = await sessionWithCrew(dir, 'cost-1', false);
      const report = costReport(agent.events);
      const main = report.byRole.find((line) => line.role === ROOT_ROLE);
      assert.deepEqual([main?.input, main?.output, main?.cacheRead, main?.cacheWrite], [2_500, 1_500, 17_500, 1_000]);
      near(main?.dollars ?? null, 0.039);
      near(main?.cacheHitRatio ?? null, 17_500 / 21_000);
      const planner = report.byRole.find((line) => line.role === 'planner');
      assert.deepEqual([planner?.input, planner?.output, planner?.cacheRead], [1_000, 100, 3_000]);
      near(planner?.dollars ?? null, 0.0054);
      near(planner?.cacheHitRatio ?? null, 0.75);
      near(report.total.dollars, 0.0444);
      assert.deepEqual(report.byRole.map((line) => line.role), ['main', 'planner']);
      assert.deepEqual(report.byModel.map((line) => line.model), ['fake']);
      assert.equal(report.total.unpriced.length, 0);
      assert.equal(report.prices.checked, '2026-11-19');
      await agent.close();
    });
  });

  it('agrees with the budget ledger to the last token and the last cent', async () => {
    await withTempDir(async (dir) => {
      const agent = await sessionWithCrew(dir, 'cost-2', false);
      const family = familySpend(agent.events);
      const { total } = costReport(agent.events);
      assert.deepEqual([total.input, total.output, total.cacheRead, total.cacheWrite], [family.input, family.output, family.cacheRead, family.cacheWrite]);
      near(total.dollars, family.dollars as number);
      await agent.close();
    });
  });

  it('shows unknown dollars, never zero, for a model with no price, and names it', async () => {
    await withTempDir(async (dir) => {
      const agent = await sessionWithCrew(dir, 'cost-3', true);
      const report = costReport(agent.events);
      const scout = report.byRole.find((line) => line.role === 'scout');
      assert.deepEqual([scout?.input, scout?.output], [4_000, 300], 'tokens are always exact');
      assert.equal(scout?.dollars, null);
      assert.deepEqual(scout?.unpriced, ['qwen-local']);
      assert.equal(scout?.cacheHitRatio, 0, 'it read 4000 tokens in and none came from the cache');
      assert.equal(report.total.dollars, null, 'one unknown makes the total unknown');
      assert.deepEqual(report.total.unpriced, ['qwen-local']);
      near(report.byRole.find((line) => line.role === 'main')?.dollars ?? null, 0.039);
      near(report.byRole.find((line) => line.role === 'planner')?.dollars ?? null, 0.0054);
      const shown = formatCostReport(report);
      assert.match(shown, /scout .*unknown \(no price for qwen-local\)/);
      assert.match(shown, /total .*unknown \(no price for qwen-local\)/);
      assert.doesNotMatch(shown, /scout .*\$0\.0000/);
      await agent.close();
    });
  });

  it('is the same from the log alone: after a resume it reads the same rows', async () => {
    await withTempDir(async (dir) => {
      const agent = await sessionWithCrew(dir, 'cost-4', true);
      const live = costReport(agent.events);
      await agent.close();
      const resumed = await open(dir, config(new ScriptedProvider([text('again')]), fakeTools()), 'cost-4');
      assert.deepEqual(costReport(resumed.events), live);
      await resumed.close();
    });
  });

  it('has no cache ratio, rather than a made-up one, when nothing was read in', () => {
    assert.equal(costReport([]).total.cacheHitRatio, null);
    assert.deepEqual(costReport([]).byRole, []);
    near(costReport([]).total.dollars, 0);
  });

  it('keeps a role called __proto__ or constructor as an ordinary row, and files a child nobody catalogued under "unknown"', async () => {
    await withTempDir(async (dir) => {
      registerPrices(new Map([['fake', PRICE]]), '2026-11-19');
      const agent = await open(dir, config(new ScriptedProvider([text('ok')]), fakeTools()), 'cost-5');
      await agent.run('hi');
      const small: Usage = { input: 10, output: 1, cacheRead: 0, cacheWrite: 0 };
      for (const [child, role] of [['x1', '__proto__'], ['x2', 'constructor']] as const) {
        agent.record('subagent/catalog', { kind: 'spawned', child, role, model: 'fake' });
        agent.record('budget/charge', chargeData(child, 'fake', small, 'settled'));
      }
      agent.record('budget/charge', chargeData('never-catalogued', 'fake', small, 'settled'));
      agent.record('budget/charge', { ...chargeData('lost', 'recovered', small, 'recovered'), dollars: 0.5 });
      const report = costReport(agent.events);
      assert.deepEqual(report.byRole.map((line) => line.role), ['__proto__', 'constructor', 'main', 'unknown']);
      assert.equal(report.byRole.find((line) => line.role === 'unknown')?.input, 20, 'both uncatalogued children');
      assert.ok(report.byModel.some((line) => line.model === 'recovered (model not known)'));
      await agent.close();
    });
  });
});
