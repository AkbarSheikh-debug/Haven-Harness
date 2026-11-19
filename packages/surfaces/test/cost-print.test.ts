import assert from 'node:assert/strict';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { KeyStore, registerPrices, resetPrices } from '@hn/provider';
import { formatCostLine, loadPriceFile, runFleetFile, runPrint, sumJobCosts } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir } from '@hn/testkit';

/** The fake server reports 100 tokens in and 10 out for every call. At $10 and $20 per million that is $0.0012 a call. */
const FAKE_PRICE = new Map([['fake', { input: 10, output: 20, cacheRead: 1, cacheWrite: 5 }]]);
const PER_CALL = 0.0012;
const near = (actual: number | null | undefined, want: number): void => assert.ok(typeof actual === 'number' && Math.abs(actual - want) < 1e-9, `${actual} is not ${want}`);
afterEach(() => resetPrices());

interface Line {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  cacheHitRatio: number | null;
  dollars: number | null;
  unpriced: string[];
}
interface PrintReport {
  cost: { total: Line; byRole: (Line & { role: string })[]; byModel: (Line & { model: string })[]; prices: { source: string; checked: string | null } };
}

async function printJson(root: string, baseUrl: string, prompt: string): Promise<PrintReport> {
  const out: string[] = [];
  const before = process.env['HN_PARENT_SESSION'];
  try {
    const code = await runPrint({ workdir: root, mode: 'read-only', model: 'fake', baseUrl, window: 64_000, env: { HN_HOME: join(root, '.home') }, verify: 'off', prompt, json: true }, KeyStore.capture({}), (text) => (out.push(text), true));
    assert.equal(code, 0);
  } finally {
    if (before === undefined) delete process.env['HN_PARENT_SESSION'];
    else process.env['HN_PARENT_SESSION'] = before;
  }
  return JSON.parse(out.join('').trim().split('\n').at(-1) ?? '{}') as PrintReport;
}

describe('hn -p --json carries the cost report', () => {
  it('reports a root-only run exactly: two calls of 100 in and 10 out, and what they cost', { timeout: 120_000 }, async () => {
    const model = await startFakeOpenAI((request) => (request.messages.filter((message) => message.role === 'tool').length === 0 ? { calls: [{ id: 'r1', name: 'read_file', args: { path: 'a.txt' } }] } : { text: 'ok' }));
    try {
      await withTempDir(async (dir) => {
        const root = await realpath(dir);
        await writeFile(join(root, 'a.txt'), 'hello\n');
        registerPrices(FAKE_PRICE, '2026-11-19');
        const { cost } = await printJson(root, model.url, 'read a.txt');
        assert.deepEqual([cost.total.input, cost.total.output, cost.total.cacheRead, cost.total.cacheWrite], [200, 20, 0, 0]);
        near(cost.total.dollars, 2 * PER_CALL);
        assert.equal(cost.total.cacheHitRatio, 0);
        assert.deepEqual(cost.byRole.map((line) => line.role), ['main']);
        assert.deepEqual(cost.byModel.map((line) => line.model), ['fake']);
        assert.equal(cost.prices.checked, '2026-11-19');
      });
    } finally {
      await model.close();
    }
  });

  it('shows unknown dollars, not 0, when the model has no price, and still counts the tokens', { timeout: 120_000 }, async () => {
    const model = await startFakeOpenAI(() => ({ text: 'hello' }));
    try {
      await withTempDir(async (dir) => {
        const { cost } = await printJson(await realpath(dir), model.url, 'say hello');
        assert.deepEqual([cost.total.input, cost.total.output], [100, 10]);
        assert.equal(cost.total.dollars, null);
        assert.deepEqual(cost.total.unpriced, ['fake']);
      });
    } finally {
      await model.close();
    }
  });

  it('splits a run that used a background scout by role: the child is its own row, and the total is the sum', { timeout: 120_000 }, async () => {
    const model = await startFakeOpenAI((request) => {
      const system = String(request.messages[0]?.content ?? '');
      if (system.includes('You are a scout')) return { text: 'SCOUT-REPORT' };
      const all = JSON.stringify(request.messages);
      if (all.includes('Background children have settled')) return { text: 'FINAL' };
      if (request.messages.at(-1)?.role === 'tool') return { text: 'Started it; ending my turn.' };
      return { calls: [{ id: 'b1', name: 'subagent', args: { agent: 'scout', task: 'Look around.', background: true } }] };
    });
    try {
      await withTempDir(async (dir) => {
        registerPrices(FAKE_PRICE, '2026-11-19');
        const { cost } = await printJson(await realpath(dir), model.url, 'Start a background scout.');
        const main = cost.byRole.find((line) => line.role === 'main');
        const scout = cost.byRole.find((line) => line.role === 'scout');
        assert.ok(main !== undefined && scout !== undefined, JSON.stringify(cost.byRole.map((line) => line.role)));
        // The scout made one call. The root made three: start the scout, end its turn, use the report.
        assert.deepEqual([scout.input, scout.output], [100, 10]);
        assert.deepEqual([main.input, main.output], [300, 30]);
        near(scout.dollars, PER_CALL);
        near(main.dollars, 3 * PER_CALL);
        assert.deepEqual([cost.total.input, cost.total.output], [400, 40]);
        near(cost.total.dollars, 4 * PER_CALL);
      });
    } finally {
      await model.close();
    }
  });
});

describe('fleet results carry the cost report', () => {
  it('puts each job\'s cost in its result row, keeps it when a second run takes the job from the file, and sums to one line', { timeout: 180_000 }, async () => {
    const model = await startFakeOpenAI((request) => (request.messages.filter((message) => message.role === 'tool').length === 0 ? { calls: [{ id: 'w1', name: 'write_file', args: { path: 'done.txt', content: 'x\n' } }] } : { text: 'finished' }));
    try {
      await withTempDir(async (dir) => {
        const root = await realpath(dir);
        registerPrices(FAKE_PRICE, '2026-11-19');
        for (const name of ['repo-1', 'repo-2']) await mkdir(join(root, name));
        await writeFile(join(root, 'fleet.json'), JSON.stringify({ model: 'fake', baseUrl: model.url, window: 64_000, jobs: [1, 2].map((n) => ({ name: `job-${n}`, workdir: `repo-${n}`, task: `TASK job-${n}: write done.txt` })) }));
        const options = { keys: KeyStore.capture({}), defaults: { model: 'fake', baseUrl: model.url, window: 64_000 } };
        const first = await runFleetFile(join(root, 'fleet.json'), options);
        assert.equal(first.counts.done, 2);
        for (const result of first.results) {
          assert.deepEqual([result.cost?.total.input, result.cost?.total.output], [200, 20], `${result.name} made a write call and a final answer`);
          near(result.cost?.total.dollars, 2 * PER_CALL);
          assert.deepEqual(result.cost?.byRole.map((line) => line.role), ['main']);
        }
        const requestsAfterFirst = model.requests.length;
        const second = await runFleetFile(join(root, 'fleet.json'), options);
        assert.equal(model.requests.length, requestsAfterFirst, 'the second run took both jobs from the results file');
        assert.deepEqual(second.results.map((result) => result.cost), first.results.map((result) => result.cost), 'the file kept each job\'s cost');
        const sum = sumJobCosts(second.results);
        assert.deepEqual([sum?.input, sum?.output], [400, 40]);
        near(sum?.dollars, 4 * PER_CALL);
        assert.match(formatCostLine(sum as Line), /^Cost: \$0\.0048, 400 in, 40 out, 0% cached\.$/);
      });
    } finally {
      await model.close();
    }
  });

  it('sums to unknown, naming the model, when any job ran on an unpriced model, and to nothing when no job reported a cost', () => {
    const line = (dollars: number | null, unpriced: string[]): { cost: { total: Line; byRole: [] } } => ({ cost: { total: { input: 100, output: 10, cacheRead: 0, cacheWrite: 0, cacheHitRatio: 0, dollars, unpriced }, byRole: [] } });
    const sum = sumJobCosts([line(0.5, []), line(null, ['local-qwen']), line(null, ['alpha'])]);
    assert.equal(sum?.dollars, null);
    assert.deepEqual(sum?.unpriced, ['alpha', 'local-qwen']);
    assert.equal(formatCostLine(sum as Line), 'Cost: unknown (no price for alpha, local-qwen), 300 in, 30 out, 0% cached.');
    assert.equal(sumJobCosts([{}, {}]), null);
    assert.equal(sumJobCosts([]), null);
  });
});

describe('the price file in the home folder', () => {
  it('is silent when there is none, uses a good one, and says what is wrong with a bad one without stopping', async () => {
    await withTempDir(async (home) => {
      const warnings: string[] = [];
      await loadPriceFile(home, (text) => warnings.push(text));
      assert.equal(warnings.length, 0);
      await writeFile(join(home, 'prices.json'), JSON.stringify({ checked: '2026-11-19', prices: { 'my-local': { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, broken: { input: 1 } } }));
      await loadPriceFile(home, (text) => warnings.push(text));
      assert.equal(warnings.length, 1);
      assert.match(warnings[0] as string, /^hn: prices\.json: broken: it needs exactly input, output, cacheRead and cacheWrite/);
      const { costOf } = await import('@hn/provider');
      assert.equal(costOf('my-local', { input: 1000, output: 1000, cacheRead: 0, cacheWrite: 0 }), 0, 'a price of zero, given on purpose, is a price');
      assert.equal(costOf('broken', { input: 1000, output: 0, cacheRead: 0, cacheWrite: 0 }), null, 'a refused entry is unpriced, not guessed');
    });
  });

  it('does not use a file that is not JSON or is far too large', async () => {
    await withTempDir(async (home) => {
      const warnings: string[] = [];
      await writeFile(join(home, 'prices.json'), 'not json');
      await loadPriceFile(home, (text) => warnings.push(text));
      assert.match(warnings.join(), /not JSON/);
      await writeFile(join(home, 'prices.json'), ' '.repeat(300 * 1024));
      await loadPriceFile(home, (text) => warnings.push(text));
      assert.match(warnings.join(), /larger than 262144 bytes, so it was not used/);
    });
  });
});
