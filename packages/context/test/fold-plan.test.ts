import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { toolCallsOf, type SessionEvent } from '@hn/core';
import { computeBudget, planFold, SHRUNK_ROW_TOKENS, UnbalancedFoldError, type Budget, type FoldPlan } from '@hn/context';
import { seededRandom } from '@hn/testkit';

/** Synthetic rows carry their own size, so the planner is tested apart from the estimator. */
const sizeOf = (row: SessionEvent): number => row.data['tokens'] as number;

class History {
  readonly rows: SessionEvent[] = [];
  #seq = 0;
  #call = 0;

  #push(type: SessionEvent['type'], data: Record<string, unknown>): SessionEvent {
    this.#seq += 1;
    const origin = type === 'user/message' ? 'user' : type === 'tool/result' ? 'tool-output' : 'model-derived';
    const row: SessionEvent = { seq: this.#seq, ts: '2026-11-05T00:00:00.000Z', type, origin, data };
    this.rows.push(row);
    return row;
  }

  pinned(tokens: number): void {
    this.#push('user/message', { tokens, pinned: true });
  }

  user(tokens: number): void {
    this.#push('user/message', { tokens });
  }

  /** One step: an assistant row with one call per result, then the results in `order`. */
  step(tokens: number, results: readonly number[], order?: readonly number[]): void {
    const ids = results.map(() => `c${(this.#call += 1)}`);
    this.#push('assistant/message', { tokens, toolCalls: ids.map((id) => ({ id, name: 'read_file', args: {} })) });
    for (const index of order ?? results.map((_, i) => i)) {
      this.#push('tool/result', { tokens: results[index], callId: ids[index] });
    }
  }

  total(fixed: number): number {
    return fixed + this.rows.reduce((sum, row) => sum + sizeOf(row), 0);
  }
}

const WINDOWS: readonly [number, number][] = [
  [32_000, 4_000],
  [64_000, 8_000],
  [128_000, 32_000],
  [200_000, 32_000],
];

function groupOf(plan: FoldPlan): Map<number, string> {
  const group = new Map<number, string>();
  for (const name of ['pinned', 'head', 'middle', 'tail'] as const) {
    for (const seq of plan[name]) {
      assert.equal(group.has(seq), false, `seq ${seq} is in two groups`);
      group.set(seq, name);
    }
  }
  return group;
}

function assertPairsWhole(rows: readonly SessionEvent[], plan: FoldPlan): void {
  const group = groupOf(plan);
  const callRow = new Map<string, number>();
  for (const row of rows) for (const call of toolCallsOf(row)) callRow.set(call.id, row.seq);
  for (const row of rows) {
    if (row.type !== 'tool/result') continue;
    const call = callRow.get(row.data['callId'] as string) as number;
    assert.equal(group.get(row.seq), group.get(call), `call ${call} and result ${row.seq} were split`);
  }
}

function plan(history: History, budget: Budget, fixed: number, priorFolds = 0): FoldPlan {
  return planFold({ rows: history.rows, budget, keep: budget.keep, fixedTokens: fixed, priorFolds, estimate: sizeOf });
}

/** A random long session that has just crossed T, ending at a step boundary. */
function randomHistory(random: () => number, budget: Budget, fixed: number): History {
  const T = budget.trigger;
  const pick = (low: number, high: number): number => Math.floor(low + random() * (high - low));
  const history = new History();
  for (let i = pick(0, 3); i > 0; i -= 1) history.pinned(pick(10, Math.floor(0.03 * T)));
  history.user(random() < 0.2 ? pick(1_000, Math.floor(0.4 * T)) : pick(5, 800));
  while (history.total(fixed) < T) {
    const calls = pick(0, 4);
    const results = Array.from({ length: calls }, () =>
      random() < 0.1 ? pick(1_000, Math.floor(0.4 * T)) : pick(5, 1_500),
    );
    const order = results.map((_, i) => i).sort(() => random() - 0.5);
    history.step(pick(5, Math.min(budget.output, Math.floor(0.08 * T))), results, order);
    if (calls === 0 || random() < 0.15) history.user(pick(5, 600));
  }
  return history;
}

describe('fold planner', () => {
  it('property: never splits a pair, keeps rows in order and the newest step, changes something, lands under T', () => {
    const random = seededRandom(20261105);
    const runs = Number(process.env['HN_FUZZ_RUNS'] ?? 400);
    for (let run = 0; run < runs; run += 1) {
      const [window, output] = WINDOWS[run % WINDOWS.length] as [number, number];
      const budget = computeBudget({ window, modelMaxOutput: output });
      const fixed = Math.floor(budget.trigger * (0.02 + random() * 0.08));
      const history = randomHistory(random, budget, fixed);
      const result = plan(history, budget, fixed, run % 3 === 0 ? 1 : 0);
      const label = `run ${run}, window ${window}`;

      assertPairsWhole(history.rows, result);
      const order = [...result.head, ...result.middle, ...result.tail];
      const conversational = history.rows.filter((row) => row.data['pinned'] !== true).map((row) => row.seq);
      assert.deepEqual(order, conversational, label);
      assert.ok(result.middle.length > 0 || result.shrink.length > 0, `${label}: a no-op above T`);
      assert.ok(result.tokensAfter < budget.trigger, `${label}: ${result.tokensAfter} >= ${budget.trigger}`);
      const newest = (history.rows.at(-1) as SessionEvent).seq;
      assert.ok(result.tail.includes(newest) || result.head.includes(newest), `${label}: the newest step was folded`);
    }
  });

  it('protects the first three conversational rows, not counting pinned prefix rows', () => {
    const budget = computeBudget({ window: 32_000, modelMaxOutput: 4_000 });
    const history = new History();
    history.pinned(500);
    history.user(100);
    history.step(50, []);
    history.user(100);
    for (let i = 0; i < 40; i += 1) history.step(50, [600]);
    const result = plan(history, budget, 1_000);
    assert.deepEqual(result.pinned, [1]);
    assert.deepEqual(result.head, [2, 3, 4]);
  });

  it('grows the head forward while it ends on an unanswered call', () => {
    const budget = computeBudget({ window: 32_000, modelMaxOutput: 4_000 });
    const history = new History();
    history.user(100);
    history.step(50, [100, 100, 100]);
    for (let i = 0; i < 40; i += 1) history.step(50, [600]);
    const result = plan(history, budget, 1_000);
    assert.deepEqual(result.head, [1, 2, 3, 4, 5]);
  });

  it('keeps a pair larger than half of T whole in the tail, shrinking its results instead of splitting it', () => {
    const budget = computeBudget({ window: 32_000, modelMaxOutput: 4_000 });
    const history = new History();
    history.user(100);
    for (let i = 0; i < 20; i += 1) history.step(50, [500]);
    history.step(100, [7_000, 7_000]);
    const result = plan(history, budget, 1_000);
    assertPairsWhole(history.rows, result);
    const last = history.rows.slice(-3).map((row) => row.seq);
    for (const seq of last) assert.ok(result.tail.includes(seq), `seq ${seq} should stay in the tail`);
    assert.ok(result.shrink.some((seq) => last.includes(seq)));
  });

  it('refuses to plan mid-step, while a call has no result', () => {
    const budget = computeBudget({ window: 32_000, modelMaxOutput: 4_000 });
    const history = new History();
    history.user(100);
    history.step(50, [100]);
    history.rows.pop();
    assert.throws(() => plan(history, budget, 1_000), UnbalancedFoldError);
  });

  it('keeps a huge first paste on the first fold and cuts it on the second', () => {
    const budget = computeBudget({ window: 64_000, modelMaxOutput: 8_000 });
    const history = new History();
    history.user(15_000);
    for (let i = 0; i < 60; i += 1) history.step(50, [700]);
    assert.equal(plan(history, budget, 1_000, 0).shrink.includes(1), false);
    const second = plan(history, budget, 1_000, 1);
    assert.ok(second.shrink.includes(1));
    assert.ok(second.tokensAfter < budget.trigger);
  });

  it('counts a shrunk result at the stub size', () => {
    const budget = computeBudget({ window: 32_000, modelMaxOutput: 4_000 });
    const history = new History();
    history.user(100);
    history.step(50, [30_000]);
    const result = plan(history, budget, 500);
    assert.ok(result.shrink.includes(3));
    assert.equal(result.tokensAfter, 500 + 100 + 50 + SHRUNK_ROW_TOKENS + budget.summaryCap);
  });
});
