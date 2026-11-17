import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ProviderError, type ModelProvider, type ModelRequest } from '@hn/provider';
import { withTempDir } from '@hn/testkit';
import { RateLimiter, chargeData, childSpend, familySpend, limitProvider, ownSpend, rateLimitsFromEnv, tokensOf } from '@hn/delegate';
import { spentTokens } from '@hn/loop';
import { ScriptedProvider, config, fakeTools, open, text, toolCalls } from '../../loop/test/helpers.ts';

/** A clock that only moves when someone sleeps on it. */
function fakeClock() {
  let now = 1_000_000;
  const slept: number[] = [];
  return {
    now: () => now,
    slept,
    advance: (ms: number) => {
      now += ms;
    },
    sleep: async (ms: number) => {
      slept.push(ms);
      now += ms;
    },
  };
}

const request = (chars: number): ModelRequest => ({ model: 'm', system: 'x'.repeat(chars), tools: [], messages: [], maxOutputTokens: 0 });

describe('the budget ledger', () => {
  it('folds its own spend from the log, and it survives a fold and a resume', async () => {
    await withTempDir(async (dir) => {
      const provider = new ScriptedProvider([toolCalls(['c1', 'read_file']), text('done')]);
      const loop = config(provider, fakeTools());
      const agent = await open(dir, loop, 'ledger-1');
      await agent.run('look');
      const before = ownSpend(agent.events);
      assert.deepEqual({ ...before, dollars: null }, { input: 20, output: 10, cacheRead: 0, cacheWrite: 0, dollars: null });
      await agent.compact();
      assert.equal(tokensOf(ownSpend(agent.events)), 30, 'a fold keeps the attempt rows');
      await agent.close();
      const resumed = await open(dir, config(new ScriptedProvider([text('again')]), fakeTools()), 'ledger-1');
      assert.equal(tokensOf(ownSpend(resumed.events)), 30, 'a resume reads the same rows');
      assert.equal((await resumed.run('more')).end, 'done');
      assert.equal(tokensOf(ownSpend(resumed.events)), 45);
      await resumed.close();
    });
  });

  it('counts children in the family through budget/charge rows, priced when the model is known', async () => {
    await withTempDir(async (dir) => {
      const agent = await open(dir, config(new ScriptedProvider([text('ok')]), fakeTools()), 'ledger-2');
      await agent.run('hi');
      agent.record('budget/charge', chargeData('child-a', 'claude-opus-5-5', { input: 1_000_000, output: 0, cacheRead: 0, cacheWrite: 0 }, 'settled'));
      agent.record('budget/charge', chargeData('child-a', 'claude-opus-5-5', { input: 0, output: 100, cacheRead: 0, cacheWrite: 0 }, 'message'));
      agent.record('budget/charge', chargeData('child-b', 'local-model', { input: 50, output: 5, cacheRead: 0, cacheWrite: 0 }, 'settled'));
      const children = childSpend(agent.events);
      assert.equal(children.get('child-a')?.dollars, 4.002);
      assert.equal(children.get('child-b')?.dollars, null, 'an unknown price is unknown, never zero');
      const family = familySpend(agent.events);
      assert.equal(tokensOf(family), 15 + 1_000_100 + 55);
      assert.equal(family.dollars, null, 'one unknown price makes the family total unknown');
      await agent.close();
    });
  });
});

describe('the token budget in the loop', () => {
  it('ends the turn as budget once the session has spent its tokens, and a resume does not reset it', async () => {
    await withTempDir(async (dir) => {
      const provider = new ScriptedProvider([toolCalls(['c1', 'read_file']), toolCalls(['c2', 'read_file']), text('never')]);
      const loop = config(provider, fakeTools(), { tokenBudget: 30 });
      const agent = await open(dir, loop, 'budget-1');
      const result = await agent.run('work');
      assert.equal(result.end, 'budget');
      assert.match(result.detail ?? '', /token budget is spent: 30 of 30/);
      assert.equal(provider.requests.length, 2);
      await agent.close();
      const resumed = await open(dir, loop, 'budget-1');
      assert.equal((await resumed.run('more')).end, 'budget');
      assert.equal(provider.requests.length, 2, 'no call after a resume either');
      await resumed.close();
    });
  });
});

describe('fresh-token budgets (fleet jobs)', () => {
  it('leaves cache reads out when a budget counts fresh tokens only', () => {
    const row = (usage: Record<string, number>) => ({ seq: 1, ts: new Date(0).toISOString(), type: 'assistant/attempt' as const, origin: 'harness' as const, data: { usage } });
    const events = [row({ input: 100, output: 20, cacheRead: 90_000, cacheWrite: 500 }), row({ input: 10, output: 5, cacheRead: 95_000, cacheWrite: 0 })];
    assert.equal(spentTokens(events), 185_635);
    assert.equal(spentTokens(events, 'fresh'), 635);
  });
});

describe('the rate limiter', () => {
  it('lets a burst through up to the per-minute limit, then makes the next caller wait', async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter({ rpm: 3, now: clock.now, sleep: clock.sleep });
    for (let i = 0; i < 3; i += 1) await limiter.acquire(10);
    assert.deepEqual(clock.slept, []);
    await limiter.acquire(10);
    assert.deepEqual(clock.slept, [20_000], 'one request refills every 20 s at 3 per minute');
  });

  it('counts tokens, and the real usage corrects the estimate', async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter({ tpm: 6_000, now: clock.now, sleep: clock.sleep });
    await limiter.acquire(1_000);
    limiter.settle(1_000, 6_000);
    await limiter.acquire(1_000);
    assert.equal(clock.slept.length, 1);
    assert.equal(clock.slept[0], 10_000, 'the bucket was overdrawn by the real count and refills at 100 tokens a second');
  });

  it('a Retry-After pauses every holder, not only the one that got the 429', async () => {
    const clock = fakeClock();
    const limiter = new RateLimiter({ now: clock.now, sleep: clock.sleep });
    let calls = 0;
    const flaky: ModelProvider = {
      route: 'fake',
      complete: async () => {
        calls += 1;
        if (calls === 1) throw new ProviderError('rate_limited', 'slow down', { status: 429, retryAfterMs: 7_000 });
        return { parts: [], stopReason: 'end', usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 }, model: 'm' };
      },
    };
    const parent = limitProvider(flaky, limiter);
    const child = limitProvider(flaky, limiter);
    await assert.rejects(parent.complete(request(10)), /slow down/);
    assert.equal(limiter.pausedUntil, clock.now() + 7_000);
    await child.complete(request(10));
    assert.deepEqual(clock.slept, [7_000], 'the other holder waited out the pause before calling');
  });

  it('stops waiting when the caller is stopped', async () => {
    const limiter = new RateLimiter({ rpm: 1 });
    await limiter.acquire(1);
    const stop = new AbortController();
    const waiting = limiter.acquire(1, stop.signal);
    stop.abort();
    await assert.rejects(waiting, /Stopped while waiting/);
  });

  it('reads limits from the environment and ignores nonsense', () => {
    assert.deepEqual(rateLimitsFromEnv({ HN_RATE_RPM: '50', HN_RATE_TPM: 'lots' }), { rpm: 50 });
    assert.throws(() => new RateLimiter({ rpm: 0 }), /positive/);
  });
});
