import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { anchorFromLog, envelopeFor, type LoopConfig } from '@hn/loop';
import { ProviderError, resolveCaps, type ModelProvider, type ModelReply, type ModelRequest } from '@hn/provider';
import { closingRecords } from '@hn/session';
import { withTempDir } from '@hn/testkit';
import { config, fakeTools, open } from './helpers.ts';
import { assertFoldsClosed, assertOneResultPerCall, assertSurfaceBalanced, DRAFT, isSummaryRequest, requestTokens } from './pressure.ts';

interface WorkerOptions {
  readonly window: number;
  readonly rounds: number;
  /** When set, summary requests fail with this. */
  readonly summaryError?: Error;
  /** Characters of reasoning text in each tool-call reply. Pruning never touches assistant text. */
  readonly narration?: number;
}

/**
 * A model that works through `rounds` tool calls and then answers. It counts its own context and refuses
 * a request that does not fit, exactly as a provider would, so "no overflow" is checked by the far side.
 * Its count includes the JSON framing of every message, so it reads about twice our estimate: the loop
 * must cope with a provider that counts more than we do.
 */
class WorkingModel implements ModelProvider {
  readonly route = 'fake';
  readonly requests: ModelRequest[] = [];
  readonly overflows: number[] = [];
  summaries = 0;
  #round = 0;
  readonly #options: WorkerOptions;

  constructor(options: WorkerOptions) {
    this.#options = options;
  }

  async complete(request: ModelRequest): Promise<ModelReply> {
    this.requests.push(request);
    const input = requestTokens(request);
    if (input + request.maxOutputTokens > this.#options.window) {
      this.overflows.push(input);
      throw new ProviderError('context_too_long', `prompt is too long: ${input} tokens`);
    }
    const usage = { input, output: 20, cacheRead: 0, cacheWrite: 0 };
    if (isSummaryRequest(request)) {
      this.summaries += 1;
      if (this.#options.summaryError !== undefined) throw this.#options.summaryError;
      return { parts: [{ type: 'text', text: DRAFT }], stopReason: 'end', usage, model: 'fake' };
    }
    if (this.#round >= this.#options.rounds) {
      return { parts: [{ type: 'text', text: 'done' }], stopReason: 'end', usage, model: 'fake' };
    }
    this.#round += 1;
    const id = `r${this.#round}`;
    const said = `Step ${this.#round}: checking the next file before changing anything. `
      .repeat(40)
      .slice(0, this.#options.narration ?? 1_500);
    return {
      parts: [
        ...(said === '' ? [] : [{ type: 'text' as const, text: said }]),
        { type: 'tool_call', id, name: 'read_file', args: { path: `src/file${this.#round}.ts` } },
      ],
      stopReason: 'tool_use',
      usage,
      model: 'fake',
    };
  }
}

/** Each read returns a different, large file, so nothing dedupes and the window really fills. */
const bigTools = (chars: number) =>
  fakeTools({
    run: (_name, args) => ({
      content: `${JSON.stringify(args)} `.repeat(Math.ceil(chars / 20)).slice(0, chars),
      isError: false,
      origin: 'workspace',
    }),
  });

function loopConfig(model: ModelProvider, window: number, output: number, chars: number): LoopConfig {
  return config(model, bigTools(chars), {
    caps: resolveCaps('fake', { window, maxOutput: output, usage: 'full' }),
    maxOutputTokens: output,
    maxIterations: 500,
  });
}

async function session(loop: LoopConfig, prompt = 'Read every file in src. Never push to main.') {
  return withTempDir(async (directory) => {
    const agent = await open(directory, loop);
    const result = await agent.run(prompt);
    const events = [...agent.events];
    await agent.close();
    return { result, events };
  });
}

describe('compaction in the loop', () => {
  for (const [window, output] of [
    [32_000, 4_000],
    [64_000, 8_000],
    [128_000, 32_000],
  ] as const) {
    it(`a long session on a ${window / 1000}k window folds instead of ending, and never overflows`, async () => {
      const model = new WorkingModel({ window, rounds: 120 });
      const { result, events } = await session(loopConfig(model, window, output, 8_000));
      assert.equal(result.end, 'done', result.detail);
      assert.deepEqual(model.overflows, [], 'no request was too long for the window');
      assert.ok(events.some((event) => event.type === 'compaction/summary'), 'at least one fold');
      assertOneResultPerCall(events);
      assertSurfaceBalanced(events, 'final');
      const starts = events.filter((event) => event.type === 'compaction/start').length;
      assert.equal(events.filter((event) => event.type === 'compaction/end').length, starts);
    });
  }

  it('quotes the user request word for word in the summary the model sees', async () => {
    const model = new WorkingModel({ window: 32_000, rounds: 40 });
    await session(loopConfig(model, 32_000, 4_000, 8_000));
    const after = model.requests.filter((request) => !isSummaryRequest(request)).at(-1);
    assert.match(JSON.stringify(after?.messages), /Never push to main\./);
    assert.match(JSON.stringify(after?.messages), /CONTEXT COMPACTION/);
  });

  it('continues on the static summary when the summary model fails', async () => {
    const model = new WorkingModel({ window: 32_000, rounds: 40, summaryError: new ProviderError('overloaded', 'busy') });
    const { result, events } = await session(loopConfig(model, 32_000, 4_000, 8_000));
    assert.equal(result.end, 'done', result.detail);
    const ends = events.filter((event) => event.type === 'compaction/end' && event.data['source'] === 'static');
    assert.ok(ends.length > 0, 'a static fold landed');
    assert.deepEqual(model.overflows, []);
  });

  it('gives a thinking summary model room to reason, so its summary is not cut off (found live with qwen3)', async () => {
    const model = new WorkingModel({ window: 32_000, rounds: 40 });
    const limits: number[] = [];
    // Spends 2,000 output tokens reasoning before it writes, as qwen3 does; with less room the summary is cut off.
    const thinking: ModelProvider = {
      route: 'fake',
      complete: async (request) => {
        if (!isSummaryRequest(request)) return model.complete(request);
        limits.push(request.maxOutputTokens);
        if (request.maxOutputTokens < 2_000 + 600) {
          return { parts: [{ type: 'text', text: 'Work so far' }], stopReason: 'length', usage: { input: 1, output: request.maxOutputTokens, cacheRead: 0, cacheWrite: 0 }, model: 'fake' };
        }
        return model.complete(request);
      },
    };
    const { result, events } = await session(loopConfig(thinking, 32_000, 4_000, 8_000));
    assert.equal(result.end, 'done', result.detail);
    assert.ok(limits.length > 0 && limits.every((limit) => limit <= 4_000), 'never more than the session output budget');
    const ends = events.filter((event) => event.type === 'compaction/end' && event.data['outcome'] === 'folded');
    assert.ok(ends.length > 0);
    assert.ok(ends.every((event) => event.data['source'] === 'main'), 'the model wrote every summary; none fell back to static');
    assert.deepEqual(model.overflows, []);
  });

  it('never asks a model for a summary that cannot fit under the cap (found live: told 500 tokens, held to 409)', async () => {
    const model = new WorkingModel({ window: 16_384, rounds: 30 });
    // The harness quotes the request and every constraint word for word, so on this window they fill the cap.
    const request = [
      'There are 24 files in src, module00.js to module23.js, and each one must be read in full before anything is written about it.',
      'For each file in turn, use read_file to read the whole file, and never use grep or a partial read instead.',
      'Then add one line for it to NOTES.md giving the file name and the names of every function it exports, in the order they appear.',
      'Never push to main. Never delete a file. Never change a file in src. Always keep NOTES.md sorted by file name.',
      'Always stop and say so if a file cannot be read, and never guess what it exports.',
    ].join(' ');
    const { result, events } = await session(loopConfig(model, 16_384, 8_192, 3_000), request);
    assert.equal(result.end, 'done', result.detail);
    assert.equal(model.summaries, 0, 'no summary call was made that could only fail');
    const folded = events.filter((event) => event.type === 'compaction/end' && event.data['outcome'] === 'folded');
    assert.ok(folded.length > 0);
    for (const end of folded) assert.equal(end.data['source'], 'static');
    // Once benched, or near the window, a fold goes straight to static and records no attempt; the first says why.
    assert.ok(folded.some((end) => /too few for a model to write one/.test(JSON.stringify(end.data['failures']))));
    assert.ok(!folded.some((end) => /over the \d+ cap/.test(JSON.stringify(end.data['failures']))));
    assert.deepEqual(model.overflows, []);
  });

  it('prunes without any model call when the free step is enough', async () => {
    const model = new WorkingModel({ window: 32_000, rounds: 16, narration: 0 });
    const { result, events } = await session(loopConfig(model, 32_000, 4_000, 2_400));
    assert.equal(result.end, 'done', result.detail);
    assert.ok(events.some((event) => event.type === 'compaction/prune'));
    const firstEnd = events.find((event) => event.type === 'compaction/end');
    assert.equal(firstEnd?.data['outcome'], 'pruned');
    assert.equal(model.summaries, 0);
  });

  it('answers context-too-long with one maximal fold and one retry, then gives up honestly', async () => {
    const model = new WorkingModel({ window: 32_000, rounds: 3 });
    let refusals = 0;
    const flaky: ModelProvider = {
      route: 'fake',
      complete: (request) => {
        if (!isSummaryRequest(request) && refusals < 1 && request.messages.length > 4) {
          refusals += 1;
          return Promise.reject(new ProviderError('context_too_long', 'prompt is too long'));
        }
        return model.complete(request);
      },
    };
    const { result, events } = await session(loopConfig(flaky, 32_000, 4_000, 3_000));
    assert.equal(result.end, 'done', result.detail);
    assert.ok(events.some((event) => event.type === 'compaction/start' && event.data['reason'] === 'overflow'));

    const stubborn: ModelProvider = {
      route: 'fake',
      complete: () => Promise.reject(new ProviderError('context_too_long', 'too long')),
    };
    const second = await session(loopConfig(stubborn, 32_000, 4_000, 3_000));
    assert.equal(second.result.end, 'window_full');
  });

  it('crash at every compaction event boundary: repair leaves a legal surface and closes the fold', async () => {
    const model = new WorkingModel({ window: 32_000, rounds: 60 });
    const { events } = await session(loopConfig(model, 32_000, 4_000, 8_000));
    const boundaries = events.flatMap((event, index) =>
      event.type.startsWith('compaction/') || event.data['surfaceOp'] !== undefined ? [index] : [],
    );
    assert.ok(boundaries.length > 6);
    for (const index of boundaries) {
      for (const cut of [index, index + 1]) {
        const prefix = events.slice(0, cut);
        const seq = prefix.at(-1)?.seq ?? 0;
        const repaired = [
          ...prefix,
          ...closingRecords(prefix).map((record, i) => ({ seq: seq + i + 1, ts: '2026-11-05T00:00:00.000Z', ...record })),
        ];
        assertSurfaceBalanced(repaired, `cut at ${cut}`);
        assertFoldsClosed(repaired, `cut at ${cut}`);
      }
    }
  });

  it('manual /compact runs between turns', async () => {
    await withTempDir(async (directory) => {
      const model = new WorkingModel({ window: 32_000, rounds: 4 });
      const agent = await open(directory, loopConfig(model, 32_000, 4_000, 3_000));
      await agent.run('Read four files.');
      const outcome = await agent.compact();
      assert.ok(['folded', 'pruned', 'noop'].includes(outcome), outcome);
      assert.ok(agent.events.some((event) => event.type === 'compaction/start' && event.data['reason'] === 'manual'));
      await agent.close();
    });
  });

  it('refuses a window under 16k when the session opens', async () => {
    await withTempDir(async (directory) => {
      const model = new WorkingModel({ window: 8_000, rounds: 0 });
      await assert.rejects(open(directory, loopConfig(model, 8_000, 1_000, 10)), /under the 16000 minimum/);
    });
  });

  it('anchors on the provider count only until a fold changes the surface', async () => {
    const model = new WorkingModel({ window: 32_000, rounds: 40 });
    const loop = loopConfig(model, 32_000, 4_000, 8_000);
    const { events } = await session(loop);
    const envelope = envelopeFor(loop);
    const lastFold = events.findLastIndex((event) => event.data['surfaceOp'] !== undefined);
    assert.equal(anchorFromLog(events.slice(0, lastFold + 1), envelope), null);
    assert.notEqual(anchorFromLog(events, envelope), null, 'a later reply anchors again');
    assert.equal(anchorFromLog(events, 'another-envelope'), null);
  });
});
