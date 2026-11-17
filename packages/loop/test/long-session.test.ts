import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type { SessionEvent } from '@hn/core';
import { ProviderError, resolveCaps, type ModelProvider, type ModelReply, type ModelRequest } from '@hn/provider';
import { parseLog } from '@hn/session';
import { seededRandom, withTempDir } from '@hn/testkit';
import { config, fakeTools, key, open } from './helpers.ts';
import { assertFoldsClosed, assertOneResultPerCall, assertSurfaceBalanced, DRAFT, isSummaryRequest, pairingProblem, requestTokens } from './pressure.ts';

/**
 * A simulated 8-hour session. A fake model works through 32 turns of about
 * 100 steps each on a fake clock, with parallel calls, results up to the dispatcher's 100,000-character cap,
 * re-reads, failures, and three crashes that also lose the tail of the log. The model counts its own context
 * and refuses any request that does not fit, so "no overflow" is judged by the far side.
 */

const TURNS = 33;
const STEPS_PER_TURN = 100;
const CRASH_TURNS = new Set([8, 16, 24]);
const CRASH_STEP = 50;
const STEP_MS = 9_600;
const SUMMARY_MS = 20_000;
const HOUR_MS = 3_600_000;
/** The dispatcher's inline cap: nothing bigger ever reaches the loop. */
const MAX_RESULT_CHARS = 100_000;
const CONSTRAINT = 'Never push to main.';

interface ReadArgs {
  readonly path: string;
  readonly size: number;
  readonly fail?: boolean;
  readonly crash?: boolean;
}

/** Ordinary text, mostly words, the shape of a source file or a test log. */
function body(path: string, size: number): string {
  const lines: string[] = [];
  let length = 0;
  for (let n = 1; length < size; n += 1) {
    const line = `line ${n} of ${path}: the parser reads each token and keeps going until the end`;
    lines.push(line);
    length += line.length + 1;
  }
  return lines.join('\n').slice(0, size);
}

class Clock {
  readonly start = Date.parse('2026-11-12T09:00:00.000Z');
  at = this.start;
  readonly now = (): number => this.at;
}

class EightHourModel implements ModelProvider {
  readonly route = 'fake';
  readonly overflows: string[] = [];
  /** Requests a provider would refuse because a call has no result next to it. */
  readonly unpaired: string[] = [];
  readonly random = seededRandom(80_808);
  peak = 0;
  summaries = 0;
  lastMain: ModelRequest | undefined;
  #turn = 0;
  #step = 0;
  #reads: ReadArgs[] = [];
  readonly window: number;
  readonly clock: Clock;

  constructor(window: number, clock: Clock) {
    this.window = window;
    this.clock = clock;
  }

  startTurn(turn: number): void {
    this.#turn = turn;
    this.#step = 0;
  }

  async complete(request: ModelRequest): Promise<ModelReply> {
    const input = requestTokens(request);
    this.peak = Math.max(this.peak, (input + request.maxOutputTokens) / this.window);
    const pairing = pairingProblem(request);
    if (pairing !== null) {
      this.unpaired.push(`turn ${this.#turn} step ${this.#step}: ${pairing}`);
      throw new ProviderError('bad_request', `tool_use without tool_result: ${pairing}`);
    }
    if (input + request.maxOutputTokens > this.window) {
      const kind = isSummaryRequest(request) ? 'summary' : 'main';
      this.overflows.push(`${kind} request at turn ${this.#turn} step ${this.#step}: ${input} + ${request.maxOutputTokens} output, ${request.messages.length} messages`);
      throw new ProviderError('context_too_long', `prompt is too long: ${input} tokens`);
    }
    const usage = { input, output: 40, cacheRead: 0, cacheWrite: 0 };
    if (isSummaryRequest(request)) {
      this.clock.at += SUMMARY_MS;
      this.summaries += 1;
      return { parts: [{ type: 'text', text: DRAFT }], stopReason: 'end', usage, model: 'fake' };
    }
    this.clock.at += STEP_MS;
    this.lastMain = request;
    if (this.#step >= STEPS_PER_TURN) {
      return { parts: [{ type: 'text', text: `Turn ${this.#turn} is done.` }], stopReason: 'end', usage, model: 'fake' };
    }
    this.#step += 1;
    const width = 1 + Math.floor(this.random() * 4);
    const crash = CRASH_TURNS.has(this.#turn) && this.#step === CRASH_STEP;
    let large = false;
    const calls = Array.from({ length: width }, (_, index) => {
      const args = this.#pick(index === 0 && crash, large);
      large ||= args.size > 20_000;
      return { type: 'tool_call' as const, id: `t${this.#turn}s${this.#step}c${index}`, name: 'read_file', args };
    });
    const said = 'Checking the next part of the migration before changing anything. '.repeat(20).slice(0, Math.floor(this.random() * 1_200));
    return {
      parts: [...(said === '' ? [] : [{ type: 'text' as const, text: said }]), ...calls],
      stopReason: 'tool_use',
      usage,
      model: 'fake',
    };
  }

  /** At most one large result per step, so a step stays under the dispatcher's 200,000-character step cap. */
  #pick(crash: boolean, largeTaken: boolean): ReadArgs {
    const roll = this.random();
    if (crash) return { path: 'src/crash.ts', size: 10, crash: true };
    if (roll < 0.05 && this.#reads.length > 0) return this.#reads[Math.floor(this.random() * this.#reads.length)] as ReadArgs;
    if (roll < 0.08) return { path: `src/missing${this.#turn}-${this.#step}.ts`, size: 0, fail: true };
    const size =
      roll < 0.11 && !largeTaken
        ? 20_000 + Math.floor(this.random() * (MAX_RESULT_CHARS - 20_000))
        : roll < 0.28
          ? 3_000 + Math.floor(this.random() * 9_000)
          : 200 + Math.floor(this.random() * 2_800);
    const args = { path: `src/module${this.#turn}/file${this.#step}-${Math.floor(this.random() * 1e6)}.ts`, size };
    this.#reads.push(args);
    return args;
  }
}

/** `onCrash` runs inside the crashing tool, while the call is on disk and no result is: the moment a process dies. */
const tools = (onCrash: () => void) =>
  fakeTools({
    run: (_name, raw) => {
      const args = raw as ReadArgs;
      if (args.crash === true) {
        onCrash();
        throw new Error('power cut');
      }
      if (args.fail === true) return { content: `ENOENT: no such file ${args.path}`, isError: true, origin: 'workspace' };
      return { content: body(args.path, args.size), isError: false, origin: 'workspace' };
    },
  });

function checkLog(events: readonly SessionEvent[], label: string): void {
  assertOneResultPerCall(events);
  assertSurfaceBalanced(events, label);
  assertFoldsClosed(events, label);
}

describe('a simulated 8-hour session', () => {
  for (const [window, output] of [
    [32_000, 4_000],
    [64_000, 8_000],
    [128_000, 32_000],
  ] as const) {
    it(`${window / 1000}k window: about 3,000 steps over 8 hours, with crashes, no overflow and every pair intact`, async (t) => {
      await withTempDir(async (directory) => {
        const clock = new Clock();
        const model = new EightHourModel(window, clock);
        const path = join(directory, 'long');
        let snapshot: Buffer | null = null;
        const loop = config(model, tools(() => (snapshot = readFileSync(path))), {
          caps: resolveCaps('fake', { window, maxOutput: output, usage: 'full' }),
          maxOutputTokens: output,
          maxIterations: STEPS_PER_TURN + 20,
          now: clock.now,
        });
        const random = seededRandom(window);
        let agent = await open(directory, loop, 'long');
        let crashes = 0;
        for (let turn = 1; turn <= TURNS; turn += 1) {
          model.startTurn(turn);
          const prompt = turn === 1 ? `Migrate every module in src to the new parser. ${CONSTRAINT}` : `Turn ${turn}: carry on with the next modules.`;
          if (!CRASH_TURNS.has(turn)) {
            const result = await agent.run(prompt);
            assert.equal(result.end, 'done', `turn ${turn}: ${result.detail ?? ''}`);
            continue;
          }
          // In-process, the loop handles the throw gracefully. A real crash stops everything at the throw, so the
          // log is put back to what was on disk at that moment, and loses up to 2% more, as a power cut can.
          snapshot = null;
          await agent.run(prompt);
          await agent.close();
          const bytes = snapshot as Buffer | null;
          assert.ok(bytes !== null, `turn ${turn}: the crash point was reached`);
          crashes += 1;
          const lost = Math.floor(random() * Math.min(bytes.length * 0.02, 65_536));
          await writeFile(path, bytes.subarray(0, bytes.length - lost));
          agent = await open(directory, loop, 'long');
          checkLog(agent.events, `resumed after crash ${crashes}`);
        }
        await agent.close();

        const events = parseLog(await readFile(path), key).events;
        checkLog(events, 'whole log');
        const steps = events.filter((event) => event.type === 'assistant/message' && ((event.data['toolCalls'] as unknown[] | undefined)?.length ?? 0) > 0).length;
        const calls = events.flatMap((event) => (event.type === 'assistant/message' ? ((event.data['toolCalls'] as unknown[] | undefined) ?? []) : []));
        const folds = events.filter((event) => event.type === 'compaction/end');
        const summaries = folds.filter((event) => event.data['outcome'] !== 'pruned').length;
        const hours = (clock.at - clock.start) / HOUR_MS;

        assert.deepEqual(model.overflows, [], 'no request was too long for the window');
        assert.deepEqual(model.unpaired, [], 'every request kept each call next to its result');
        assert.equal(crashes, CRASH_TURNS.size);
        assert.ok(steps >= 3_000, `${steps} steps`);
        assert.ok(hours >= 8, `${hours.toFixed(2)} simulated hours`);
        assert.ok(folds.length > 0 && summaries > 0, 'the window filled and folded');
        assert.ok(events.some((event) => event.type === 'compaction/prune'), 'the free step ran');
        assert.ok(JSON.stringify(model.lastMain?.messages).includes(CONSTRAINT), 'the constraint survived every fold word for word');
        t.diagnostic(
          `${window / 1000}k: ${steps} steps, ${calls.length} calls, ${hours.toFixed(1)} h, ${folds.length} folds (${summaries} with a summary), ${model.summaries} summary calls, peak ${(model.peak * 100).toFixed(1)}% of the window, ${events.length} log rows`,
        );
      });
    });
  }
});
