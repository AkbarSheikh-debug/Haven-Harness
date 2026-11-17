import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { estimateText, SUMMARY_SECTIONS } from '@hn/context';
import type { SessionEvent } from '@hn/core';
import type { InstructionFrameLike, InstructionHooks, LoopConfig, MemoryFrame, MemoryHooks } from '@hn/loop';
import { resolveCaps, type ModelProvider, type ModelReply, type ModelRequest } from '@hn/provider';
import { deriveSurface } from '@hn/session';
import { withTempDir } from '@hn/testkit';
import { config, fakeTools, open } from './helpers.ts';

/** A chain stand-in: a fixed snapshot, and a delta the first time a file under `lib/` is touched. */
class FakeChain implements InstructionHooks {
  snapshots = 0;
  readonly touchedPaths: string[] = [];
  version = 'v1';
  #libSeen = false;

  async snapshot(): Promise<InstructionFrameLike> {
    this.snapshots += 1;
    const text = `<system-reminder>\nInstructions from: AGENTS.md (${this.version})\n</system-reminder>`;
    return { text, origin: 'workspace', digest: this.version };
  }

  async touched(paths: readonly string[]): Promise<InstructionFrameLike | null> {
    this.touchedPaths.push(...paths);
    if (this.#libSeen || !paths.some((path) => path.startsWith('lib/'))) return null;
    this.#libSeen = true;
    const text = '<system-reminder>\nAdditional instructions from: lib/AGENTS.md\n</system-reminder>';
    return { text, origin: 'workspace', digest: 'lib' };
  }
}

const usage = (input: number) => ({ input, output: 10, cacheRead: 0, cacheWrite: 0 });
const DRAFT = SUMMARY_SECTIONS.map((section) => `## ${section}\nok`).join('\n');

/** Reads lib/a.ts, runs bash, then answers. Summary requests get a draft. */
class Model implements ModelProvider {
  readonly route = 'fake';
  #step = 0;

  async complete(request: ModelRequest): Promise<ModelReply> {
    const input = estimateText(JSON.stringify(request.messages));
    const reply = (parts: ModelReply['parts'], stopReason: ModelReply['stopReason']): ModelReply => ({
      parts,
      stopReason,
      usage: usage(input),
      model: 'fake',
    });
    if (JSON.stringify(request.messages.at(-1)).includes('NEW TURNS TO INCORPORATE')) {
      return reply([{ type: 'text', text: DRAFT }], 'end');
    }
    this.#step += 1;
    const said = { type: 'text' as const, text: 'Thinking about the next step carefully. '.repeat(40) };
    if (this.#step === 1) return reply([said, { type: 'tool_call', id: 'a', name: 'read_file', args: { path: 'lib/a.ts' } }], 'tool_use');
    if (this.#step === 2) return reply([{ type: 'tool_call', id: 'b', name: 'bash', args: { command: 'cd lib && ls' } }], 'tool_use');
    this.#step = 0;
    return reply([{ type: 'text', text: 'done' }], 'end');
  }
}

function loop(model: ModelProvider, chain: InstructionHooks, window = 200_000): LoopConfig {
  const tools = fakeTools({ run: () => ({ content: 'x '.repeat(3_000), isError: false, origin: 'workspace' }) });
  return config(model, tools, {
    caps: resolveCaps('fake', { window, maxOutput: 4_000, usage: 'full' }),
    maxOutputTokens: 4_000,
    instructions: chain,
  });
}

const instructionRows = (events: readonly SessionEvent[]) =>
  deriveSurface(events).filter((row) => row.data['instructions'] === true);
const pinnedRows = (events: readonly SessionEvent[]) =>
  instructionRows(events).filter((row) => row.data['pinned'] === true);

describe('instructions in the loop', () => {
  it('sends one pinned snapshot before the first message, and a delta after a file tool, never after bash', async () => {
    await withTempDir(async (directory) => {
      const chain = new FakeChain();
      const agent = await open(directory, loop(new Model(), chain));
      await agent.run('go');
      const surface = deriveSurface(agent.events);
      assert.equal(surface[0]?.data['instructions'], true);
      assert.equal(surface[0]?.data['pinned'], true);
      assert.equal(surface[1]?.data['text'], 'go');
      assert.deepEqual(chain.touchedPaths, ['lib/a.ts'], 'bash, even with cd, does not refresh');
      const delta = surface.find((row) => String(row.data['text']).includes('Additional instructions from: lib/AGENTS.md'));
      assert.ok(delta !== undefined);
      assert.equal(surface[surface.indexOf(delta) - 1]?.type, 'tool/result', 'the delta follows the tool result');
      await agent.close();
    });
  });

  it('does not send the snapshot again on resume when nothing changed, and replaces it when the files did', async () => {
    await withTempDir(async (directory) => {
      const chain = new FakeChain();
      const first = await open(directory, loop(new Model(), chain), 'same');
      await first.run('one');
      await first.close();
      const second = await open(directory, loop(new Model(), chain), 'same');
      await second.run('two');
      assert.equal(pinnedRows(second.events).length, 1);
      assert.equal(second.events.filter((event) => event.data['pinned'] === true).length, 1, 'no second copy in the log');
      await second.close();
      chain.version = 'v2';
      const third = await open(directory, loop(new Model(), chain), 'same');
      await third.run('three');
      const pinned = pinnedRows(third.events);
      assert.equal(pinned.length, 1, 'the new snapshot replaced the old one');
      assert.equal(pinned[0]?.data['digest'], 'v2');
      assert.equal(deriveSurface(third.events)[0]?.data['digest'], 'v2', 'still first, after the cached prefix');
      await third.close();
    });
  });

  it('sends the whole chain again after a fold, in place of the old snapshot', async () => {
    await withTempDir(async (directory) => {
      const chain = new FakeChain();
      const agent = await open(directory, loop(new Model(), chain, 32_000));
      for (let i = 0; i < 40; i += 1) await agent.run(`turn ${i}`);
      assert.ok(agent.events.some((event) => event.type === 'compaction/summary'), 'a fold happened');
      assert.ok(chain.snapshots >= 2);
      const pinned = pinnedRows(agent.events);
      assert.equal(pinned.length, 1);
      assert.equal(deriveSurface(agent.events)[0], pinned[0]);
      await agent.close();
    });
  });
});

/** A memory stand-in: one frozen frame per version. */
class FakeMemory implements MemoryHooks {
  version = 'm1';
  calls = 0;
  async snapshot(): Promise<MemoryFrame> {
    this.calls += 1;
    return { text: `<system-reminder>\n<memory>\nUses pnpm (${this.version})\n</memory>\n</system-reminder>`, digest: this.version, origin: 'memory' };
  }
}

const memoryRows = (events: readonly SessionEvent[]) => deriveSurface(events).filter((row) => row.data['memory'] === true);

describe('memory in the loop', () => {
  it('places one pinned memory row right after the instruction row, before the first message', async () => {
    await withTempDir(async (directory) => {
      const memory = new FakeMemory();
      const agent = await open(directory, { ...loop(new Model(), new FakeChain()), memory });
      await agent.run('go');
      await agent.run('again');
      const surface = deriveSurface(agent.events);
      assert.equal(surface[0]?.data['instructions'], true);
      assert.equal(surface[1]?.data['memory'], true);
      assert.equal(surface[1]?.data['pinned'], true);
      assert.equal(surface[1]?.origin, 'memory');
      assert.equal(surface[2]?.data['text'], 'go');
      assert.equal(memoryRows(agent.events).length, 1, 'a second turn adds no second copy');
      await agent.close();
    });
  });

  it('keeps the memory row through folds, and on resume replaces it only when memory changed', async () => {
    await withTempDir(async (directory) => {
      const memory = new FakeMemory();
      const first = await open(directory, { ...loop(new Model(), new FakeChain(), 32_000), memory }, 'mem');
      for (let i = 0; i < 40; i += 1) await first.run(`turn ${i}`);
      assert.ok(first.events.some((event) => event.type === 'compaction/summary'), 'a fold happened');
      assert.equal(memoryRows(first.events).length, 1);
      assert.equal(memoryRows(first.events)[0]?.data['digest'], 'm1');
      await first.close();
      const second = await open(directory, { ...loop(new Model(), new FakeChain(), 32_000), memory }, 'mem');
      await second.run('resumed');
      assert.equal(second.events.filter((event) => event.data['memory'] === true).length, 1, 'same memory: no new row');
      await second.close();
      memory.version = 'm2';
      const third = await open(directory, { ...loop(new Model(), new FakeChain(), 32_000), memory }, 'mem');
      await third.run('changed');
      assert.deepEqual(memoryRows(third.events).map((row) => row.data['digest']), ['m2']);
      await third.close();
    });
  });
});

describe('relevant recall in the loop', () => {
  it('puts recall right after the user message, and the prefix bytes are the same before and after it', async () => {
    await withTempDir(async (directory) => {
      const memory = new FakeMemory();
      const queries: string[] = [];
      const recalling: MemoryHooks = {
        snapshot: () => memory.snapshot(),
        recall: async (query) => {
          queries.push(query);
          return { text: `<system-reminder>\n<recall>\nnote about ${query}\n</recall>\n</system-reminder>`, digest: query, origin: 'memory' };
        },
      };
      const requests: ModelRequest[] = [];
      const model = new Model();
      const watching: ModelProvider = { route: 'fake', complete: (request) => (requests.push(request), model.complete(request)) };
      const agent = await open(directory, { ...loop(watching, new FakeChain()), memory: recalling });
      await agent.run('first');
      await agent.run('second');
      assert.deepEqual(queries, ['first', 'second'], 'the query is the user\'s own words, once per turn');
      const surface = deriveSurface(agent.events);
      const second = surface.findIndex((row) => row.data['text'] === 'second');
      assert.equal(surface[second + 1]?.data['recall'], true);
      assert.equal(surface[second + 1]?.origin, 'memory');
      const prefix = (request: ModelRequest) => JSON.stringify(request.messages.slice(0, 2));
      assert.ok(requests.length >= 2);
      assert.ok(requests.every((request) => prefix(request) === prefix(requests[0] as ModelRequest)), 'instructions and memory never move');
      await agent.close();
    });
  });

  it('a recall that throws leaves the turn as it was', async () => {
    await withTempDir(async (directory) => {
      const broken: MemoryHooks = { snapshot: () => new FakeMemory().snapshot(), recall: async () => { throw new Error('index gone'); } };
      const agent = await open(directory, { ...loop(new Model(), new FakeChain()), memory: broken });
      assert.equal((await agent.run('go')).end, 'done');
      await agent.close();
    });
  });
});

describe('the compaction flush in the loop', () => {
  it('hands the flush exactly the rows a summary fold is about to replace, before the fold', async () => {
    await withTempDir(async (directory) => {
      const flushed: number[][] = [];
      const summariesAtFlush: number[] = [];
      let agentRef: { events: readonly SessionEvent[] } | null = null;
      const memory: MemoryHooks = {
        snapshot: () => new FakeMemory().snapshot(),
        flush: async (rows) => {
          flushed.push(rows.map((row) => row.seq));
          summariesAtFlush.push(agentRef?.events.filter((event) => event.type === 'compaction/summary').length ?? -1);
        },
      };
      const agent = await open(directory, { ...loop(new Model(), new FakeChain(), 32_000), memory });
      agentRef = agent;
      for (let i = 0; i < 40; i += 1) await agent.run(`turn ${i}`);
      const summaries = agent.events.filter((event) => event.type === 'compaction/summary');
      assert.ok(summaries.length > 0 && flushed.length >= summaries.length, `${flushed.length} flushes for ${summaries.length} folds`);
      assert.ok(flushed.every((seqs) => seqs.length > 0));
      assert.ok(summariesAtFlush.every((count, i) => count <= i), 'each flush ran before its own summary');
      const visible = new Set(deriveSurface(agent.events).map((row) => row.seq));
      assert.ok(flushed.flat().every((seq) => !visible.has(seq)), 'every flushed row was then folded away');
      await agent.close();
    });
  });
});
