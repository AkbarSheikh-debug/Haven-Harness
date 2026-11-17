import assert from 'node:assert/strict';
import { readFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import type { EventType, SessionEvent } from '@hn/core';
import { localOperations } from '@hn/operations';
import { LeasePool, createWorkflowTools, processLauncher, runWorkflow, type RunnerChannel, type WorkflowHandlers } from '@hn/orchestrate';
import { withTempDir } from '@hn/testkit';

const limits = { concurrency: 4, maxAgents: 50, maxItems: 100, maxResultChars: 2_000 };

function journal() {
  const events: SessionEvent[] = [];
  const record = (type: EventType, data: Record<string, unknown>) => events.push({ seq: events.length + 1, ts: '2026-11-14T00:00:00Z', type, origin: 'harness', data });
  return { events, record };
}

function handlers(calls: string[], over: Partial<WorkflowHandlers> = {}): WorkflowHandlers {
  return {
    agent: async ({ prompt }) => {
      calls.push(prompt);
      if (prompt.includes('FAIL')) return { value: null, origin: 'child' };
      return { value: `answer to ${prompt}`, origin: 'child' };
    },
    tool: async ({ name, args }) => ({ value: { ok: true, content: `${name} ${JSON.stringify(args)}` }, origin: 'workspace' }),
    ...over,
  };
}

async function runIn(dir: string, script: string, h: WorkflowHandlers, j = journal(), signal = new AbortController().signal) {
  const root = await realpath(dir);
  const launch = processLauncher({ processes: localOperations(join(root, 'spill')).processes!, cwd: root, where: 'local' });
  const result = await runWorkflow({ script, args: { n: 3 }, launch, handlers: h, record: j.record, events: () => j.events, limits, signal });
  return { result, j };
}

describe('the workflow runtime', () => {
  it('runs a script with agent, tool, parallel, pipeline, phase, log and args, and journals every call', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const script = `
        phase('gather');
        log('starting with ' + args.n);
        const first = await agent('scan the repo', { label: 'scan' });
        const many = await parallel([1, 2, 3].map((i) => () => agent('part ' + i)));
        const piped = await pipeline(['a', 'b'], (x) => x.toUpperCase(), (x) => agent('use ' + x));
        const read = await tool('read_file', { path: 'x.ts' });
        return { first, many, piped, read: read.content };`;
      const { result, j } = await runIn(dir, script, handlers([]));
      assert.equal(result.ok, true, result.error);
      assert.deepEqual(result.result, {
        first: 'answer to scan the repo',
        many: ['answer to part 1', 'answer to part 2', 'answer to part 3'],
        piped: ['answer to use A', 'answer to use B'],
        read: 'read_file {"path":"x.ts"}',
      });
      assert.equal(result.agents, 6);
      assert.equal(result.origin, 'child', 'the worst origin of the sub-calls');
      const types = j.events.map((event) => event.type);
      assert.equal(types[0], 'workflow/run-start');
      assert.equal(types.at(-1), 'workflow/run-end');
      assert.equal(types.filter((type) => type === 'workflow/agent-end').length, 6);
      assert.ok(types.includes('workflow/phase') && types.includes('workflow/log') && types.includes('workflow/tool'));
    });
  });

  it('has the exact error semantics: a failed child is null, a throw in a combinator is null, WorkflowError kills the run with no partial output', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const soft = await runIn(dir, `
        const failed = await agent('FAIL please');
        const mixed = await parallel([() => agent('ok'), () => { throw new Error('boom'); }, () => agent('FAIL too')]);
        const piped = await pipeline([1, 2], (x) => { if (x === 2) throw new Error('no'); return x; });
        return { failed, mixed, piped };`, handlers([]));
      assert.deepEqual(soft.result.result, { failed: null, mixed: ['answer to ok', null, null], piped: [1, null] });
      const fatal = await runIn(dir, `await agent('one'); await parallel([() => { throw new WorkflowError('stop now'); }]); return 'never';`, handlers([]));
      assert.equal(fatal.result.ok, false);
      assert.equal(fatal.result.fatal, true);
      assert.match(fatal.result.error ?? '', /stop now/);
      assert.equal(fatal.result.result, undefined, 'no partial output');
      const big = await runIn(dir, `return 'x'.repeat(5000);`, handlers([]));
      assert.match(big.result.error ?? '', /5002 characters; at most 2000/);
      const thrown = await runIn(dir, `throw new Error('plain');`, handlers([]));
      assert.equal(thrown.result.ok, false);
      assert.equal(thrown.result.fatal, false);
    });
  });

  it('enforces the agent and item limits', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const agents = await runIn(dir, `for (let i = 0; i < 60; i += 1) await agent('a' + i); return 1;`, handlers([]));
      assert.match(agents.result.error ?? '', /more than 50 agents/);
      const items = await runIn(dir, `return parallel(Array.from({ length: 101 }, () => () => 1));`, handlers([]));
      assert.match(items.result.error ?? '', /at most 100 items/);
    });
  });

  it('resumes a crashed run from the journal: finished agents are not asked again, and the run is the same run', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const script = `
        const pick = Math.floor(Math.random() * 1000);
        const started = Date.now();
        const out = [];
        for (let i = 0; i < 5; i += 1) out.push(await agent('step ' + i));
        return { pick, started, out };`;
      const j = journal();
      const first: string[] = [];
      const stop = new AbortController();
      const crashing = handlers(first, {
        agent: async ({ prompt }) => {
          first.push(prompt);
          if (prompt === 'step 3') {
            stop.abort();
            await new Promise(() => undefined);
          }
          return { value: `done ${prompt}`, origin: 'child' };
        },
      });
      const crashed = await runIn(dir, script, crashing, j, stop.signal);
      assert.equal(crashed.result.ok, false);
      assert.deepEqual(first, ['step 0', 'step 1', 'step 2', 'step 3']);
      const second: string[] = [];
      const resumed = await runIn(dir, script, handlers(second, { agent: async ({ prompt }) => (second.push(prompt), { value: `done ${prompt}`, origin: 'child' }) }), j);
      assert.equal(resumed.result.ok, true, resumed.result.error);
      assert.deepEqual(second, ['step 3', 'step 4'], 'only the calls that had not finished went live');
      assert.equal(resumed.result.replayed, 3);
      assert.equal(resumed.result.run, crashed.result.run, 'the same run, resumed');
      const done = resumed.result.result as { pick: number; started: number; out: string[] };
      assert.deepEqual(done.out, ['done step 0', 'done step 1', 'done step 2', 'done step 3', 'done step 4']);
      // Same seed and logged clock: run it from the same journal state once more and it chooses and dates the same.
      const j2 = journal();
      for (const event of j.events.filter((row) => row.type !== 'workflow/run-end')) j2.events.push(event);
      const replay = await runIn(dir, script, handlers([]), j2);
      const again = replay.result.result as { pick: number; started: number };
      assert.equal(again.pick, done.pick, 'seeded random replays');
      assert.equal(again.started, done.started, 'logged time replays');
    });
  });

  it('drops a message without the run token: nothing but the runner can call a tool', async () => {
    const j = journal();
    const listeners: ((message: unknown) => void)[] = [];
    let release: (value: { code: number | null }) => void = () => undefined;
    const fake: RunnerChannel = {
      send: (message) => {
        const start = message as { kind: string; t: string };
        if (start.kind !== 'start') return;
        setTimeout(() => {
          for (const listener of listeners) listener({ kind: 'call', id: 1, op: 'tool', name: 'bash', args: { command: 'rm -rf /' } });
          for (const listener of listeners) listener({ t: 'guess', kind: 'call', id: 2, op: 'tool', name: 'bash', args: {} });
          for (const listener of listeners) listener({ t: start.t, kind: 'done', ok: true, result: 'fine' });
        }, 5);
      },
      onMessage: (listener) => listeners.push(listener),
      exited: new Promise((resolve) => (release = resolve)),
      kill: () => release({ code: 0 }),
    };
    let toolCalls = 0;
    const result = await runWorkflow({ script: 'x', args: null, launch: () => fake, handlers: handlers([], { tool: async () => ((toolCalls += 1), { value: null, origin: 'harness' }) }), record: j.record, events: () => j.events, limits, signal: new AbortController().signal });
    assert.equal(result.ok, true);
    assert.equal(toolCalls, 0);
    assert.equal(j.events.filter((event) => event.data['kind'] === 'workflow-message-dropped').length, 2);
  });

  it('runs forty agents through a pool of four: capacity waits, it is never a null', async () => {
    const pool = new LeasePool(4);
    let done = 0;
    await Promise.all(Array.from({ length: 40 }, async () => {
      const release = await pool.acquire(new AbortController().signal);
      await new Promise((resolve) => setTimeout(resolve, 2));
      done += 1;
      release();
    }));
    assert.equal(done, 40);
    assert.equal(pool.peak, 4);
  });
});

describe('workflow and run_code below tier 3', () => {
  it('attack: vm_escape_refused_below_tier3 (an escape payload never runs, because the tool refuses before any runner starts)', async () => {
    await withTempDir(async (dir) => {
      const canary = join(await realpath(dir), 'VM-ESCAPE-CANARY').replaceAll('\\', '/');
      let launched = 0;
      const tools = createWorkflowTools({
        tier: 2,
        launch: () => {
          launched += 1;
          throw new Error('unreachable');
        },
        handlers: handlers([]),
        record: () => undefined,
        events: () => [],
      });
      const escape = `const p = this.constructor.constructor('return process')(); p.mainModule.require('fs').writeFileSync('${canary}', 'escaped'); return 1;`;
      assert.deepEqual(tools.map((tool) => tool.name), ['workflow', 'run_code']);
      for (const tool of tools) assert.match(tool.refuse?.({ script: escape, code: escape }) ?? '', /refuses below tier 3\. The script runs in a vm, and a vm is not a boundary/);
      assert.equal(launched, 0);
      assert.equal(await readFile(canary).then(() => true, () => false), false);
    });
  });
});

describe('run_code', () => {
  it('runs code that calls tools through the handler, and has no agents', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const seen: string[] = [];
      const j = journal();
      const tools = createWorkflowTools({
        tier: 2,
        unsafeBelowTier3: true,
        launch: processLauncher({ processes: localOperations(join(root, 'spill')).processes!, cwd: root, where: 'local' }),
        handlers: handlers([], { tool: async ({ name }) => (seen.push(name), { value: { ok: true, content: `ran ${name}` }, origin: 'tool-output' }) }),
        record: j.record,
        events: () => j.events,
      });
      const runCode = tools.find((tool) => tool.name === 'run_code')!;
      const context = { signal: new AbortController().signal, callId: 'c1' } as never;
      const ok = await runCode.execute({ code: "const a = await tool('grep', { pattern: 'x' }); return a.content;" }, context);
      assert.equal(ok.isError, false);
      assert.match(ok.content, /"ran grep"/);
      assert.equal(ok.origin, 'model-derived', 'never better than model-derived, and tool-output ranks the same');
      assert.deepEqual(seen, ['grep']);
      const noAgents = await runCode.execute({ code: "return await agent('hi');" }, context);
      assert.equal(noAgents.isError, true);
      assert.match(noAgents.content, /run_code has no agents/);
    });
  });
});
