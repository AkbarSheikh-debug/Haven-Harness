// The workflow runner (section 11.4). Plain JavaScript, so it runs on any Node inside a box image. It runs a script in
// an empty vm context and asks its parent for everything else: agents, tools, logs. The vm is not the boundary (the
// box is), so this file never touches the network, files or processes itself; it only reads stdin and writes stdout.
//
// Protocol, one JSON object per line. Parent to runner: {t, kind: 'start', script, args, seed, startedAt, limits}
// once, then {t, kind: 'reply', id, ok, value | error}. Runner to parent: {t, kind: 'call', id, op, ...} and finally
// {t, kind: 'done', ok, result | error, fatal}. Every message carries the run's token.
import { AsyncLocalStorage } from 'node:async_hooks';
import { createInterface } from 'node:readline';
import vm from 'node:vm';

const lines = createInterface({ input: process.stdin });
const pending = new Map();
let token = '';
let nextId = 1;
let started = false;

function send(message) {
  process.stdout.write(`${JSON.stringify({ ...message, t: token })}\n`);
}

function ask(op, payload) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    send({ kind: 'call', id, op, ...payload });
  });
}

class WorkflowError extends Error {
  constructor(message) {
    super(String(message));
    this.name = 'WorkflowError';
  }
}

/** mulberry32: the script's Math.random, seeded from the journal so a resumed run makes the same choices. */
function seeded(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = state;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}

async function run(start) {
  const limits = start.limits;
  const paths = new AsyncLocalStorage();
  let agents = 0;
  let clock = 0;
  const random = seeded(start.seed);

  // A call's place in the script: the combinator branch it is in, then its order there. Replay finds it by this path.
  const root = { path: 'r', counter: { n: 0 } };
  const place = () => {
    const frame = paths.getStore() ?? root;
    return `${frame.path}/${frame.counter.n++}`;
  };
  const branch = (path, work) => paths.run({ path, counter: { n: 0 } }, work);

  /** Up to the concurrency limit at once, results in order. */
  async function pool(count, work) {
    const results = new Array(count);
    let next = 0;
    const lane = async () => {
      for (let index = next++; index < count; index = next++) results[index] = await work(index);
    };
    await Promise.all(Array.from({ length: Math.min(limits.concurrency, count) }, lane));
    return results;
  }

  const fatal = (error) => error instanceof WorkflowError || (error !== null && typeof error === 'object' && error.name === 'WorkflowError');

  const hooks = {
    args: start.args,
    WorkflowError,
    log: (message) => void ask('log', { message: String(message).slice(0, 2_000) }),
    phase: (title) => void ask('phase', { title: String(title).slice(0, 200) }),
    async agent(prompt, opts = {}) {
      agents += 1;
      if (agents > limits.maxAgents) throw new WorkflowError(`The workflow asked for more than ${limits.maxAgents} agents.`);
      const path = place();
      const value = await ask('agent', { path, prompt: String(prompt), opts: JSON.parse(JSON.stringify(opts ?? {})) });
      clock += 1;
      return value;
    },
    async tool(name, toolArgs = {}) {
      const path = place();
      return ask('tool', { path, name: String(name), args: JSON.parse(JSON.stringify(toolArgs ?? {})) });
    },
    async parallel(thunks) {
      if (!Array.isArray(thunks)) throw new WorkflowError('parallel takes a list of functions.');
      if (thunks.length > limits.maxItems) throw new WorkflowError(`parallel takes at most ${limits.maxItems} items.`);
      const base = place();
      return pool(thunks.length, (index) =>
        branch(`${base}.${index}`, async () => {
          try {
            return await thunks[index]();
          } catch (error) {
            if (fatal(error)) throw error;
            return null;
          }
        }),
      );
    },
    async pipeline(items, ...stages) {
      if (!Array.isArray(items)) throw new WorkflowError('pipeline takes a list of items.');
      if (items.length > limits.maxItems) throw new WorkflowError(`pipeline takes at most ${limits.maxItems} items.`);
      const base = place();
      return pool(items.length, (index) =>
        branch(`${base}.${index}`, async () => {
          let value = items[index];
          for (const stage of stages) {
            try {
              value = await stage(value, items[index], index);
            } catch (error) {
              if (fatal(error)) throw error;
              return null;
            }
            if (value === null || value === undefined) return null;
          }
          return value;
        }),
      );
    },
  };

  const context = vm.createContext(Object.create(null), { codeGeneration: { strings: false, wasm: false } });
  context.__hn = { ...hooks, random, now: () => start.startedAt + clock };
  // Logged time and seeded random, so a resumed run is the same run.
  vm.runInContext(
    `(() => { const hn = globalThis.__hn; delete globalThis.__hn;
      Math.random = () => hn.random();
      const RealDate = Date;
      globalThis.Date = class extends RealDate { constructor(...a) { super(...(a.length ? a : [hn.now()])); } static now() { return hn.now(); } };
      for (const name of ['args', 'WorkflowError', 'log', 'phase', 'agent', 'tool', 'parallel', 'pipeline']) globalThis[name] = hn[name];
    })();`,
    context,
  );
  const body = new vm.Script(`(async () => {\n${start.script}\n})()`, { filename: 'workflow.js' });
  const result = await branch('r', () => body.runInContext(context, { timeout: 5_000 }));
  const text = JSON.stringify(result === undefined ? null : result);
  if (text.length > limits.maxResultChars) throw new WorkflowError(`The workflow's result is ${text.length} characters; at most ${limits.maxResultChars} are allowed, and no partial output is returned.`);
  return JSON.parse(text);
}

lines.on('line', (line) => {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    return;
  }
  if (!started) {
    if (message?.kind !== 'start' || typeof message.t !== 'string') return;
    started = true;
    token = message.t;
    run(message)
      .then(
        (result) => send({ kind: 'done', ok: true, result }),
        (error) => send({ kind: 'done', ok: false, fatal: error?.name === 'WorkflowError', error: String(error?.message ?? error).slice(0, 2_000) }),
      )
      .finally(() => setTimeout(() => process.exit(0), 10));
    return;
  }
  if (message?.t !== token || message.kind !== 'reply') return;
  const waiter = pending.get(message.id);
  if (waiter === undefined) return;
  pending.delete(message.id);
  if (message.ok) waiter.resolve(message.value);
  else waiter.reject(new Error(String(message.error ?? 'failed')));
});
lines.on('close', () => {
  for (const waiter of pending.values()) waiter.reject(new Error('The parent closed the channel.'));
});
