import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { availableParallelism } from 'node:os';
import type { EventType, Origin, SessionEvent } from '@hn/core';
import { join as joinOrigins } from '@hn/security';

/** Section 11.4's limits. */
export interface WorkflowLimits {
  readonly concurrency: number;
  readonly maxAgents: number;
  readonly maxItems: number;
  readonly maxResultChars: number;
}

export function defaultLimits(): WorkflowLimits {
  return { concurrency: Math.max(1, Math.min(16, availableParallelism() - 2)), maxAgents: 1_000, maxItems: 4_096, maxResultChars: 50_000 };
}

/** The pipe to one runner process: lines of JSON each way. */
export interface RunnerChannel {
  send(message: unknown): void;
  onMessage(listener: (message: unknown) => void): void;
  readonly exited: Promise<{ readonly code: number | null }>;
  kill(): void;
}

/** What a script's sub-calls do. Each runs exactly as the same call from the model would: gated, logged, narrowed. */
export interface WorkflowHandlers {
  agent(request: { readonly path: string; readonly key: string; readonly prompt: string; readonly opts: Readonly<Record<string, unknown>> }, signal: AbortSignal): Promise<{ readonly value: unknown; readonly origin: Origin; readonly child?: string }>;
  tool(request: { readonly path: string; readonly key: string; readonly name: string; readonly args: Readonly<Record<string, unknown>> }, signal: AbortSignal): Promise<{ readonly value: unknown; readonly origin: Origin }>;
}

export interface WorkflowRun {
  readonly run: string;
  readonly ok: boolean;
  readonly result?: unknown;
  readonly error?: string;
  readonly fatal?: boolean;
  /** The worst origin of everything the script's sub-calls brought in, and never better than model-derived. */
  readonly origin: Origin;
  readonly agents: number;
  readonly replayed: number;
}

export function scriptHash(script: string, args: unknown): string {
  return createHash('sha256').update(script).update('\0').update(JSON.stringify(args ?? null)).digest('hex');
}

/** The journal key (11.4): call path, prompt or tool, schema, model and inputs. */
export function callKey(path: string, what: string, details: unknown): string {
  return createHash('sha256').update(JSON.stringify([path, what, details])).digest('hex').slice(0, 32);
}

export interface JournalEntry {
  readonly value: unknown;
  readonly origin: Origin;
}

/** What an earlier, unfinished run of this script left in the log: its seed and clock, and every finished call. */
export interface Journal {
  readonly run: string;
  readonly seed: number;
  readonly startedAt: number;
  readonly done: ReadonlyMap<string, JournalEntry>;
}

/**
 * The newest run of this exact script and arguments that never ended well, rebuilt from the `workflow/*` rows of the
 * calling session. Null when there is none, so the run starts fresh.
 */
export function findJournal(events: readonly SessionEvent[], hash: string): Journal | null {
  const starts = events.filter((event) => event.type === 'workflow/run-start' && event.data['scriptHash'] === hash);
  for (const start of starts.reverse()) {
    const run = String(start.data['run']);
    if (events.some((event) => event.type === 'workflow/run-end' && event.data['run'] === run && event.data['ok'] === true)) continue;
    const done = new Map<string, JournalEntry>();
    for (const event of events) {
      if ((event.type === 'workflow/agent-end' || event.type === 'workflow/tool') && event.data['run'] === run && event.data['ok'] === true && typeof event.data['key'] === 'string') {
        done.set(event.data['key'], { value: event.data['value'] ?? null, origin: (event.data['origin'] as Origin | undefined) ?? 'model-derived' });
      }
    }
    return { run, seed: Number(start.data['seed']), startedAt: Number(start.data['startedAt']), done };
  }
  return null;
}

export interface RunOptions {
  readonly script: string;
  readonly args: unknown;
  readonly meta?: Readonly<Record<string, unknown>>;
  readonly launch: () => RunnerChannel;
  readonly handlers: WorkflowHandlers;
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  /** The calling session's log, for the journal. */
  readonly events: () => readonly SessionEvent[];
  readonly limits?: WorkflowLimits;
  readonly signal: AbortSignal;
  readonly now?: () => number;
}

const MAX_LOGS = 200;

function sameToken(given: unknown, token: string): boolean {
  if (typeof given !== 'string') return false;
  const a = Buffer.from(given);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Runs one workflow (section 11.4). The script runs in a fresh runner process; this side holds the token, treats every
 * message as hostile, journals every finished sub-call in the calling session, and replays journaled calls when an
 * unfinished run of the same script is found, so a crash costs only the calls that had not finished.
 */
export async function runWorkflow(options: RunOptions): Promise<WorkflowRun> {
  const limits = options.limits ?? defaultLimits();
  const hash = scriptHash(options.script, options.args);
  const journal = findJournal(options.events(), hash);
  const run = journal?.run ?? randomBytes(9).toString('base64url');
  const seed = journal?.seed ?? randomInt(0, 2 ** 31);
  const startedAt = journal?.startedAt ?? (options.now ?? Date.now)();
  const token = randomBytes(24).toString('base64url');
  let worst: Origin = 'model-derived';
  let agents = 0;
  let replayed = 0;
  let logs = 0;
  if (journal === null) options.record('workflow/run-start', { run, scriptHash: hash, seed, startedAt, meta: options.meta ?? {} });
  else options.record('workflow/run-start', { run, scriptHash: hash, seed, startedAt, resumed: true, journaled: journal.done.size });

  const channel = options.launch();
  const inner = new AbortController();
  const signal = AbortSignal.any([options.signal, inner.signal]);
  const onAbort = (): void => channel.kill();
  signal.addEventListener('abort', onAbort, { once: true });
  const reply = (id: number, outcome: { ok: true; value: unknown } | { ok: false; error: string }): void => channel.send({ t: token, kind: 'reply', id, ...outcome });

  const handle = async (message: Record<string, unknown>): Promise<void> => {
    const id = Number(message['id']);
    const op = message['op'];
    const path = typeof message['path'] === 'string' ? message['path'].slice(0, 500) : '';
    try {
      if (op === 'log' || op === 'phase') {
        if (logs++ < MAX_LOGS) options.record(op === 'log' ? 'workflow/log' : 'workflow/phase', { run, text: String(message['message'] ?? message['title'] ?? '').slice(0, 2_000) });
        reply(id, { ok: true, value: null });
        return;
      }
      if (op === 'agent') {
        const prompt = String(message['prompt'] ?? '');
        const opts = (typeof message['opts'] === 'object' && message['opts'] !== null ? message['opts'] : {}) as Record<string, unknown>;
        const key = callKey(path, prompt, { schema: opts['schema'] ?? null, model: opts['model'] ?? null, agent: opts['agent'] ?? null });
        agents += 1;
        const known = journal?.done.get(key);
        if (known !== undefined) {
          replayed += 1;
          worst = joinOrigins(worst, known.origin);
          reply(id, { ok: true, value: known.value });
          return;
        }
        options.record('workflow/agent-start', { run, key, path, label: String(opts['label'] ?? '').slice(0, 200), phase: String(opts['phase'] ?? '').slice(0, 200) });
        const outcome = await options.handlers.agent({ path, key, prompt, opts }, signal);
        worst = joinOrigins(worst, outcome.origin);
        options.record('workflow/agent-end', { run, key, ok: true, value: outcome.value as never, origin: outcome.origin, ...(outcome.child === undefined ? {} : { child: outcome.child }) });
        reply(id, { ok: true, value: outcome.value });
        return;
      }
      if (op === 'tool') {
        const name = String(message['name'] ?? '');
        const args = (typeof message['args'] === 'object' && message['args'] !== null ? message['args'] : {}) as Record<string, unknown>;
        const key = callKey(path, `tool:${name}`, args);
        const known = journal?.done.get(key);
        if (known !== undefined) {
          replayed += 1;
          worst = joinOrigins(worst, known.origin);
          reply(id, { ok: true, value: known.value });
          return;
        }
        const outcome = await options.handlers.tool({ path, key, name, args }, signal);
        worst = joinOrigins(worst, outcome.origin);
        options.record('workflow/tool', { run, key, name, ok: true, value: outcome.value as never, origin: outcome.origin });
        reply(id, { ok: true, value: outcome.value });
        return;
      }
      reply(id, { ok: false, error: `unknown call ${String(op)}` });
    } catch (error) {
      reply(id, { ok: false, error: error instanceof Error ? error.message : String(error) });
    }
  };

  const finished = new Promise<WorkflowRun>((resolve) => {
    channel.onMessage((raw) => {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return;
      const message = raw as Record<string, unknown>;
      // Anything without this run's token is dropped: nothing else in the box can call a tool through the runner.
      if (!sameToken(message['t'], token)) {
        options.record('sandbox/event', { kind: 'workflow-message-dropped', run });
        return;
      }
      if (message['kind'] === 'call' && Number.isSafeInteger(message['id'])) void handle(message);
      else if (message['kind'] === 'done') {
        const ok = message['ok'] === true;
        resolve({
          run,
          ok,
          ...(ok ? { result: message['result'] } : { error: String(message['error'] ?? 'the workflow failed'), fatal: message['fatal'] === true }),
          origin: worst,
          agents,
          replayed,
        });
      }
    });
    void channel.exited.then(() => resolve({ run, ok: false, error: signal.aborted ? 'The workflow was stopped.' : 'The runner stopped without finishing.', origin: worst, agents, replayed }));
  });
  channel.send({ t: token, kind: 'start', script: options.script, args: options.args ?? null, seed, startedAt, limits });
  const result = await finished;
  signal.removeEventListener('abort', onAbort);
  inner.abort();
  channel.kill();
  options.record('workflow/run-end', { run, ok: result.ok, agents: result.agents, replayed: result.replayed, ...(result.ok ? {} : { error: result.error ?? '' }) });
  return result;
}
