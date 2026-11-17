import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { toolCallsOf, type SessionEvent } from '@hn/core';
import { Agent, type LoopConfig, type ToolDispatcher, type ToolOutcome } from '@hn/loop';
import { resolveCaps, type ModelProvider, type ModelReply, type ModelRequest, type StopReason } from '@hn/provider';

export const key = randomBytes(32);

export type Step = ModelReply | Error | ((request: ModelRequest) => Promise<ModelReply>);

export const text = (value: string, stopReason: StopReason = 'end'): ModelReply => ({
  parts: value === '' ? [] : [{ type: 'text', text: value }],
  stopReason,
  usage: { input: 10, output: 5, cacheRead: 0, cacheWrite: 0 },
  model: 'fake',
});

export const toolCalls = (...calls: [id: string, name: string, args?: unknown][]): ModelReply => ({
  parts: calls.map(([id, name, args]) => ({ type: 'tool_call', id, name, args: args ?? {} })),
  stopReason: 'tool_use',
  usage: { input: 10, output: 5, cacheRead: 0, cacheWrite: 0 },
  model: 'fake',
});

export class ScriptedProvider implements ModelProvider {
  readonly route = 'fake';
  readonly requests: ModelRequest[] = [];
  #script: Step[];

  constructor(script: Step[]) {
    this.#script = script;
  }

  async complete(request: ModelRequest): Promise<ModelReply> {
    this.requests.push(request);
    const step = this.#script.shift();
    if (step === undefined) throw new Error('The script ran out: the loop made an extra call.');
    if (step instanceof Error) throw step;
    return typeof step === 'function' ? step(request) : step;
  }
}

export interface FakeToolsOptions {
  run?: (name: string, args: unknown, signal: AbortSignal) => Promise<ToolOutcome> | ToolOutcome;
  safe?: (name: string) => boolean;
  writes?: (args: unknown) => string[];
}

export function fakeTools(options: FakeToolsOptions = {}): ToolDispatcher & { ran: string[] } {
  const ran: string[] = [];
  return {
    ran,
    specs: [{ name: 'read_file', description: 'read', parameters: { type: 'object' } }],
    check: (call) =>
      call.name === 'missing'
        ? { kind: 'unknown', message: 'No such tool.' }
        : call.name === 'invalid'
          ? { kind: 'invalid', message: 'Bad arguments.' }
          : { kind: 'ok', name: call.name, args: call.args },
    isConcurrencySafe: (name) => options.safe?.(name) ?? true,
    touches: (_name, args) => ({ reads: [], writes: options.writes?.(args) ?? [] }),
    run: async (call, signal) => {
      ran.push(call.id);
      return (await options.run?.(call.name, call.args, signal)) ?? { content: `ran ${call.id}`, isError: false, origin: 'workspace' };
    },
  };
}

export function config(provider: ModelProvider, tools: ToolDispatcher, overrides: Partial<LoopConfig> = {}): LoopConfig {
  return {
    provider,
    tools,
    caps: resolveCaps('fake', { window: 200_000, maxOutput: 32_000 }),
    model: 'fake',
    system: 'You are hn.',
    maxOutputTokens: 32_000,
    maxIterations: 50,
    maxParallelToolCalls: 10,
    retry: { sleep: async () => undefined, random: () => 0 },
    ...overrides,
  };
}

let sessionCounter = 0;

export function open(directory: string, loop: LoopConfig, sessionId = `s${(sessionCounter += 1)}`): Promise<Agent> {
  return Agent.open({ config: loop, path: join(directory, sessionId), sessionId, key, lockDir: directory });
}

export function assertPaired(events: readonly SessionEvent[]): void {
  const results = new Map<string, number>();
  for (const event of events) {
    if (event.type === 'tool/result') {
      const id = event.data['callId'] as string;
      results.set(id, (results.get(id) ?? 0) + 1);
    }
  }
  const calls = events.flatMap(toolCallsOf);
  for (const call of calls) {
    if (results.get(call.id) !== 1) throw new Error(`Call ${call.id} has ${results.get(call.id) ?? 0} results.`);
  }
  if (results.size !== new Set(calls.map((call) => call.id)).size) throw new Error('A result has no call.');
}

export const types = (events: readonly SessionEvent[]): string[] => events.map((event) => event.type);
