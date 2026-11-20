import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

export interface FakeReply {
  readonly text?: string;
  readonly toolCalls?: readonly { id: string; name: string; args: unknown }[];
  readonly usage?: { input: number; output: number };
  /** When set, the call fails with this error instead of replying. */
  readonly error?: Error;
}

/** A model that plays back a script, so loop tests need no network and no luck. */
export class FakeModel {
  readonly requests: unknown[] = [];
  #script: FakeReply[];

  constructor(script: readonly FakeReply[]) {
    this.#script = [...script];
  }

  get remaining(): number {
    return this.#script.length;
  }

  async complete(request: unknown): Promise<FakeReply> {
    this.requests.push(request);
    const reply = this.#script.shift();
    if (reply === undefined) throw new Error('FakeModel script ran out: the loop made an extra call.');
    if (reply.error !== undefined) throw reply.error;
    return reply;
  }
}

/** A seeded generator (mulberry32), so a failing fuzz run can be replayed exactly. */
export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = state;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}

export async function withTempDir<T>(run: (directory: string) => Promise<T>): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), 'hn-test-'));
  try {
    return await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
}

/**
 * Compares a value with its stored golden file. Run with UPDATE_GOLDEN=1 to write
 * the file, then review the diff: an unreviewed golden proves nothing.
 */
export async function assertGolden(path: string, value: unknown): Promise<void> {
  const actual = `${JSON.stringify(value, null, 2)}\n`;
  if (process.env['UPDATE_GOLDEN'] === '1') {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, actual);
    return;
  }
  const expected = await readFile(path, 'utf8').catch(() => null);
  if (expected === null) throw new Error(`Golden file ${path} is missing. Run with UPDATE_GOLDEN=1.`);
  assert.equal(actual, expected.replaceAll('\r\n', '\n'));
}

/** A tool call a fake model asks for. */
export interface FakeCall {
  readonly id: string;
  readonly name: string;
  readonly args: unknown;
}

/** One reply of a fake OpenAI-compatible model: words, tool calls, or both. */
export interface FakeOpenAIReply {
  readonly text?: string;
  readonly calls?: readonly FakeCall[];
  /** An HTTP error instead of a reply, such as 429; with `retryAfter` (seconds) as the Retry-After header. */
  readonly status?: number;
  readonly retryAfter?: number;
}

export interface FakeOpenAIRequest {
  readonly model?: string;
  readonly messages: readonly { readonly role: string; readonly content?: unknown; readonly tool_calls?: unknown }[];
  readonly tools?: readonly { readonly function?: { readonly name?: string } }[];
}

export interface FakeOpenAI {
  readonly url: string;
  readonly requests: FakeOpenAIRequest[];
  /** When each request arrived (ms since the epoch), in the same order as `requests`. */
  readonly arrivals: number[];
  /** The headers of each request, in the same order. */
  readonly headers: Record<string, string | string[] | undefined>[];
  close(): Promise<void>;
}

function sseChunks(reply: FakeOpenAIReply): string {
  const lines = [
    ...(reply.text === undefined ? [] : [{ choices: [{ delta: { content: reply.text } }] }]),
    ...(reply.calls ?? []).map((call, index) => ({ choices: [{ delta: { tool_calls: [{ index, id: call.id, function: { name: call.name, arguments: JSON.stringify(call.args) } }] } }] })),
    { choices: [{ delta: {}, finish_reason: reply.calls === undefined || reply.calls.length === 0 ? 'stop' : 'tool_calls' }] },
    { choices: [], usage: { prompt_tokens: 100, completion_tokens: 10 } },
  ];
  return lines.map((line) => 'data: ' + JSON.stringify(line) + '\n\n').join('') + 'data: [DONE]\n\n';
}

/**
 * A fake OpenAI-compatible chat server on 127.0.0.1, for tests that drive the real session stack, child processes
 * included. `decide` sees each request and returns the reply; it may be async, to hold a child mid-run.
 */
export async function startFakeOpenAI(decide: (request: FakeOpenAIRequest) => FakeOpenAIReply | Promise<FakeOpenAIReply>): Promise<FakeOpenAI> {
  const { createServer } = await import('node:http');
  const requests: FakeOpenAIRequest[] = [];
  const arrivals: number[] = [];
  const headers: Record<string, string | string[] | undefined>[] = [];
  const server = createServer((request, response) => {
    headers.push({ ...request.headers });
    const parts: Buffer[] = [];
    request.on('data', (part: Buffer) => parts.push(part));
    request.on('end', () => {
      void (async () => {
        try {
          const body = JSON.parse(Buffer.concat(parts).toString('utf8')) as FakeOpenAIRequest;
          requests.push(body);
          arrivals.push(Date.now());
          const reply = await decide(body);
          if (reply.status !== undefined) {
            response.writeHead(reply.status, { 'content-type': 'application/json', ...(reply.retryAfter === undefined ? {} : { 'retry-after': String(reply.retryAfter) }) });
            response.end(JSON.stringify({ error: { message: 'fake error' } }));
            return;
          }
          response.writeHead(200, { 'content-type': 'text/event-stream' });
          response.end(sseChunks(reply));
        } catch (error) {
          response.writeHead(500);
          response.end(String(error));
        }
      })();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as { port: number };
  return {
    url: 'http://127.0.0.1:' + String(address.port),
    requests,
    arrivals,
    headers,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** The text of the newest message with this role in a fake request. */
export function lastContent(request: FakeOpenAIRequest, role: string): string {
  const found = [...request.messages].reverse().find((message) => message.role === role);
  return typeof found?.content === 'string' ? found.content : JSON.stringify(found?.content ?? '');
}
export * from './fake-idp.ts';
export * from './attack-registry.ts';
