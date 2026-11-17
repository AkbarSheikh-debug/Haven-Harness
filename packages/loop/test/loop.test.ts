import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { FlushFailedError } from '@hn/core';
import { Agent, toProviderMessages } from '@hn/loop';
import { ProviderError, type ModelRequest } from '@hn/provider';
import { parseLog } from '@hn/session';
import { seededRandom, withTempDir } from '@hn/testkit';
import { ScriptedProvider, assertPaired, config, fakeTools, key, open, text, toolCalls, types, type Step } from './helpers.ts';

async function runScript(script: Step[], tools = fakeTools(), overrides = {}) {
  return withTempDir(async (directory) => {
    const provider = new ScriptedProvider(script);
    const agent = await open(directory, config(provider, tools, overrides));
    const result = await agent.run('do it');
    const events = [...agent.events];
    await agent.close();
    return { result, events, provider, tools };
  });
}

describe('a turn', () => {
  it('ends on plain text, and the log says what happened', async () => {
    const { result, events } = await runScript([text('hello')]);
    assert.equal(result.text, 'hello');
    assert.equal(result.end, 'done');
    assert.deepEqual(types(events), [
      'turn/start',
      'user/message',
      'step/start',
      'assistant/attempt',
      'assistant/message',
      'step/end',
      'turn/end',
    ]);
  });

  it('runs tools and loops until the model answers in words', async () => {
    const { result, events, tools } = await runScript([toolCalls(['c1', 'read_file']), text('done')]);
    assert.equal(result.text, 'done');
    assert.deepEqual(tools.ran, ['c1']);
    assertPaired(events);
  });

  it('adds up usage across steps', async () => {
    const { result } = await runScript([toolCalls(['c1', 'read_file']), text('done')]);
    assert.deepEqual(result.usage, { input: 20, output: 10, cacheRead: 0, cacheWrite: 0 });
    assert.equal(result.steps, 2);
  });

  it('never changes the system prompt or tools, and only ever appends to history', async () => {
    const { provider } = await runScript([
      toolCalls(['c1', 'read_file']),
      toolCalls(['c2', 'read_file']),
      text('done'),
    ]);
    const [first, ...rest] = provider.requests as [ModelRequest, ...ModelRequest[]];
    for (const request of rest) {
      assert.equal(request.system, first.system);
      assert.equal(JSON.stringify(request.tools), JSON.stringify(first.tools));
    }
    provider.requests.slice(1).forEach((request, index) => {
      const previous = JSON.stringify(provider.requests[index]?.messages).slice(0, -1);
      assert.ok(JSON.stringify(request.messages).startsWith(previous), 'history must be a strict extension');
    });
  });
});

describe('intent before effect', () => {
  it('has the assistant row on disk before any tool body runs', async () => {
    await withTempDir(async (directory) => {
      let durableAtRun = false;
      const tools = fakeTools({
        run: async () => {
          const log = parseLog(await readFile(join(directory, 'intent')), key);
          durableAtRun = log.events.some((event) => event.type === 'assistant/message');
          return { content: 'ok', isError: false, origin: 'workspace' };
        },
      });
      const provider = new ScriptedProvider([toolCalls(['c1', 'read_file']), text('done')]);
      const agent = await open(directory, config(provider, tools), 'intent');
      await agent.run('go');
      await agent.close();
      assert.equal(durableAtRun, true);
    });
  });

  it('runs no tool when the log cannot be flushed', async () => {
    await withTempDir(async (directory) => {
      let diskFull = false;
      const tools = fakeTools();
      const provider = new ScriptedProvider([
        async () => {
          diskFull = true;
          return toolCalls(['c1', 'read_file']);
        },
      ]);
      const agent = await Agent.open({
        config: config(provider, tools),
        path: join(directory, 'log'),
        sessionId: 'full',
        key,
        lockDir: directory,
        writer: {
          beforeWrite: () => {
            if (diskFull) throw new Error('ENOSPC');
          },
        },
      });
      await assert.rejects(agent.run('go'), FlushFailedError);
      assert.deepEqual(tools.ran, []);
      diskFull = false;
      await agent.close();
    });
  });

  it('makes no model call when the log cannot be flushed', async () => {
    await withTempDir(async (directory) => {
      let diskFull = false;
      const provider = new ScriptedProvider([]);
      const agent = await Agent.open({
        config: config(provider, fakeTools()),
        path: join(directory, 'log'),
        sessionId: 'full',
        key,
        lockDir: directory,
        writer: {
          beforeWrite: () => {
            if (diskFull) throw new Error('ENOSPC');
          },
        },
      });
      diskFull = true;
      await assert.rejects(agent.run('go'), FlushFailedError);
      assert.equal(provider.requests.length, 0);
      diskFull = false;
      await agent.close();
    });
  });
});

describe('parallel tools', () => {
  it('runs together but lands results in call order', async () => {
    let active = 0;
    let peak = 0;
    const tools = fakeTools({
      run: async (_name, args) => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, (args as { delay: number }).delay));
        active -= 1;
        return { content: String((args as { delay: number }).delay), isError: false, origin: 'workspace' };
      },
    });
    const { events } = await runScript(
      [toolCalls(['a', 'read_file', { delay: 30 }], ['b', 'read_file', { delay: 1 }]), text('done')],
      tools,
    );
    assert.equal(peak, 2);
    assert.deepEqual(
      events.filter((event) => event.type === 'tool/result').map((event) => event.data['callId']),
      ['a', 'b'],
    );
  });

  it('never overlaps a writer with another touch of the same path', async () => {
    let active = 0;
    let peak = 0;
    const tools = fakeTools({
      writes: (args) => [(args as { path: string }).path],
      run: async () => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 5));
        active -= 1;
        return { content: 'ok', isError: false, origin: 'workspace' };
      },
    });
    await runScript([toolCalls(['a', 'write', { path: 'x' }], ['b', 'write', { path: 'x' }]), text('done')], tools);
    assert.equal(peak, 1);
  });

  it('runs an unsafe tool alone', async () => {
    const order: string[] = [];
    const tools = fakeTools({
      safe: (name) => name !== 'bash',
      run: async (name) => {
        order.push(`start ${name}`);
        await new Promise((resolve) => setTimeout(resolve, 2));
        order.push(`end ${name}`);
        return { content: 'ok', isError: false, origin: 'tool-output' };
      },
    });
    await runScript([toolCalls(['a', 'read_file'], ['b', 'bash'], ['c', 'read_file']), text('done')], tools);
    assert.deepEqual(order, ['start read_file', 'end read_file', 'start bash', 'end bash', 'start read_file', 'end read_file']);
  });

  it('caps how many run at once', async () => {
    let active = 0;
    let peak = 0;
    const tools = fakeTools({
      run: async () => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 2));
        active -= 1;
        return { content: 'ok', isError: false, origin: 'workspace' };
      },
    });
    const calls = Array.from({ length: 6 }, (_, index): [string, string] => [`c${index}`, 'read_file']);
    await runScript([toolCalls(...calls), text('done')], tools, { maxParallelToolCalls: 2 });
    assert.equal(peak, 2);
  });
});

describe('bad calls', () => {
  it('answers an unknown tool with an error, so the call still has its result', async () => {
    const { events, result } = await runScript([toolCalls(['c1', 'missing']), text('sorry')]);
    assertPaired(events);
    assert.equal(result.end, 'done');
    assert.equal(events.find((event) => event.type === 'tool/result')?.data['isError'], true);
  });

  it('gives a call its result even when the dispatcher throws, so the next request stays paired', async () => {
    const tools = fakeTools({
      run: (_name, args) => {
        if ((args as { boom?: boolean }).boom === true) throw new Error('internal bug');
        return { content: 'ok', isError: false, origin: 'workspace' };
      },
    });
    const { events, result, provider } = await runScript([toolCalls(['c1', 'read_file', { boom: true }], ['c2', 'read_file', {}]), text('noted')], tools);
    assert.equal(result.end, 'done');
    assertPaired(events);
    const failed = events.find((event) => event.type === 'tool/result' && event.data['callId'] === 'c1');
    assert.equal(failed?.data['isError'], true);
    assert.equal(failed?.origin, 'harness');
    assert.match(String(failed?.data['content']), /read_file failed inside the harness: internal bug/);
    const sent = provider.requests[1]?.messages.flatMap((message) => message.parts).filter((part) => part.type === 'tool_result');
    assert.deepEqual(sent?.map((part) => (part.type === 'tool_result' ? part.callId : '')), ['c1', 'c2']);
  });

  it('gives up after three strikes', async () => {
    const script = Array.from({ length: 3 }, (_, index) => toolCalls([`c${index}`, 'missing']));
    const { result, events } = await runScript(script);
    assert.equal(result.end, 'invalid_calls');
    assertPaired(events);
  });

  it('stops after a tool fails the same way five times', async () => {
    const tools = fakeTools({ run: () => ({ content: 'boom', isError: true, origin: 'tool-output' }) });
    const script = Array.from({ length: 5 }, (_, index) => toolCalls([`c${index}`, 'read_file']));
    const { result, events } = await runScript(script, tools);
    assert.equal(result.end, 'guardrail');
    assert.ok(events.some((event) => event.origin === 'harness' && event.type === 'user/message'), 'it warned first');
  });

  it('stops when a tool keeps returning the same thing', async () => {
    const tools = fakeTools({ run: () => ({ content: 'same', isError: false, origin: 'workspace' }) });
    const script = Array.from({ length: 5 }, (_, index) => toolCalls([`c${index}`, 'read_file']));
    assert.equal((await runScript(script, tools)).result.end, 'guardrail');
  });
});

describe('ending well', () => {
  it('turns the iteration limit into a summary request with tools off', async () => {
    const { result, provider } = await runScript([toolCalls(['c1', 'read_file']), text('summary')], fakeTools(), {
      maxIterations: 1,
    });
    assert.equal(result.end, 'budget');
    assert.equal(result.text, 'summary');
    assert.equal(provider.requests.at(-1)?.toolChoice, 'none');
  });

  it('nudges once on an empty reply, then settles for (empty)', async () => {
    const { result, events } = await runScript([text(''), text(''), text(''), text('')]);
    assert.equal(result.text, '(empty)');
    assert.equal(events.filter((event) => event.origin === 'harness' && event.type === 'user/message').length, 1);
  });

  it('continues a reply cut off by the output limit', async () => {
    const { result } = await runScript([text('Hello ', 'length'), text('world')]);
    assert.equal(result.text, 'Hello world');
  });

  it('asks again when a tool call was cut off', async () => {
    const { result, tools } = await runScript([text('', 'length'), toolCalls(['c1', 'read_file']), text('done')]);
    assert.equal(result.end, 'done');
    assert.deepEqual(tools.ran, ['c1']);
  });

  it('ends on a refusal without running anything', async () => {
    const { result, tools } = await runScript([text('', 'refusal')]);
    assert.equal(result.end, 'refusal');
    assert.deepEqual(tools.ran, []);
  });

  it('stops when the window is full', async () => {
    const huge = { ...text('x'), stopReason: 'tool_use' as const, usage: { input: 170_000, output: 0, cacheRead: 0, cacheWrite: 0 } };
    const { result, events } = await runScript([{ ...huge, parts: toolCalls(['c1', 'read_file']).parts }]);
    assert.equal(result.end, 'window_full');
    assertPaired(events);
  });
});

describe('failures', () => {
  it('retries what can succeed, and logs each retry', async () => {
    const { result, events } = await runScript([new ProviderError('overloaded', 'busy'), text('ok')]);
    assert.equal(result.text, 'ok');
    assert.equal(events.filter((event) => event.type === 'llm/retry').length, 1);
  });

  it('ends the turn on a failure retrying cannot fix', async () => {
    const { result } = await runScript([new ProviderError('auth', 'bad key')]);
    assert.equal(result.end, 'failed');
    assert.match(result.detail ?? '', /bad key/);
  });

  it('survives an unexpected error up to the cap, then stops', async () => {
    const { result } = await runScript(Array.from({ length: 8 }, () => new TypeError('bug')));
    assert.equal(result.end, 'failed');
  });
});

describe('the user interrupting', () => {
  it('stops mid-tool and records CANCELLED, with the log left legal', async () => {
    await withTempDir(async (directory) => {
      let agent: Agent | undefined;
      const tools = fakeTools({
        run: (_name, _args, signal) =>
          new Promise((resolve) => {
            signal.addEventListener('abort', () =>
              resolve({ content: 'CANCELLED', isError: true, origin: 'harness', cancelled: true }),
            );
            setImmediate(() => agent?.stop());
          }),
      });
      agent = await open(directory, config(new ScriptedProvider([toolCalls(['c1', 'read_file'])]), tools));
      const result = await agent.run('go');
      assert.equal(result.end, 'cancelled');
      assertPaired(agent.events);
      await agent.close();
    });
  });

  it('adds a steer after the newest tool result without stopping', async () => {
    await withTempDir(async (directory) => {
      let agent: Agent | undefined;
      const tools = fakeTools({
        run: () => {
          agent?.steer('use the other file');
          return { content: 'ok', isError: false, origin: 'workspace' };
        },
      });
      const provider = new ScriptedProvider([toolCalls(['c1', 'read_file']), text('done')]);
      agent = await open(directory, config(provider, tools));
      await agent.run('go');
      const rows = agent.events.filter((event) => ['tool/result', 'user/message'].includes(event.type));
      assert.deepEqual(rows.map((event) => event.type), ['user/message', 'tool/result', 'user/message']);
      assert.equal(rows.at(-1)?.origin, 'user');
      await agent.close();
    });
  });

  it('keeps partial text when corrected mid-reply', async () => {
    await withTempDir(async (directory) => {
      let agent: Agent | undefined;
      const provider = new ScriptedProvider([
        (request) =>
          new Promise((_resolve, reject) => {
            request.onEvent?.({ type: 'text', text: 'I will delete' });
            request.signal?.addEventListener('abort', () => reject(new ProviderError('aborted', 'stopped')));
            setImmediate(() => agent?.redirect('no, keep it'));
          }),
        text('understood'),
      ]);
      agent = await open(directory, config(provider, fakeTools()));
      const result = await agent.run('go');
      assert.equal(result.text, 'understood');
      const assistant = agent.events.filter((event) => event.type === 'assistant/message');
      assert.equal(assistant[0]?.data['text'], 'I will delete');
      assert.equal(agent.events.some((event) => event.data['text'] === 'no, keep it'), true);
      await agent.close();
    });
  });
});

describe('crashing and resuming', () => {
  it('resumes a crash mid-tool with an honest record, then carries on', async () => {
    await withTempDir(async (directory) => {
      const path = join(directory, 'crash');
      const crash = new Error('power cut');
      const tools = fakeTools({
        run: () => {
          throw crash;
        },
      });
      const first = await open(directory, config(new ScriptedProvider([toolCalls(['c1', 'bash'])]), tools), 'crash');
      await first.run('go').catch(() => undefined);
      await first.close();
      assert.ok(parseLog(await readFile(path), key).events.length > 0);

      const provider = new ScriptedProvider([text('resumed')]);
      const second = await open(directory, config(provider, fakeTools()), 'crash');
      const result = await second.run('carry on');
      assert.equal(result.text, 'resumed');
      assertPaired(second.events);
      await second.close();
    });
  });

  it('property: every call has exactly one result, across random sessions and kills', async () => {
    const random = seededRandom(424242);
    for (let round = 0; round < 60; round += 1) {
      await withTempDir(async (directory) => {
        const script: Step[] = [];
        const steps = 1 + Math.floor(random() * 5);
        for (let step = 0; step < steps; step += 1) {
          const width = 1 + Math.floor(random() * 3);
          script.push(toolCalls(...Array.from({ length: width }, (_, index): [string, string] => [`r${round}s${step}c${index}`, 'read_file'])));
        }
        script.push(text('done'));

        const provider = new ScriptedProvider(script);
        const agent = await open(directory, config(provider, fakeTools()), 'p');
        await agent.run('go');
        await agent.close();

        const path = join(directory, 'p');
        const bytes = await readFile(path);
        const { writeFile } = await import('node:fs/promises');
        await writeFile(path, bytes.subarray(0, Math.floor(random() * bytes.length)));

        const resumed = await open(directory, config(new ScriptedProvider([]), fakeTools()), 'p');
        assertPaired(resumed.events);
        await resumed.close();
        assertPaired(parseLog(await readFile(path), key).events);
      });
    }
  });
});

describe('thinking blocks and folds', () => {
  const opaque = { type: 'opaque', route: 'anthropic', value: { type: 'thinking', signature: 's' } };
  const event = (seq: number, type: string, data: Record<string, unknown>) =>
    ({ seq, ts: '2026-11-02T00:00:00.000Z', type, origin: 'harness', data }) as never;

  it('replays thinking on an untouched history', () => {
    const messages = toProviderMessages([event(1, 'assistant/message', { text: 'a', opaque: [opaque] })]);
    assert.deepEqual(messages[0]?.parts[0], opaque);
  });

  it('drops thinking at or before the newest fold, keeping text and tool calls', () => {
    const toolCall = { id: 'c', name: 'x', args: {} };
    const messages = toProviderMessages([
      event(1, 'assistant/message', { text: 'old', opaque: [opaque] }),
      event(2, 'user/message', { text: 'summary', surfaceOp: { op: 'replace', startSeq: 1, endSeq: 1, shadowedSeqs: [] } }),
      event(3, 'assistant/message', { text: 'after', opaque: [opaque], toolCalls: [toolCall] }),
    ]);
    assert.deepEqual(messages[0]?.parts, [{ type: 'text', text: 'old' }]);
    assert.deepEqual(messages[2]?.parts[0], opaque, 'blocks after the fold are still valid');
  });
});

describe('size limits', () => {
  it('keeps every source file small enough to read', async () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    for (const name of await readdir(root)) {
      const source = join(root, name, 'src');
      const files = await readdir(source, { recursive: true }).catch(() => [] as string[]);
      for (const file of files.filter((entry) => entry.endsWith('.ts'))) {
        const lines = (await readFile(join(source, file), 'utf8')).split('\n').length;
        assert.ok(lines <= 400, `${name}/src/${file} has ${lines} lines`);
      }
    }
  });
});
