import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { toolCallsOf } from '@hn/core';
import type { HookOutcome, LoopHooks, ToolCallRequest } from '@hn/loop';
import { deriveSurface } from '@hn/session';
import { withTempDir } from '@hn/testkit';
import { config, fakeTools, open, ScriptedProvider, text, toolCalls } from './helpers.ts';

const none: HookOutcome = { blocked: null, messages: [] };

/** Hooks that block chosen tools, say something after every tool, and can hold the answer. */
class Hooks implements LoopHooks {
  stopBlocks = 0;
  stops = 0;
  blockPrompt = false;
  readonly blockTools = new Set<string>();

  async sessionStart(): Promise<HookOutcome> {
    return { blocked: null, messages: [{ text: 'hook: session started', origin: 'hook' }] };
  }
  async userPrompt(): Promise<HookOutcome> {
    return this.blockPrompt ? { blocked: 'no secrets in prompts', messages: [] } : none;
  }
  async preTool(call: ToolCallRequest): Promise<HookOutcome> {
    return this.blockTools.has(call.name) ? { blocked: `policy: ${call.name} is off today`, messages: [] } : none;
  }
  async postTool(call: ToolCallRequest): Promise<HookOutcome> {
    return { blocked: null, messages: [{ text: `hook: saw ${call.id}`, origin: 'hook' }] };
  }
  async preVerify(): Promise<HookOutcome> {
    return none;
  }
  async stop(): Promise<HookOutcome> {
    this.stops += 1;
    return this.stops <= this.stopBlocks ? { blocked: 'the changelog is missing', messages: [] } : none;
  }
}

describe('hooks in the loop', () => {
  it('blocks a call a hook refuses without running it, and keeps hook output after all the results of the round', async () => {
    await withTempDir(async (directory) => {
      const hooks = new Hooks();
      hooks.blockTools.add('bash');
      const provider = new ScriptedProvider([
        toolCalls(['a', 'read_file', { path: 'x' }], ['b', 'bash', { command: 'rm -rf build' }], ['c', 'read_file', { path: 'y' }]),
        text('done'),
      ]);
      const tools = fakeTools();
      const agent = await open(directory, config(provider, tools, { hooks }));
      await agent.run('go');
      assert.deepEqual(tools.ran, ['a', 'c'], 'the blocked call never ran');
      const surface = deriveSurface(agent.events);
      const blocked = surface.find((row) => row.type === 'tool/result' && row.data['callId'] === 'b');
      assert.match(String(blocked?.data['content']), /A hook blocked this call: policy: bash is off today/);
      const call = surface.findIndex((row) => toolCallsOf(row).length === 3);
      const types = surface.slice(call + 1, call + 6).map((row) => row.type);
      assert.deepEqual(types, ['tool/result', 'tool/result', 'tool/result', 'user/message', 'user/message']);
      const hookRows = surface.filter((row) => String(row.data['text']).startsWith('hook: saw'));
      assert.ok(hookRows.length === 2 && hookRows.every((row) => row.origin === 'hook'));
      assert.equal(surface.filter((row) => row.data['text'] === 'hook: session started').length, 1);
      await agent.close();
    });
  });

  it('ends the turn when a hook blocks the prompt', async () => {
    await withTempDir(async (directory) => {
      const hooks = new Hooks();
      hooks.blockPrompt = true;
      const provider = new ScriptedProvider([]);
      const agent = await open(directory, config(provider, fakeTools(), { hooks }));
      const result = await agent.run('here is my password');
      assert.equal(result.end, 'refusal');
      assert.match(result.detail ?? '', /A hook blocked this prompt: no secrets in prompts/);
      assert.equal(provider.requests.length, 0, 'the model never saw it');
      await agent.close();
    });
  });

  it('sends the model back when a Stop hook holds the answer, but never more than three times', async () => {
    await withTempDir(async (directory) => {
      const hooks = new Hooks();
      hooks.stopBlocks = 10;
      const provider = new ScriptedProvider([text('one'), text('two'), text('three'), text('four')]);
      const agent = await open(directory, config(provider, fakeTools(), { hooks }));
      const result = await agent.run('go');
      assert.equal(result.text, 'four', 'after three holds the answer goes through');
      const holds = agent.events.filter((event) => String(event.data['text']).includes('A Stop hook held your answer'));
      assert.equal(holds.length, 3);
      await agent.close();
    });
  });
});
