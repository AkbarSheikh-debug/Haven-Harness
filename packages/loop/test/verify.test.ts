import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { ModelReply, ModelRequest } from '@hn/provider';
import type { StopGate, StopGateVerdict } from '@hn/loop';
import { withTempDir } from '@hn/testkit';
import { config, fakeTools, open, ScriptedProvider, text, toolCalls } from './helpers.ts';

/** A check that fails until the model has written the fix. It counts rounds the way the real verifier does. */
class Check implements StopGate {
  fixed = false;
  runs = 0;
  #dirty = false;

  noteRound(names: readonly string[]): void {
    if (names.some((name) => name === 'write_file' || name === 'edit_file')) this.#dirty = true;
  }

  async check(): Promise<StopGateVerdict> {
    if (!this.#dirty) return { kind: 'accept' };
    this.runs += 1;
    if (this.fixed) {
      this.#dirty = false;
      return { kind: 'accept', note: 'The check `npm test` passed.' };
    }
    const failure = 'The check `npm test` failed: expected 2, got 3. Your answer is on hold.';
    return { kind: 'retry', text: failure, origin: 'tool-output' };
  }
}

describe('verify-on-stop in the loop', () => {
  it('sends back a model that stops with a failing check, and lets its fixed answer through', async () => {
    await withTempDir(async (directory) => {
      const check = new Check();
      const sawFailure = (request: ModelRequest): boolean => JSON.stringify(request.messages).includes('expected 2, got 3');
      const provider = new ScriptedProvider([
        toolCalls(['w1', 'write_file', { path: 'a.ts', content: 'return 3' }]),
        text('Done: a.ts is fixed.'),
        async (request): Promise<ModelReply> => {
          assert.ok(sawFailure(request), 'the failure output reached the model');
          return toolCalls(['w2', 'edit_file', { path: 'a.ts', old: '3', new: '2' }]);
        },
        text('Fixed for real: the test passes.'),
      ]);
      const tools = fakeTools({
        run: (name) => {
          if (name === 'edit_file') check.fixed = true;
          return { content: 'ok', isError: false, origin: 'workspace' };
        },
      });
      const agent = await open(directory, config(provider, tools, { stopGate: check }));
      const result = await agent.run('Fix the failing test in a.ts.');
      assert.equal(result.end, 'done');
      assert.equal(result.text, 'Fixed for real: the test passes.', 'the user sees the answer that got through');
      assert.equal(result.detail, 'The check `npm test` passed.');
      assert.equal(check.runs, 2);
      const held = agent.events.filter((event) => event.data['stopGate'] === true);
      assert.equal(held.length, 1);
      assert.equal(held[0]?.origin, 'tool-output');
      await agent.close();
    });
  });

  it('does not hold an answer to a question, when nothing changed', async () => {
    await withTempDir(async (directory) => {
      const check = new Check();
      const provider = new ScriptedProvider([toolCalls(['r1', 'read_file', { path: 'a.ts' }]), text('It returns 3.')]);
      const agent = await open(directory, config(provider, fakeTools(), { stopGate: check }));
      const result = await agent.run('What does a.ts return?');
      assert.equal(result.text, 'It returns 3.');
      assert.equal(check.runs, 0);
      await agent.close();
    });
  });
});
