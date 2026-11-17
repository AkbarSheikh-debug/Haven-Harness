import assert from 'node:assert/strict';
import { readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { localOperations } from '@hn/operations';
import { Gate, Jail } from '@hn/security';
import { createDispatcher } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

interface Seen {
  tool: string;
  writes: readonly string[];
}

async function kit(dir: string, beforeMutation: (call: Seen) => Promise<void>) {
  const root = await realpath(dir);
  const ops = localOperations(join(root, '..', 'spill-before'));
  const gate = new Gate({ mode: 'accept-edits', workdir: root, audit: () => undefined, jail: new Jail({ root, realpath: ops.read.realpath }), approver: async () => 'once' });
  const tools = createDispatcher({ gate, ops, workdir: root, beforeMutation });
  const run = async (name: string, args: unknown) => {
    const request = { id: `c-${name}-${Math.random()}`, name, args };
    const check = tools.check(request);
    if (check.kind !== 'ok') return { content: check.message, isError: true };
    return tools.run({ ...request, name: check.name, args: check.args }, new AbortController().signal);
  };
  return { root, run };
}

describe('the snapshot hook', () => {
  it('runs before a change, with the paths it will write, and not before a read', async () => {
    await withTempDir(async (dir) => {
      const seen: Seen[] = [];
      const { root, run } = await kit(dir, async (call) => void seen.push(call));
      await writeFile(join(root, 'a.txt'), 'hello');
      await run('read_file', { path: 'a.txt' });
      assert.deepEqual(seen, [], 'a read must not snapshot');
      await run('write_file', { path: 'b.txt', content: 'x' });
      assert.deepEqual(seen, [{ tool: 'write_file', writes: ['b.txt'] }]);
    });
  });

  it('runs before bash too, which is the gap other tools leave', async () => {
    await withTempDir(async (dir) => {
      const seen: Seen[] = [];
      const { run } = await kit(dir, async (call) => void seen.push(call));
      await run('bash', { command: 'echo hi' }).catch(() => undefined);
      assert.ok(seen.some((call) => call.tool === 'bash'), 'bash ran without a snapshot');
    });
  });

  it('stops the change when no snapshot can be saved, and says why', async () => {
    await withTempDir(async (dir) => {
      const { root, run } = await kit(dir, async () => {
        throw new Error('A checkpoint could not be saved, so write_file did not run: disk full');
      });
      const result = await run('write_file', { path: 'c.txt', content: 'x' });
      assert.equal(result.isError, true);
      assert.match(result.content, /could not be saved/);
      await assert.rejects(readFile(join(root, 'c.txt')), 'the file was written without a snapshot');
    });
  });

  it('does not run for a call the gate refused', async () => {
    await withTempDir(async (dir) => {
      const seen: Seen[] = [];
      const { run } = await kit(dir, async (call) => void seen.push(call));
      await run('write_file', { path: '.env', content: 'K=1' });
      assert.deepEqual(seen, [], 'a refused call must not cost a snapshot');
    });
  });
});
