import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CheckpointPolicy, CheckpointStore, createSafeFiles, findHelper, type CheckpointInfo, type SafeFiles } from '@hn/operations';
import { withTempDir } from '@hn/testkit';
import { createCheckpointing } from '@hn/surfaces';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
let files: SafeFiles;
before(async () => {
  const helper = await findHelper({ env: {}, repoRoot });
  assert.ok(helper !== null, 'hn-sandbox is not built. Run: pnpm build:sandbox');
  files = createSafeFiles(helper);
});

async function kit(dir: string, tree: Record<string, string>, extra: { policy?: CheckpointPolicy } = {}) {
  const base = await realpath(dir);
  const root = join(base, 'project');
  await mkdir(root);
  for (const [path, text] of Object.entries(tree)) {
    await mkdir(join(root, path, '..'), { recursive: true });
    await writeFile(join(root, path), text);
  }
  const store = new CheckpointStore({ dir: join(base, 'store'), key: Buffer.from('k'.repeat(32)), files });
  const recorded: CheckpointInfo[] = [];
  const checkpointing = createCheckpointing({ store, sessionId: 'sess', root, record: (info) => void recorded.push(info), ...(extra.policy === undefined ? {} : { policy: extra.policy }) });
  return { root, store, recorded, checkpointing };
}

const put = (root: string, path: string, text: string): Promise<void> => writeFile(join(root, path), text);

describe('the session checkpoints', () => {
  it('snapshots before a first bash call even when it is the very first change', async () => {
    await withTempDir(async (dir) => {
      const { recorded, checkpointing } = await kit(dir, { 'a.txt': 'a' });
      await checkpointing.before({ tool: 'bash', writes: [] });
      assert.equal(recorded.length, 1, 'bash ran with nothing to go back to');
      assert.equal(recorded[0]?.reason, 'before bash');
    });
  });

  it('snapshots before the first change, once per directory, and records each in the log', async () => {
    await withTempDir(async (dir) => {
      const { root, recorded, checkpointing } = await kit(dir, { 'a.txt': 'a' });
      await checkpointing.before({ tool: 'write_file', writes: ['a.txt'] });
      await checkpointing.before({ tool: 'edit_file', writes: ['a.txt'] });
      assert.equal(recorded.length, 1, 'the second edit in the same folder did not need another');
      await mkdir(join(root, 'sub'));
      await checkpointing.before({ tool: 'write_file', writes: ['sub/b.txt'] });
      assert.equal(recorded.length, 2);
      await checkpointing.before({ tool: 'bash', writes: [] });
      assert.equal(recorded.length, 2, 'bash works in the project folder, which already has a snapshot inside the 50-step window');
      assert.deepEqual(recorded.map((info) => info.ref), ['sess/1', 'sess/2']);
      assert.match(recorded[0]?.treeHash ?? '', /^[0-9a-f]{64}$/);
    });
  });

  it('attack: a second call that runs at the same time waits for the snapshot, so nothing changes while files are saved', async () => {
    await withTempDir(async (dir) => {
      const base = await realpath(dir);
      const root = join(base, 'project');
      await mkdir(root);
      await writeFile(join(root, 'a.txt'), 'a');
      const events: string[] = [];
      class SlowStore extends CheckpointStore {
        override async create(...args: Parameters<CheckpointStore['create']>): Promise<CheckpointInfo> {
          events.push('snapshot starts');
          await new Promise((resolve) => setTimeout(resolve, 120));
          const info = await super.create(...args);
          events.push('snapshot done');
          return info;
        }
      }
      const store = new SlowStore({ dir: join(base, 'store'), key: Buffer.from('k'.repeat(32)), files });
      const checkpointing = createCheckpointing({ store, sessionId: 'sess', root, record: () => undefined });
      await Promise.all([
        checkpointing.before({ tool: 'write_file', writes: ['a.txt'] }).then(() => events.push('first may run')),
        checkpointing.before({ tool: 'bash', writes: [] }).then(() => events.push('second may run')),
        checkpointing.before({ tool: 'edit_file', writes: ['a.txt'] }).then(() => events.push('third may run')),
      ]);
      assert.deepEqual(events.slice(0, 3), ['snapshot starts', 'snapshot done', 'first may run'], 'a call was released before the snapshot finished');
      assert.ok(events.indexOf('second may run') > events.indexOf('snapshot done'));
      assert.ok(events.indexOf('third may run') > events.indexOf('snapshot done'));
    });
  });

  it('numbers concurrent snapshots without collisions', async () => {
    await withTempDir(async (dir) => {
      const { recorded, checkpointing } = await kit(dir, { 'a.txt': 'a' }, { policy: new CheckpointPolicy({ everySteps: 1, now: () => 0 }) });
      await Promise.all(Array.from({ length: 6 }, (_, i) => checkpointing.before({ tool: 'write_file', writes: [`f${i}.txt`] })));
      const seqs = recorded.map((info) => info.seq).sort((a, b) => a - b);
      assert.deepEqual(seqs, [1, 2, 3, 4, 5, 6], 'two snapshots shared a number');
    });
  });

  it('fails closed: when a snapshot cannot be saved, the change is refused', async () => {
    await withTempDir(async (dir) => {
      const { root, checkpointing } = await kit(dir, { 'a.txt': 'a' });
      // The store folder is replaced by a file, so nothing can be saved.
      await writeFile(join(root, '..', 'store'), 'not a folder');
      await assert.rejects(checkpointing.before({ tool: 'write_file', writes: ['a.txt'] }), /A checkpoint could not be saved, so write_file did not run/);
    });
  });

  it('by default restores only the files the agent wrote, so a person\'s own edits survive', async () => {
    await withTempDir(async (dir) => {
      const { root, checkpointing } = await kit(dir, { 'agent.txt': 'a1', 'mine.txt': 'm1' });
      await checkpointing.before({ tool: 'write_file', writes: ['agent.txt'] });
      await put(root, 'agent.txt', 'agent broke it');
      await put(root, 'mine.txt', 'I edited this by hand');
      const report = await checkpointing.rollback({ all: false });
      assert.deepEqual(report.restored, ['agent.txt']);
      assert.equal(await readFile(join(root, 'mine.txt'), 'utf8'), 'I edited this by hand');
      assert.equal(await readFile(join(root, 'agent.txt'), 'utf8'), 'a1');
      assert.equal(report.checkpoint.seq, 1);
    });
  });

  it('--all restores everything and removes what was added', async () => {
    await withTempDir(async (dir) => {
      const { root, checkpointing } = await kit(dir, { 'a.txt': 'a1', 'b.txt': 'b1' });
      await checkpointing.before({ tool: 'bash', writes: [] });
      await put(root, 'a.txt', 'a2');
      await put(root, 'b.txt', 'b2');
      await put(root, 'added.txt', 'new');
      const report = await checkpointing.rollback({ all: true });
      assert.deepEqual([...report.restored].sort(), ['a.txt', 'b.txt']);
      assert.deepEqual(report.deleted, ['added.txt']);
    });
  });

  it('attack: rollback_refuses_while_box_alive, and runs while stopped when it can stop the box', async () => {
    await withTempDir(async (dir) => {
      const { root, checkpointing } = await kit(dir, { 'a.txt': 'a1' });
      await checkpointing.before({ tool: 'write_file', writes: ['a.txt'] });
      await put(root, 'a.txt', 'a2');
      await assert.rejects(checkpointing.rollback({ all: true, boxAlive: () => true }), /still running/);
      assert.equal(await readFile(join(root, 'a.txt'), 'utf8'), 'a2');
      let stopped = false;
      const report = await checkpointing.rollback({
        all: true,
        boxAlive: () => !stopped,
        whileStopped: async (work) => {
          stopped = true;
          try {
            return await work();
          } finally {
            stopped = false;
          }
        },
      });
      assert.deepEqual(report.restored, ['a.txt']);
    });
  });

  it('says so when there is nothing to go back to', async () => {
    await withTempDir(async (dir) => {
      const { checkpointing } = await kit(dir, { 'a.txt': 'a' });
      await assert.rejects(checkpointing.rollback({ all: true }), /no checkpoint/);
    });
  });

  it('reports what was never saved with the rollback', async () => {
    await withTempDir(async (dir) => {
      const { root, checkpointing } = await kit(dir, { 'a.txt': 'a', '.env': 'K=1' });
      await checkpointing.before({ tool: 'write_file', writes: ['a.txt'] });
      await put(root, 'a.txt', 'changed');
      const report = await checkpointing.rollback({ all: true });
      assert.ok(report.skipped.some((entry) => entry.path === '.env'));
    });
  });
});
