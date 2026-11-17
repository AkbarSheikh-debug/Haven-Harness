import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { mkdir, readFile, readdir, realpath, rename, rmdir, stat, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { withTempDir } from '@hn/testkit';
import { CheckpointPolicy, CheckpointStore, RollbackRefused, createSafeFiles, findHelper, type SafeFiles } from '@hn/operations';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const KEY = Buffer.from('c'.repeat(32));
const API_KEY = 'sk-ant-api03-Zq8vN2mXk4Lp7TrW9yBc3Dh6Fj1Gs5Aa';

let files: SafeFiles;
before(async () => {
  const helper = await findHelper({ env: {}, repoRoot });
  assert.ok(helper !== null, 'hn-sandbox is not built. Run: pnpm build:sandbox');
  files = createSafeFiles(helper);
});

interface Kit {
  root: string;
  outside: string;
  store: CheckpointStore;
  dir: string;
}

async function kit(dir: string, tree: Record<string, string> = {}, options: { key?: Buffer; maxFileBytes?: number; maxCheckpoints?: number } = {}): Promise<Kit> {
  const base = await realpath(dir);
  const root = join(base, 'project');
  const outside = join(base, 'outside');
  await mkdir(root);
  await mkdir(outside);
  await writeFile(join(outside, 'secret.txt'), 'TOP SECRET');
  for (const [path, text] of Object.entries(tree)) {
    await mkdir(join(root, path, '..'), { recursive: true });
    await writeFile(join(root, path), text);
  }
  const storeDir = join(base, 'store');
  const store = new CheckpointStore({ dir: storeDir, key: options.key ?? KEY, files, ...(options.maxFileBytes === undefined ? {} : { maxFileBytes: options.maxFileBytes }), ...(options.maxCheckpoints === undefined ? {} : { maxCheckpoints: options.maxCheckpoints }) });
  return { root, outside, store, dir: storeDir };
}

async function put(root: string, path: string, text: string): Promise<void> {
  await mkdir(join(root, path, '..'), { recursive: true });
  await writeFile(join(root, path), text);
}

const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);

describe('creating a checkpoint', () => {
  it('saves the tree, with a hash that is the same for the same content', async () => {
    await withTempDir(async (dir) => {
      const { root, store } = await kit(dir, { 'src/a.ts': 'a', 'README.md': 'hello world' });
      const first = await store.create(root, { session: 's1', reason: 'before bash' });
      const second = await store.create(root, { session: 's1', reason: 'again' });
      assert.equal(first.fileCount, 2);
      assert.equal(first.treeHash, second.treeHash);
      assert.deepEqual([first.seq, second.seq], [1, 2]);
      assert.equal(first.ref, 's1/1');
      await put(root, 'src/a.ts', 'changed');
      assert.notEqual((await store.create(root, { session: 's1', reason: 'x' })).treeHash, first.treeHash);
      assert.deepEqual((await store.list()).map((info) => info.seq), [1, 2, 3]);
    });
  });

  it('attack: checkpoint_excludes_secrets (by name, by content, and in nested places)', async () => {
    await withTempDir(async (dir) => {
      const { root, store, dir: storeDir } = await kit(dir, {
        'src/a.ts': 'ordinary source',
        '.env': 'DB_PASSWORD=hunter2hunter2',
        'sub/.env.local': 'TOKEN=abc',
        'keys/id_rsa': 'PRIVATE',
        'config/notes.txt': `the key is ${API_KEY}`,
        'config/creds.yaml': 'password: correct-horse-battery',
      });
      const info = await store.create(root, { session: 's', reason: 'x' });
      const skipped = new Map(info.skipped.map((entry) => [entry.path, entry.why]));
      for (const path of ['.env', 'sub/.env.local', 'keys/id_rsa']) assert.match(skipped.get(path) ?? '', /secrets/, path);
      assert.match(skipped.get('config/notes.txt') ?? '', /holds a secret/);
      assert.match(skipped.get('config/creds.yaml') ?? '', /holds a secret/);
      assert.equal(info.fileCount, 1);
      // Nothing in long-term storage may contain a secret, or even ordinary file text in the clear.
      const everything = (await readdir(storeDir, { recursive: true, withFileTypes: true })).filter((entry) => entry.isFile());
      for (const entry of everything) {
        const bytes = await readFile(join(entry.parentPath, entry.name));
        for (const forbidden of ['hunter2', API_KEY, 'PRIVATE', 'correct-horse', 'ordinary source']) assert.equal(bytes.includes(Buffer.from(forbidden)), false, `${forbidden} is in ${entry.name}`);
      }
    });
  });

  it('never honours project ignore files, because the attacker would decide what is saved', async () => {
    await withTempDir(async (dir) => {
      const { root, store } = await kit(dir, { '.gitignore': 'dist/\n*.ts\n', 'dist/out.js': 'built', 'a.ts': 'a' });
      const info = await store.create(root, { session: 's', reason: 'x' });
      assert.equal(info.fileCount, 3);
    });
  });

  it('reports nested git trees, dependency folders, links, special files and oversize files as skipped', async () => {
    await withTempDir(async (dir) => {
      const { root, outside, store } = await kit(dir, { 'a.txt': 'a', 'vendor/lib/.git/config': '[core]', '.git/HEAD': 'ref', 'node_modules/x/i.js': 'x', 'big.bin': 'x'.repeat(2000) }, { maxFileBytes: 1000 });
      symlinkSync(outside, join(root, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
      const info = await store.create(root, { session: 's', reason: 'x' });
      const why = (path: string): string => info.skipped.find((entry) => entry.path === path)?.why ?? '(not reported)';
      assert.match(why('.git'), /git internals/);
      assert.match(why('vendor/lib/.git'), /git internals/);
      assert.match(why('node_modules'), /dependency folder/);
      assert.match(why('link'), /link/);
      assert.match(why('big.bin'), /over 1000 bytes/);
      assert.equal(info.fileCount, 1);
    });
  });
});

describe('restoring', () => {
  it('puts everything back: edits, deletions and files added since', async () => {
    await withTempDir(async (dir) => {
      const { root, store } = await kit(dir, { 'a.ts': 'one', 'b.ts': 'two', 'deep/c.ts': 'three' });
      const saved = await store.create(root, { session: 's', reason: 'x' });
      await put(root, 'a.ts', 'broken');
      await unlink(join(root, 'b.ts'));
      await put(root, 'new.ts', 'added by the agent');
      await put(root, 'deep/more/d.ts', 'also added');
      const report = await store.restore(root, saved.seq, { boxAlive: () => false, deleteNew: true });
      assert.deepEqual([...report.restored].sort(), ['a.ts', 'b.ts']);
      assert.deepEqual([...report.deleted].sort(), ['deep/more/d.ts', 'new.ts']);
      assert.equal(await readFile(join(root, 'a.ts'), 'utf8'), 'one');
      assert.equal(await readFile(join(root, 'b.ts'), 'utf8'), 'two');
      assert.equal(await exists(join(root, 'new.ts')), false);
    });
  });

  it('keeps a person\'s own edits when only the agent\'s paths are restored', async () => {
    await withTempDir(async (dir) => {
      const { root, store } = await kit(dir, { 'agent.ts': 'a', 'mine.ts': 'm' });
      const saved = await store.create(root, { session: 's', reason: 'x' });
      await put(root, 'agent.ts', 'agent broke it');
      await put(root, 'mine.ts', 'I fixed this by hand');
      const report = await store.restore(root, saved.seq, { boxAlive: () => false, paths: ['agent.ts'] });
      assert.deepEqual(report.restored, ['agent.ts']);
      assert.equal(await readFile(join(root, 'mine.ts'), 'utf8'), 'I fixed this by hand');
    });
  });

  it('does not touch a file that is already as saved', async () => {
    await withTempDir(async (dir) => {
      const { root, store } = await kit(dir, { 'a.ts': 'same' });
      const saved = await store.create(root, { session: 's', reason: 'x' });
      assert.deepEqual((await store.restore(root, saved.seq, { boxAlive: () => false })).restored, []);
    });
  });

  it('attack: rollback_refuses_while_box_alive', async () => {
    await withTempDir(async (dir) => {
      const { root, store } = await kit(dir, { 'a.ts': 'one' });
      const saved = await store.create(root, { session: 's', reason: 'x' });
      await put(root, 'a.ts', 'two');
      await assert.rejects(store.restore(root, saved.seq, { boxAlive: () => true }), RollbackRefused);
      await assert.rejects(store.restore(root, saved.seq, { boxAlive: async () => true }), /still running/);
      assert.equal(await readFile(join(root, 'a.ts'), 'utf8'), 'two', 'a restore ran while the box was alive');
    });
  });

  it('attack: rollback_reports_skipped_paths (what was never saved, and what could not be restored)', async () => {
    await withTempDir(async (dir) => {
      const { root, outside, store } = await kit(dir, { 'src/a.ts': 'a', '.env': 'K=1', 'vendor/.git/config': '[core]' });
      const saved = await store.create(root, { session: 's', reason: 'x' });
      // The agent replaced a folder with a link to the outside.
      await rename(join(root, 'src'), join(root, 'src-moved'));
      if (process.platform === 'win32') execFileSync('cmd', ['/C', 'mklink', '/J', join(root, 'src'), outside], { stdio: 'ignore' });
      else symlinkSync(outside, join(root, 'src'));
      const report = await store.restore(root, saved.seq, { boxAlive: () => false });
      assert.ok(report.skipped.some((entry) => entry.path === '.env'), 'a secret that was never saved was not reported');
      assert.ok(report.skipped.some((entry) => entry.path === 'vendor/.git'), 'a nested git tree was not reported');
      assert.ok(report.failed.some((entry) => entry.path === 'src/a.ts' && /link/i.test(entry.why)), 'a restore through a link was not refused and reported');
      assert.deepEqual(await readdir(outside), ['secret.txt'], 'the restore wrote through the link');
      await (process.platform === 'win32' ? rmdir(join(root, 'src')) : unlink(join(root, 'src')));
    });
  });

  it('refuses a checkpoint that does not exist', async () => {
    await withTempDir(async (dir) => {
      const { root, store } = await kit(dir, { 'a.ts': 'a' });
      await assert.rejects(store.restore(root, 99, { boxAlive: () => false }), /no checkpoint 99/);
    });
  });
});

describe('the store on disk', () => {
  it('cannot be read with another key, and a changed object is not restored', async () => {
    await withTempDir(async (dir) => {
      const { root, store, dir: storeDir } = await kit(dir, { 'a.ts': 'secretly ordinary' });
      const saved = await store.create(root, { session: 's', reason: 'x' });
      const stranger = new CheckpointStore({ dir: storeDir, key: Buffer.from('z'.repeat(32)), files });
      assert.deepEqual(await stranger.list(), []);
      await assert.rejects(stranger.restore(root, saved.seq, { boxAlive: () => false }), /no checkpoint/);

      const objects = await readdir(join(storeDir, 'objects'));
      const target = join(storeDir, 'objects', objects[0] as string);
      const bytes = await readFile(target);
      bytes[bytes.length - 1] = (bytes[bytes.length - 1] as number) ^ 1;
      await writeFile(target, bytes);
      await put(root, 'a.ts', 'edited');
      const report = await store.restore(root, saved.seq, { boxAlive: () => false });
      assert.deepEqual(report.restored, []);
      assert.equal(report.failed.length, 1);
      assert.equal(await readFile(join(root, 'a.ts'), 'utf8'), 'edited', 'tampered data was written back');
    });
  });

  it('keeps the newest checkpoints, protects what a live session references, and removes unreferenced objects', async () => {
    await withTempDir(async (dir) => {
      const { root, store, dir: storeDir } = await kit(dir, { 'a.txt': 'v0' }, { maxCheckpoints: 2 });
      for (let i = 1; i <= 4; i += 1) {
        await put(root, 'a.txt', `v${i}`);
        await store.create(root, { session: i === 1 ? 'old-live' : 'other', reason: `step ${i}` });
      }
      const result = await store.prune(new Set(['old-live']));
      assert.deepEqual((await store.list()).map((info) => info.seq), [1, 3, 4]);
      assert.equal(result.removedCheckpoints, 1);
      assert.equal(result.removedObjects, 1, 'only the object nothing points to is removed');
      assert.equal((await readdir(join(storeDir, 'objects'))).length, 3);
      const report = await store.restore(root, 1, { boxAlive: () => false });
      assert.deepEqual(report.restored, ['a.txt']);
      assert.equal(await readFile(join(root, 'a.txt'), 'utf8'), 'v1');
    });
  });
});

describe('when to snapshot', () => {
  it('snapshots before the first mutating step in each directory, bash included', () => {
    const policy = new CheckpointPolicy({ now: () => 0 });
    assert.equal(policy.shouldSnapshot('/repo', 1), true);
    assert.equal(policy.shouldSnapshot('/repo', 2), false);
    assert.equal(policy.shouldSnapshot('/repo/sub', 3), true, 'a new directory gets its own snapshot');
    assert.equal(policy.shouldSnapshot('/repo/sub', 4), false);
  });

  it('then at most once per 50 steps or 10 minutes, so a long run has many restore points but not one per step', () => {
    let now = 0;
    const policy = new CheckpointPolicy({ now: () => now });
    assert.equal(policy.shouldSnapshot('/repo', 1), true);
    let taken = 0;
    for (let step = 2; step <= 200; step += 1) if (policy.shouldSnapshot('/repo', step)) taken += 1;
    assert.equal(taken, 3, 'one every 50 steps over 200 steps');
    now += 10 * 60_000;
    assert.equal(policy.shouldSnapshot('/repo', 201), true, 'ten minutes passed');
    assert.equal(policy.shouldSnapshot('/repo', 202), false);
  });
});
