import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { describe, it } from 'node:test';
import { Workspaces, findGit, git, gitTopLevel } from '@hn/operations';
import { withTempDir } from '@hn/testkit';

async function repo(dir: string): Promise<string> {
  const root = join(await realpath(dir), 'project');
  await mkdir(root);
  await git(['init', '--quiet', '-b', 'main'], { cwd: root });
  await writeFile(join(root, 'a.txt'), 'one\ntwo\nthree\n');
  await writeFile(join(root, 'b.txt'), 'bee\n');
  await git(['add', '-A'], { cwd: root });
  await git(['commit', '--quiet', '-m', 'start'], { cwd: root });
  return root;
}

const exists = (path: string) => readFile(path).then(() => true, () => false);

describe('hardened git', () => {
  it('is found by absolute path, and ignores a relative override', async () => {
    const found = await findGit();
    assert.ok(found !== null && isAbsolute(found));
    assert.equal(await findGit({ HN_GIT_BIN: 'git', PATH: '.' }), await findGit({ PATH: '' }), 'a relative name or PATH entry is never used');
  });

  it('runs no hook and no fsmonitor that a repository names', async () => {
    await withTempDir(async (dir) => {
      const root = await repo(dir);
      const canary = join(dir, 'CANARY');
      const script = `#!/bin/sh\necho ran > "${canary.replaceAll('\\', '/')}"\n`;
      await writeFile(join(root, '.git', 'hooks', 'pre-commit'), script, { mode: 0o755 });
      await writeFile(join(root, '.git', 'hooks', 'post-commit'), script, { mode: 0o755 });
      await git(['config', 'core.fsmonitor', join(root, '.git', 'hooks', 'post-commit')], { cwd: root });
      await writeFile(join(root, 'c.txt'), 'c');
      await git(['add', '-A'], { cwd: root });
      await git(['commit', '--quiet', '-m', 'more'], { cwd: root });
      await git(['status'], { cwd: root });
      assert.equal(await exists(canary), false);
      assert.equal(await gitTopLevel(root), root);
      assert.equal(await gitTopLevel(dir), null);
    });
  });
});

describe('private clones for parallel writers (decision 3)', () => {
  it('two writers on different files both land; two on the same line: the second is a conflict, kept at its ref', async () => {
    await withTempDir(async (dir) => {
      const root = await repo(dir);
      const ws = new Workspaces({ repo: root, folder: join(dir, 'clones'), namespace: 'refs/hn/run-1' });
      assert.equal(await ws.check(), null);
      const a = await ws.create('child-a');
      const b = await ws.create('child-b');
      const c = await ws.create('child-c');
      await writeFile(join(a.path, 'a.txt'), 'one\nTWO FROM A\nthree\n');
      await writeFile(join(b.path, 'b.txt'), 'bee from b\n');
      await writeFile(join(b.path, 'new.txt'), 'brand new\n');
      await writeFile(join(c.path, 'a.txt'), 'one\nTWO FROM C\nthree\n');
      const ha = await ws.harvest('child-a', a.base, 'a');
      const hb = await ws.harvest('child-b', b.base, 'b');
      const hc = await ws.harvest('child-c', c.base, 'c');
      assert.deepEqual(hb?.files, ['b.txt', 'new.txt']);
      assert.deepEqual(await ws.land(ha!), { ok: true, files: ['a.txt'] });
      assert.deepEqual(await ws.land(hb!), { ok: true, files: ['b.txt', 'new.txt'] });
      const conflict = await ws.land(hc!);
      assert.equal(conflict.ok, false);
      assert.equal(conflict.ok ? '' : conflict.ref, 'refs/hn/run-1/child-c');
      assert.equal(await readFile(join(root, 'a.txt'), 'utf8'), 'one\nTWO FROM A\nthree\n', 'the first writer won, nothing was forced');
      assert.equal(await readFile(join(root, 'new.txt'), 'utf8'), 'brand new\n');
      const kept = await git(['show', 'refs/hn/run-1/child-c:a.txt'], { cwd: root });
      assert.match(kept.stdout, /TWO FROM C/, 'the losing work is not lost');
      assert.equal((await git(['rev-parse', 'main'], { cwd: root })).stdout.trim(), a.base, 'no branch of the project moved');
      const none = await ws.create('child-d');
      assert.equal(await ws.harvest('child-d', none.base, 'nothing'), null);
    });
  });

  it('never runs a filter planted in a clone config', async () => {
    await withTempDir(async (dir) => {
      const root = await repo(dir);
      const canary = join(dir, 'FILTER-CANARY').replaceAll('\\', '/');
      const ws = new Workspaces({ repo: root, folder: join(dir, 'clones'), namespace: 'refs/hn/run-2' });
      const clone = await ws.create('evil');
      await writeFile(join(clone.path, '.git', 'config'), `[filter "evil"]\n\tclean = node -e "require('fs').writeFileSync('${canary}','ran')"\n\trequired = true\n`);
      await writeFile(join(clone.path, '.gitattributes'), '* filter=evil\n');
      await writeFile(join(clone.path, 'a.txt'), 'changed\n');
      const harvest = await ws.harvest('evil', clone.base, 'x');
      assert.ok(harvest !== null);
      assert.equal(await exists(canary), false);
    });
  });

  it('refuses a dirty tree and a folder that is not a repository', async () => {
    await withTempDir(async (dir) => {
      const root = await repo(dir);
      await writeFile(join(root, 'a.txt'), 'uncommitted\n');
      assert.match((await new Workspaces({ repo: root, folder: join(dir, 'c'), namespace: 'refs/hn/x' }).check()) ?? '', /uncommitted changes/);
      const plain = join(dir, 'plain');
      await mkdir(plain);
      assert.match((await new Workspaces({ repo: plain, folder: join(dir, 'c'), namespace: 'refs/hn/x' }).check()) ?? '', /not a git repository/);
      assert.throws(() => new Workspaces({ repo: root, folder: dir, namespace: 'refs/heads/main' }), /under refs\/hn/);
    });
  });
});
