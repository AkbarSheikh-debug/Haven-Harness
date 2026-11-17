import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { symlinkSync } from 'node:fs';
import { link, mkdir, readFile, readdir, realpath, rename, rmdir, symlink, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { withTempDir } from '@hn/testkit';
import { SafeFileError, createSafeFiles, findHelper, localOperations, relativeInside, type SafeFiles } from '@hn/operations';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));

let files: SafeFiles;
before(async () => {
  const helper = await findHelper({ env: {}, repoRoot });
  assert.ok(helper !== null, 'hn-sandbox is not built. Run: pnpm build:sandbox');
  files = createSafeFiles(helper);
});

interface Project {
  root: string;
  outside: string;
}

async function project(dir: string): Promise<Project> {
  const base = await realpath(dir);
  const root = join(base, 'project');
  const outside = join(base, 'outside');
  await mkdir(root);
  await mkdir(outside);
  await writeFile(join(outside, 'secret.txt'), 'TOP SECRET');
  return { root, outside };
}

/** A directory link that needs no privilege on Windows. */
function linkDirectory(at: string, target: string): void {
  if (process.platform === 'win32') execFileSync('cmd', ['/C', 'mklink', '/J', at, target], { stdio: 'ignore' });
  else symlinkSync(target, at);
}

async function refusal(promise: Promise<unknown>): Promise<SafeFileError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof SafeFileError, `expected a SafeFileError, got ${String(error)}`);
    return error;
  }
  assert.fail('expected a refusal');
}

describe('safeRead and safeWrite', () => {
  it('read and write ordinary files, making folders as needed', async () => {
    await withTempDir(async (dir) => {
      const { root } = await project(dir);
      await files.write(root, join(root, 'a', 'b', 'c.txt'), Buffer.from('hello'), { mkdir: true });
      assert.equal((await files.read(root, join(root, 'a', 'b', 'c.txt'), 1000)).toString(), 'hello');
      await files.write(root, join(root, 'a', 'b', 'c.txt'), Buffer.from('replaced'));
      assert.equal(await readFile(join(root, 'a', 'b', 'c.txt'), 'utf8'), 'replaced');
      assert.deepEqual(await readdir(join(root, 'a', 'b')), ['c.txt'], 'a temp file was left behind');
    });
  });

  it('keeps exact bytes, including binary and non-ASCII text', async () => {
    await withTempDir(async (dir) => {
      const { root } = await project(dir);
      const bytes = Buffer.from([0, 255, 10, 13, 0xe2, 0x82, 0xac, 0x80, 1]);
      await files.write(root, join(root, 'b.bin'), bytes);
      assert.deepEqual(await files.read(root, join(root, 'b.bin'), 100), bytes);
    });
  });

  it('refuses paths outside the project without starting the helper', async () => {
    await withTempDir(async (dir) => {
      const { root, outside } = await project(dir);
      assert.equal((await refusal(files.read(root, join(outside, 'secret.txt'), 100))).reason, 'outside_root');
      assert.equal((await refusal(files.write(root, join(root, '..', 'x.txt'), Buffer.from('x')))).reason, 'outside_root');
      assert.throws(() => relativeInside(root, root), SafeFileError);
    });
  });

  it('reports a missing file as ENOENT, so existing handling keeps working', async () => {
    await withTempDir(async (dir) => {
      const { root } = await project(dir);
      const error = await refusal(files.read(root, join(root, 'nope.txt'), 100));
      assert.equal(error.code, 'ENOENT');
    });
  });

  it('refuses a file over the limit, and a create-only write over an existing file', async () => {
    await withTempDir(async (dir) => {
      const { root } = await project(dir);
      await files.write(root, join(root, 'big.txt'), Buffer.alloc(5000, 'x'));
      assert.equal((await refusal(files.read(root, join(root, 'big.txt'), 100))).reason, 'too_large');
      assert.equal((await refusal(files.write(root, join(root, 'big.txt'), Buffer.from('y'), { createOnly: true }))).code, 'EEXIST');
    });
  });
});

describe('attacks the Node jail cannot stop on its own', () => {
  it('a folder that is a link to the outside is refused for reads, writes and mkdir', async () => {
    await withTempDir(async (dir) => {
      const { root, outside } = await project(dir);
      linkDirectory(join(root, 'sub'), outside);
      assert.equal((await refusal(files.read(root, join(root, 'sub', 'secret.txt'), 100))).reason, 'link');
      assert.equal((await refusal(files.write(root, join(root, 'sub', 'new.txt'), Buffer.from('x')))).reason, 'link');
      assert.equal((await refusal(files.write(root, join(root, 'sub', 'deep', 'new.txt'), Buffer.from('x'), { mkdir: true }))).reason, 'link');
      assert.deepEqual(await readdir(outside), ['secret.txt'], 'a write went through the link');
    });
  });

  it('attack: hardlink_to_denied_file_refused', async () => {
    await withTempDir(async (dir) => {
      const { root, outside } = await project(dir);
      await link(join(outside, 'secret.txt'), join(root, 'innocent.txt'));
      assert.equal((await refusal(files.read(root, join(root, 'innocent.txt'), 100))).reason, 'hardlink');
      assert.equal((await refusal(files.write(root, join(root, 'innocent.txt'), Buffer.from('x')))).reason, 'hardlink');
      assert.equal(await readFile(join(outside, 'secret.txt'), 'utf8'), 'TOP SECRET');
    });
  });

  it('attack: agents_md_symlink_to_secret_not_loaded (a hardlink on Windows, a symlink elsewhere)', async () => {
    await withTempDir(async (dir) => {
      const { root, outside } = await project(dir);
      if (process.platform === 'win32') await link(join(outside, 'secret.txt'), join(root, 'AGENTS.md'));
      else await symlink(join(outside, 'secret.txt'), join(root, 'AGENTS.md'));
      const error = await refusal(files.read(root, join(root, 'AGENTS.md'), 100));
      assert.ok(['link', 'hardlink'].includes(error.reason), error.reason);
    });
  });

  it('attack: symlink_swap_during_read_write', async () => {
    await withTempDir(async (dir) => {
      const { root, outside } = await project(dir);
      const sub = join(root, 'sub');
      const holding = join(root, 'sub-real');
      await mkdir(sub);
      await writeFile(join(sub, 'secret.txt'), 'harmless inside');

      let flips = 0;
      let busy = false;
      // Every tick moves the real folder away, puts a link to the outside in its place, and undoes it.
      const timer = setInterval(() => {
        if (busy) return;
        busy = true;
        rename(sub, holding)
          .then(async () => {
            linkDirectory(sub, outside);
            flips += 1;
            await new Promise((resolve) => setTimeout(resolve, 2));
            await (process.platform === 'win32' ? rmdir(sub) : unlink(sub)).catch(() => undefined);
            await rename(holding, sub).catch(() => undefined);
          })
          .catch(() => undefined)
          .finally(() => {
            busy = false;
          });
      }, 0);

      let leaked = false;
      for (let i = 0; i < 60; i += 1) {
        const text = await files.read(root, join(sub, 'secret.txt'), 100).then(
          (bytes) => bytes.toString(),
          () => '',
        );
        if (text === 'TOP SECRET') leaked = true;
        await files.write(root, join(sub, 'written.txt'), Buffer.from('w')).catch(() => undefined);
      }
      clearInterval(timer);
      await new Promise((resolve) => setTimeout(resolve, 50));
      assert.ok(flips > 0, 'the folder was never swapped, so this test proved nothing');
      assert.equal(leaked, false, 'a read returned a file from outside the project');
      assert.deepEqual(await readdir(outside), ['secret.txt'], 'a write landed outside the project');
    });
  });
});

describe('local operations in safe mode', () => {
  it('route project reads and writes through the helper, and refuse what it refuses', async () => {
    await withTempDir(async (dir) => {
      const { root, outside } = await project(dir);
      const ops = localOperations(join(dir, 'spill'), { safe: { files, root } });
      await ops.write.mkdir(join(root, 'x', 'y'));
      await ops.write.writeFile(join(root, 'x', 'y', 'f.txt'), Buffer.from('data'));
      assert.equal((await ops.read.readFile(join(root, 'x', 'y', 'f.txt'))).toString(), 'data');
      await assert.rejects(ops.read.readFile(join(outside, 'secret.txt')), SafeFileError);
      linkDirectory(join(root, 'sub'), outside);
      await assert.rejects(ops.read.readFile(join(root, 'sub', 'secret.txt')), SafeFileError);
    });
  });

  it('still work the ordinary way when no helper is given', async () => {
    await withTempDir(async (dir) => {
      const ops = localOperations(join(dir, 'spill'));
      await writeFile(join(dir, 'plain.txt'), 'plain');
      assert.equal((await ops.read.readFile(join(dir, 'plain.txt'))).toString(), 'plain');
    });
  });
});

describe('finding the helper', () => {
  it('returns null when nothing runnable is found, so the caller can refuse', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'not-a-helper.exe'), 'nope');
      assert.equal(await findHelper({ env: { HN_SANDBOX_BIN: join(dir, 'not-a-helper.exe') } }), null);
      assert.equal(await findHelper({ env: {} }), null);
      assert.equal(await findHelper({ env: { HN_SANDBOX_BIN: join(dir, 'missing') }, repoRoot: join(dir, 'nowhere'), home: dir }), null);
    });
  });

  it('finds the built helper in the repo', async () => {
    assert.ok((await findHelper({ env: {}, repoRoot })) !== null);
  });
});
