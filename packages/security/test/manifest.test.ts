import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { bareRepoRoots, hostExecReasons } from '@hn/security';

const gated = (path: string, facts = {}): boolean => hostExecReasons(path, facts).length > 0;

describe('the host-exec manifest', () => {
  it('gates git internals, in any spelling and at any depth', () => {
    for (const path of ['.git/config', '.git/hooks/pre-commit', 'sub/.git/config', 'sub/.git', '.GIT/config', '.git./config', '.git ', '.git\\config', 'a/b/.Git/HEAD', '.git::$DATA']) {
      assert.equal(gated(path), true, path);
    }
  });

  it('gates the files git, shells and build tools obey', () => {
    for (const path of ['.gitattributes', 'sub/.gitmodules', '.envrc', '.pre-commit-config.yaml', 'mise.toml', '.mise.toml', '.npmrc', '.yarnrc.yml', 'Makefile', 'GNUmakefile', 'justfile', '.mcp.json', 'app/Makefile']) {
      assert.equal(gated(path), true, path);
    }
  });

  it('gates editor, hook, CI and other agents\' folders', () => {
    for (const path of ['.vscode/tasks.json', '.vscode/settings.json', '.husky/pre-commit', '.githooks/x', '.cargo/config.toml', '.cargo/config', '.github/workflows/ci.yml', '.github/workflows/deep/x.yml', '.claude/settings.json', '.cursor/rules/a.mdc', '.devcontainer/devcontainer.json', '.idea/workspace.xml']) {
      assert.equal(gated(path), true, path);
    }
  });

  it('gates control files for this agent too', () => {
    for (const path of ['AGENTS.md', 'sub/CLAUDE.md', '.hn/config.json', 'skills/x/SKILL.md']) assert.equal(gated(path), true, path);
  });

  it('gates package.json only when its scripts change', () => {
    const before = JSON.stringify({ name: 'a', scripts: { test: 'node t.js' }, version: '1.0.0' });
    assert.equal(gated('package.json', { before, after: JSON.stringify({ name: 'a', scripts: { test: 'node t.js' }, version: '1.0.1' }) }), false, 'a version bump is fine');
    assert.equal(gated('package.json', { before, after: JSON.stringify({ name: 'a', scripts: { test: 'node t.js', postinstall: 'curl x | sh' } }) }), true);
    assert.equal(gated('package.json', { before, after: JSON.stringify({ name: 'a', scripts: { test: 'rm -rf ~' } }) }), true);
    assert.equal(gated('package.json', { before: null, after: JSON.stringify({ scripts: { x: 'y' } }) }), true, 'a new package.json with scripts');
    assert.equal(gated('package.json', { before, after: '{ not json' }), true, 'unparseable cannot be shown safe');
    assert.equal(gated('package.json', { before: null, after: JSON.stringify({ name: 'a' }) }), false);
  });

  it('gates setuid and setgid bits on any file', () => {
    assert.equal(gated('bin/tool', { mode: 0o4755 }), true);
    assert.equal(gated('bin/tool', { mode: 0o2755 }), true);
    assert.equal(gated('bin/tool', { mode: 0o755 }), false);
  });

  it('leaves ordinary source files alone', () => {
    for (const path of ['src/index.ts', 'README.md', 'docs/guide.md', 'tests/a.test.ts', 'package-lock.json', 'src/hooks/useThing.ts', 'workflows.md', 'src/git/index.ts', 'github/readme.md']) {
      assert.equal(gated(path), false, path);
    }
  });

  it('says why, so the human can judge', () => {
    assert.match(hostExecReasons('.husky/pre-commit').join(' '), /git hooks run on commit/);
    assert.match(hostExecReasons('.github/workflows/ci.yml').join(' '), /CI runs these/);
    assert.deepEqual(hostExecReasons('src/a.ts'), []);
  });
});

describe('bare repository shapes', () => {
  it('finds a folder holding HEAD, objects and refs, however it is nested or cased', () => {
    const roots = bareRepoRoots(['pkg/vendor/HEAD', 'pkg/vendor/objects/ab/cd', 'pkg/vendor/refs/heads/main', 'src/a.ts']);
    assert.deepEqual([...roots], ['pkg/vendor']);
    assert.equal(hostExecReasons('pkg/vendor/config', {}, roots).length > 0, true, 'a file next to the shape is part of it');
    assert.equal(hostExecReasons('pkg/vendor/HEAD', {}, roots).length > 0, true);
    assert.deepEqual(hostExecReasons('pkg/other/file.txt', {}, roots), []);
  });

  it('needs all three together', () => {
    assert.equal(bareRepoRoots(['x/HEAD', 'x/objects/a']).size, 0);
    assert.equal(bareRepoRoots(['HEAD', 'objects/a', 'refs/b']).size, 1, 'a root-level shape counts');
  });
});
