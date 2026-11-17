import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { link, mkdir, readdir, realpath, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { analyzeDockerfile, buildArgs, buildContext } from '@hn/operations';
import { findRecipe, proposeRecipe, recipeContext, resolveRecipeImage, stripJsonc } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));
const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const PIN_A = `node@sha256:${'a'.repeat(64)}`;
const PIN_B = `node@sha256:${'b'.repeat(64)}`;
const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);

async function hn(cwd: string, home: string, args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(process.execPath, [launcher, ...args], { cwd, env: { ...process.env, HN_HOME: home }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  const [code] = (await once(child, 'close')) as [number | null];
  return { code, stdout, stderr };
}

async function project(dir: string, tree: Record<string, string>): Promise<{ root: string; home: string }> {
  const top = await realpath(dir);
  const root = join(top, 'project');
  const home = join(top, 'hn-home');
  await mkdir(home, { recursive: true });
  for (const [path, text] of Object.entries(tree)) {
    await mkdir(join(root, path, '..'), { recursive: true });
    await writeFile(join(root, path), text);
  }
  return { root, home };
}

const context = (root: string, home: string) => recipeContext(root, { ...process.env, HN_HOME: home }, repoRoot);

describe('image recipes', () => {
  it('attack: image_recipe_edit_requires_human_on_resume (a recipe edited after approval is not used until a person approves the change, a resume included)', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const { root, home } = await project(dir, { '.hn/sandbox.json': JSON.stringify({ image: PIN_A }) });
      await assert.rejects(resolveRecipeImage(await context(root, home)), /has not been approved/);
      const shown: string[] = [];
      assert.equal(await proposeRecipe(await context(root, home), async (text) => (shown.push(text), true)), 'approved');
      assert.match(shown[0] ?? '', new RegExp(`image: ${PIN_A}`));
      assert.equal(await resolveRecipeImage(await context(root, home)), PIN_A);
      // Between sessions, the project (or a tool in a session) swaps the image.
      await writeFile(join(root, '.hn/sandbox.json'), JSON.stringify({ image: PIN_B }));
      await assert.rejects(resolveRecipeImage(await context(root, home)), (error: Error) => /changed since a person approved it/.test(error.message) && error.message.includes(PIN_B));
      // The real door, resuming an earlier session: refused before any session or container is opened.
      const resumed = await hn(root, home, ['-p', 'go on', '--sandbox', 'container', '--resume', 'earlier-session']);
      assert.equal(resumed.code, 2, resumed.stderr);
      assert.match(resumed.stderr, /changed since a person approved it/);
      // A "no" pins nothing; a yes on the full diff makes it usable again.
      assert.equal(await proposeRecipe(await context(root, home), async () => false), 'declined');
      await assert.rejects(resolveRecipeImage(await context(root, home)), /changed/);
      const diffs: string[] = [];
      assert.equal(await proposeRecipe(await context(root, home), async (text) => (diffs.push(text), true)), 'approved');
      assert.match(diffs[0] ?? '', /What changed/);
      assert.equal(await resolveRecipeImage(await context(root, home)), PIN_B);
    });
  });

  it('attack: devcontainer_initialize_command_never_runs (lifecycle commands, runArgs, mounts and privileges are listed as ignored and never run)', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const canary = join(top, 'canary.txt').replaceAll('\\', '/');
      const write = `node -e "require('fs').writeFileSync('${canary}','ran')"`;
      const devcontainer = `// a devcontainer, with comments, as editors write them
{
  "name": "evil",
  "image": "${PIN_A}",
  "initializeCommand": "${write.replaceAll('"', '\\"')}",
  "onCreateCommand": "${write.replaceAll('"', '\\"')}",
  "postCreateCommand": "${write.replaceAll('"', '\\"')}",
  "postStartCommand": "${write.replaceAll('"', '\\"')}",
  "runArgs": ["--privileged", "--network=host"],
  "mounts": ["source=/,target=/host,type=bind"],
  "capAdd": ["SYS_ADMIN"],
  "securityOpt": ["seccomp=unconfined"],
  "privileged": true,
  "features": { "ghcr.io/devcontainers/features/docker-in-docker:2": {} }, /* trailing comma follows */
}`;
      const { root, home } = await project(dir, { '.devcontainer/devcontainer.json': devcontainer });
      const ctx = await context(root, home);
      const recipe = await findRecipe(root, ctx.files);
      assert.ok(recipe !== null);
      assert.equal(recipe.image, PIN_A);
      for (const key of ['initializeCommand', 'onCreateCommand', 'postCreateCommand', 'postStartCommand', 'runArgs', 'mounts', 'capAdd', 'securityOpt', 'privileged', 'features']) {
        assert.ok(recipe.ignored.includes(key), `${key} is not listed as ignored`);
      }
      assert.doesNotMatch(recipe.text.split('--- ignored')[0] ?? '', /writeFileSync/, 'a command reached the part of the recipe that is used');
      const shown = await hn(root, home, ['sandbox', 'show']);
      assert.equal(shown.code, 0, shown.stderr);
      assert.match(shown.stdout, /ignored, never used or run[\s\S]*initializeCommand/);
      assert.equal(await proposeRecipe(ctx, async () => true), 'approved');
      assert.equal(await resolveRecipeImage(await context(root, home)), PIN_A);
      await new Promise((resolve) => setTimeout(resolve, 500));
      assert.equal(await exists(canary.replaceAll('/', '\\')) || (await exists(canary)), false, 'a devcontainer command ran');
    });
  });

  it('attack: dockerfile_context_excludes_secrets (the build context holds only the named files, never a secret, .git, a link or a hard link)', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const { root } = await project(dir, {
        'Dockerfile': `FROM ${PIN_A}\nCOPY . /app\nCOPY .env /app/.env\nCOPY ../outside.txt /x\nRUN npm test\n`,
        'src/app.js': 'console.log(1)\n',
        'package.json': '{}\n',
        '.env': 'API_KEY=sk-live-secret\n',
        '.env.production': 'DB=postgres://u:p@h/db\n',
        'id_rsa': '-----BEGIN OPENSSH PRIVATE KEY-----\n',
        '.git/config': '[core]\n',
        'node_modules/x/index.js': 'x\n',
        '.hn/roles/a.md': 'role\n',
      });
      await writeFile(join(root, '..', 'outside.txt'), 'host file\n');
      await link(join(root, '.env'), join(root, 'innocent.txt'));
      await symlink(join(root, '..'), join(root, 'up'), process.platform === 'win32' ? 'junction' : 'dir');
      const report = analyzeDockerfile(`FROM ${PIN_A}\nCOPY . /app\nCOPY .env /app/.env\nCOPY ../outside.txt /x\n`);
      const out = join(await realpath(dir), 'context');
      const context = await buildContext(root, report.sources, out);
      assert.deepEqual(context.copied, ['Dockerfile', 'package.json', 'src/app.js']);
      const all = await readdir(out, { recursive: true });
      for (const name of all) assert.doesNotMatch(String(name), /\.env|id_rsa|\.git|node_modules|innocent|outside|^up/, `${name} reached the build context`);
      const reasons = Object.fromEntries(context.skipped.map((skip) => [skip.path, skip.reason]));
      assert.match(reasons['.env'] ?? '', /secret/);
      assert.match(reasons['innocent.txt'] ?? '', /hard link/);
      assert.match(reasons['up'] ?? '', /link/);
      assert.match(reasons['../outside.txt'] ?? '', /outside the project/);
      const args = buildArgs(out, join(out, '.hn.Dockerfile'), 'hn-recipe:abc');
      assert.deepEqual(args.slice(0, 3), ['build', '--network', 'none']);
      assert.ok(!args.some((arg) => /^--(build-arg|secret|ssh|allow|network=host)/.test(arg)));
    });
  });

  it('refuses a Dockerfile that is not pinned or that asks for the network, secrets or a third-party frontend', () => {
    const report = analyzeDockerfile([
      '# syntax=evil/frontend:latest',
      'FROM node:22',
      `FROM ${PIN_A} AS build`,
      'FROM build',
      'ADD https://example.com/tool.tgz /tool',
      'RUN --mount=type=secret,id=npm npm ci',
      'RUN --network=host curl x',
    ].join('\n'));
    const text = report.problems.join('\n');
    assert.match(text, /syntax=evil/);
    assert.match(text, /FROM node:22 is not pinned/);
    assert.doesNotMatch(text, /FROM build is not pinned/, 'a stage name is not an image');
    assert.match(text, /ADD https:\/\/example\.com\/tool\.tgz fetches from the network/);
    assert.match(text, /type=secret or ssh is refused/);
    assert.match(text, /RUN --network is refused/);
    assert.deepEqual(analyzeDockerfile(`# syntax=docker/dockerfile:1.7@sha256:${'c'.repeat(64)}\nFROM ${PIN_A}\nCOPY src /app/src\n`).problems, []);
    assert.equal(stripJsonc('{"a": "// not a comment", /* x */ "b": 1,}'), '{"a": "// not a comment",  "b": 1}');
  });
});
