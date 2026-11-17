import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createSafeFiles, findHelper } from '@hn/operations';
import { TrustStore } from '@hn/security';
import { withTempDir } from '@hn/testkit';
import type { HarnessExec, ToolContext } from '@hn/tools';
import { openSkills, withCatalogue } from '../src/skills.ts';

const helper = await findHelper({ repoRoot: fileURLToPath(new URL('../../../', import.meta.url)) });
const signal = new AbortController().signal;

async function write(path: string, text: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, text);
}

/** Records validate runs instead of spawning anything. */
function fakeExec(runs: string[]): HarnessExec {
  return {
    run: async (request: { command: string }) => {
      runs.push(request.command);
      return { ok: true, code: 0, output: 'ok' };
    },
  } as unknown as HarnessExec;
}

describe('skills through the real helper', { skip: helper === null ? 'hn-sandbox is not built' : false }, () => {
  const files = createSafeFiles(helper as string);

  it('puts a user skill in the catalogue row, holds back an unapproved project skill, and validates after a change', async () => {
    await withTempDir(async (dir) => {
      const home = join(dir, 'hn-home');
      const repo = join(dir, 'repo');
      const release = '---\nname: release\ndescription: Cut a release.\nvalidate: pnpm test\n---\n- [ ] tag it';
      await write(join(home, 'skills', 'release', 'SKILL.md'), release);
      await write(join(repo, '.hn', 'skills', 'deploy', 'SKILL.md'), '---\nname: deploy\ndescription: Ship it.\n---\nGo.');
      const runs: string[] = [];
      const setup = await openSkills({
        files,
        hnHome: home,
        projectRoot: repo,
        trust: new TrustStore(join(home, 'trust'), randomBytes(32)),
        exec: fakeExec(runs),
      });
      assert.deepEqual(setup.set.skills.map((skill) => skill.name), ['release']);
      assert.match(setup.notes.join('\n'), /Skill not loaded until approved \(new\): project\/deploy\/SKILL\.md/);

      const frame = await withCatalogue(null, setup.set).snapshot();
      assert.match(frame.text, /- release: Cut a release\./);
      assert.doesNotMatch(frame.text, /tag it/, 'only level 1 is in the prompt');
      assert.doesNotMatch(frame.text, /More tools exist/, 'no list when there are no deferred tools');
      // Found live: a small model told to use read_image gave up, because nothing it could see named the tool.
      const listed = await withCatalogue(null, setup.set, ['read_image', 'skill', 'spawn_agent']).snapshot();
      assert.match(listed.text, /Find one with tool_search, then run it with call_tool: read_image, skill, spawn_agent\./);
      assert.notEqual(listed.digest, frame.digest, 'the row is re-sent by digest, so the list is part of it');

      const body = await setup.tool.execute({ name: 'release' }, { signal } as unknown as ToolContext);
      assert.match(body.content, /tag it/);
      assert.equal(await setup.validator.afterRound(['read_file'], signal), null);
      assert.match((await setup.validator.afterRound(['edit_file'], signal))?.text ?? '', /validate passed/);
      assert.deepEqual(runs, ['pnpm test']);
    });
  });

  it('loads a project skill once a person says yes to its exact bytes on the card', async () => {
    await withTempDir(async (dir) => {
      const home = join(dir, 'hn-home');
      const repo = join(dir, 'repo');
      await mkdir(home, { recursive: true });
      await write(join(repo, '.hn', 'skills', 'deploy', 'SKILL.md'), '---\nname: deploy\ndescription: Ship it.\n---\nGo.');
      const shown: string[] = [];
      const setup = await openSkills({
        files,
        hnHome: home,
        projectRoot: repo,
        trust: new TrustStore(join(home, 'trust'), randomBytes(32)),
        exec: fakeExec([]),
        approve: async (file) => {
          shown.push(file.content.toString('utf8'));
          return true;
        },
      });
      assert.deepEqual(setup.set.skills.map((skill) => skill.name), ['deploy']);
      assert.match(shown[0] ?? '', /name: deploy/);
    });
  });
});
