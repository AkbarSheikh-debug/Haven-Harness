import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { link, mkdir, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createSafeFiles, findHelper } from '@hn/operations';
import { TrustStore } from '@hn/security';
import { withTempDir } from '@hn/testkit';
import { openInstructions } from '../src/instructions.ts';

const helper = await findHelper({ repoRoot: fileURLToPath(new URL('../../../', import.meta.url)) });

async function project(dir: string): Promise<{ root: string; home: string; outside: string }> {
  const root = join(dir, 'repo');
  const home = join(dir, 'hn-home');
  const outside = join(dir, 'outside');
  await mkdir(join(root, '.git'), { recursive: true });
  await mkdir(home, { recursive: true });
  await mkdir(outside, { recursive: true });
  await writeFile(join(outside, 'secret.txt'), 'AWS_SECRET=do-not-load-me');
  return { root, home, outside };
}

describe('instruction files through the real helper', { skip: helper === null ? 'hn-sandbox is not built' : false }, () => {
  const files = createSafeFiles(helper as string);

  it('attack: agents_md_symlink_to_secret_not_loaded, through the instruction chain', async () => {
    await withTempDir(async (dir) => {
      const { root, home, outside } = await project(dir);
      if (process.platform === 'win32') await link(join(outside, 'secret.txt'), join(root, 'AGENTS.md'));
      else await symlink(join(outside, 'secret.txt'), join(root, 'AGENTS.md'));
      const trust = new TrustStore(join(home, 'trust'), randomBytes(32));
      const asked: string[] = [];
      const setup = await openInstructions({
        files,
        root,
        sandboxed: false,
        hnHome: home,
        window: 200_000,
        trust,
        approve: async (file) => {
          asked.push(file.display);
          return true;
        },
      });
      const frame = await setup.access?.chain.snapshot();
      assert.doesNotMatch(frame?.text ?? '', /do-not-load-me/);
      assert.match(frame?.text ?? '', /Not loaded \((link|hardlink)\): AGENTS\.md/);
      assert.deepEqual(asked, [], 'a refused file is never even offered for approval');
    });
  });

  it('loads an approved file, and leaves an unapproved one out when nobody is here to ask', async () => {
    await withTempDir(async (dir) => {
      const { root, home } = await project(dir);
      await writeFile(join(root, 'AGENTS.md'), 'Use pnpm, never npm.');
      const trust = new TrustStore(join(home, 'trust'), randomBytes(32));
      const unattended = await openInstructions({ files, root, sandboxed: false, hnHome: home, window: 200_000, trust });
      assert.match(unattended.notes.join('\n'), /not loaded until approved \(new\): AGENTS\.md/);
      assert.doesNotMatch((await unattended.access?.chain.snapshot())?.text ?? '', /never npm/);

      const attended = await openInstructions({
        files,
        root,
        sandboxed: false,
        hnHome: home,
        window: 200_000,
        trust,
        approve: async () => true,
      });
      assert.match((await attended.access?.chain.snapshot())?.text ?? '', /Use pnpm, never npm\./);
    });
  });

  it('loads nothing without the helper, and says why', async () => {
    const setup = await openInstructions({
      files: null,
      root: '.',
      sandboxed: false,
      hnHome: '.',
      window: 200_000,
      trust: new TrustStore('unused', randomBytes(32)),
    });
    assert.equal(setup.access, null);
    assert.match(setup.notes[0] ?? '', /helper is not available/);
  });
});
