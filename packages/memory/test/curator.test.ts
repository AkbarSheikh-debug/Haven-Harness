import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, utimes, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { withTempDir } from '@hn/testkit';
import { CURATOR, recordSkillUse, restoreArchived, runCurator } from '@hn/memory';

const T0 = new Date('2026-11-01T12:00:00Z');
const days = (n: number) => new Date(T0.getTime() + n * 86_400_000);

async function skill(root: string, name: string, extra = 'created_by: agent'): Promise<void> {
  await mkdir(join(root, name), { recursive: true });
  const path = join(root, name, 'SKILL.md');
  await writeFile(path, `---\nname: ${name}\ndescription: test\n${extra}\n---\nbody\n`);
  await utimes(path, T0, T0);
}

const folders = async (path: string) => (await readdir(path, { withFileTypes: true }).catch(() => [])).filter((e) => e.isDirectory()).map((e) => e.name).sort();

describe('the curator', () => {
  it('marks an unused agent skill stale at 30 days and archives it at 90, never deleting it, and restore brings it back', async () => {
    await withTempDir(async (root) => {
      await skill(root, 'old-trick');
      await skill(root, 'used-trick');
      await recordSkillUse(root, 'used-trick', days(85));
      const first = await runCurator({ root, now: days(31), lastActivity: null });
      assert.deepEqual([first.ran, first.stale, first.archived], [true, ['old-trick'], []]);
      const usage = JSON.parse(await readFile(join(root, '.usage.json'), 'utf8')) as { skills: Record<string, { state: string }> };
      assert.equal(usage.skills['old-trick']?.state, 'stale');
      const later = await runCurator({ root, now: days(91), lastActivity: null });
      assert.deepEqual(later.archived, ['old-trick'], 'the skill used on day 85 stays');
      assert.deepEqual(await folders(root), ['.archive', 'used-trick']);
      assert.deepEqual(await folders(join(root, '.archive')), ['old-trick'], 'archived, not deleted');
      await restoreArchived(root, 'old-trick', days(92));
      assert.deepEqual(await folders(root), ['.archive', 'old-trick', 'used-trick']);
    });
  });

  it('never moves a user-written, pinned or locked skill', async () => {
    await withTempDir(async (root) => {
      await skill(root, 'mine', '');
      await skill(root, 'pinned-one', 'created_by: agent\npinned: true');
      await skill(root, 'locked-one', 'created_by: agent\nlocked: true');
      const report = await runCurator({ root, now: days(400), lastActivity: null });
      assert.deepEqual([report.stale, report.archived], [[], []]);
      assert.deepEqual(await folders(root), ['locked-one', 'mine', 'pinned-one']);
    });
  });

  it('runs only after two idle hours, and at most once a week', async () => {
    await withTempDir(async (root) => {
      await skill(root, 'old-trick');
      const busy = await runCurator({ root, now: days(100), lastActivity: new Date(days(100).getTime() - 3_600_000) });
      assert.deepEqual([busy.ran, busy.why], [false, 'not idle for two hours']);
      assert.equal((await runCurator({ root, now: days(100), lastActivity: days(99) })).ran, true);
      await skill(root, 'another');
      const again = await runCurator({ root, now: new Date(days(100).getTime() + (CURATOR.intervalHours - 1) * 3_600_000), lastActivity: null });
      assert.deepEqual([again.ran, again.why], [false, 'ran less than a week ago']);
    });
  });
});
