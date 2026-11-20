import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { ATTACKS, withTempDir } from '@hn/testkit';
import { expectedHallOfFame, renderHallOfFame, validateCredits, type Credit } from '../../../scripts/hall-of-fame.ts';

const run = promisify(execFile);
const REAL = fileURLToPath(new URL('../../../', import.meta.url));
const script = join(REAL, 'scripts', 'hall-of-fame.ts');

const ATTACK = ATTACKS[0]?.name ?? '';
const good: Credit = {
  handle: 'octo-reporter',
  reported: '2026-03-01',
  fixed: '2026-03-20',
  severity: 'high',
  summary: 'A symlink swapped in during a read let the tool read outside the project.',
  fix: 'a'.repeat(40),
  attack: ATTACK,
  consent: true,
};
const check = (credit: unknown, today = '2026-12-01'): string[] => validateCredits({ credits: [credit] }, { today });
const withChange = (change: Record<string, unknown>): Record<string, unknown> => ({ ...good, ...change });

describe('the hall of fame data', () => {
  it('accepts a complete entry, and an empty list', () => {
    assert.deepEqual(check(good), []);
    assert.deepEqual(validateCredits({ credits: [] }), []);
  });

  it('refuses anyone who did not consent, however the field is written', () => {
    for (const consent of [false, 'true', 1, undefined, null]) assert.match(check(withChange({ consent })).join('\n'), /consent must be true/);
  });

  it('refuses a contact detail: an email field, an email in a name or a summary', () => {
    assert.match(check(withChange({ email: 'a@b.example' })).join('\n'), /"email" is not a field/);
    assert.match(check(withChange({ name: 'Ada a@b.example' })).join('\n'), /name must be/);
    assert.match(check(withChange({ summary: 'Reported by someone at a@b.example, who found a hole in the gate.' })).join('\n'), /email address/);
  });

  it('refuses markup, links and hidden characters in a name or a summary, so a credit cannot change how the page reads', () => {
    for (const name of ['<b>x</b>', 'x [y](http://z)', 'x‮evil', 'x\nnew row', 'x | y', 'see https://evil.example', 'x'.repeat(61)]) assert.match(check(withChange({ name })).join('\n'), /name must be/, JSON.stringify(name));
    for (const summary of ['A <script>alert(1)</script> hole in the gate that was found.', 'A hole [here](http://evil.example) was found in the gate.', 'A hole that was found has a very long tail. '.repeat(10), 'short']) {
      assert.match(check(withChange({ summary })).join('\n'), /summary must be/, summary.slice(0, 30));
    }
  });

  it('needs a GitHub login, a real name or both, and refuses a login that is not one', () => {
    const { handle: _handle, ...without } = good;
    assert.match(check(without).join('\n'), /needs a handle or a name/);
    assert.deepEqual(check({ ...without, name: 'Ada Lovelace' }), []);
    for (const handle of ['-start', 'end-', 'has space', 'a/b', 'x'.repeat(40), '']) assert.match(check(withChange({ handle })).join('\n'), /handle must be a GitHub login/, handle);
  });

  it('refuses a made-up date, a fix before the report, and a fix in the future', () => {
    assert.match(check(withChange({ reported: '2026-02-30' })).join('\n'), /reported must be a real date/);
    assert.match(check(withChange({ fixed: '03/20/2026' })).join('\n'), /fixed must be a real date/);
    assert.match(check(withChange({ fixed: '2026-02-01' })).join('\n'), /fixed is before reported/);
    assert.match(check(good, '2026-03-10').join('\n'), /fixed is in the future/);
  });

  it('refuses a fix that is not a full commit, and the same commit credited twice', () => {
    assert.match(check(withChange({ fix: 'abc1234' })).join('\n'), /full 40-character commit/);
    assert.match(validateCredits({ credits: [good, { ...good, handle: 'someone-else' }] }, { today: '2026-12-01' }).join('\n'), /already credited/);
  });

  it('refuses an entry that names no attack in the registry, so a credited hole always leaves a test behind', () => {
    assert.match(check(withChange({ attack: 'not_in_the_registry' })).join('\n'), /attack must name an attack in the registry/);
    assert.match(check(withChange({ attack: undefined })).join('\n'), /attack must name an attack in the registry/);
  });

  it('refuses an unknown severity and an advisory that is not a GitHub advisory address', () => {
    assert.match(check(withChange({ severity: 'catastrophic' })).join('\n'), /severity must be one of/);
    assert.match(check(withChange({ advisory: 'https://evil.example/x' })).join('\n'), /advisory must be a GitHub security advisory/);
    assert.deepEqual(check(withChange({ advisory: 'https://github.com/AkbarSheikh-debug/Haven-Harness/security/advisories/GHSA-abcd-1234-wxyz' })), []);
  });

  it('refuses a file that is not the right shape', () => {
    for (const data of [null, [], 'x', { credits: 'x' }, { credits: [], extra: 1 }, { credits: [5] }]) assert.ok(validateCredits(data).length > 0, JSON.stringify(data));
  });
});

describe('the hall of fame page', () => {
  it('says plainly that it is empty when it is, and invents nobody', () => {
    const page = renderHallOfFame([]);
    assert.match(page, /No report has been credited yet/);
    assert.doesNotMatch(page, /\| Who \|/);
  });

  it('shows each credit with who, when, how bad, what it was, the fix, and the test, newest fix first, with a pipe in a name kept in its cell', () => {
    const older: Credit = { ...good, handle: 'older', fixed: '2026-02-01', reported: '2026-01-01', fix: 'b'.repeat(40) };
    const page = renderHallOfFame([older, { ...good, name: 'Ada Lovelace' }]);
    assert.ok(page.indexOf('Ada Lovelace') < page.indexOf('[older]'), 'the newest fix is not first');
    assert.match(page, /\| Ada Lovelace \(\[octo-reporter\]\(https:\/\/github\.com\/octo-reporter\)\) \| 2026-03-20 \| high \| A symlink swapped/);
    assert.match(page, new RegExp(`\\(fix \\[aaaaaaa\\]\\(https://github\\.com/AkbarSheikh-debug/Haven-Harness/commit/${'a'.repeat(40)}\\)\\)`));
    assert.match(page, new RegExp(`\\| \`${ATTACK}\` \\|`));
  });

  it('is what the data says: the committed page is exactly what the script writes, and the committed data is valid', async () => {
    const { page, errors } = expectedHallOfFame();
    assert.deepEqual(errors, []);
    assert.equal((await readFile(join(REAL, 'docs', 'guide', 'hall-of-fame.md'), 'utf8')).replace(/\r\n/g, '\n'), page, 'docs/guide/hall-of-fame.md is stale. Run: node --disable-proto=throw scripts/hall-of-fame.ts');
  });

  it('has public wording only', async () => {
    const page = await readFile(join(REAL, 'docs', 'guide', 'hall-of-fame.md'), 'utf8');
    assert.doesNotMatch(page, /\bphase \d|\bdecision \d|master plan|section \d+\.\d|\binvariant \d/i);
  });

  it('the command refuses invalid data and says why, writes nothing, and --check fails on a stale page', async () => {
    await withTempDir(async (dir) => {
      const data = join(dir, 'credits.json');
      const page = join(dir, 'page.md');
      await writeFile(page, 'untouched');
      await writeFile(data, JSON.stringify({ credits: [{ ...good, consent: false }] }));
      await assert.rejects(run(process.execPath, ['--disable-proto=throw', script, '--data', data, '--page', page]), (error: { stderr: string }) => /consent must be true/.test(error.stderr));
      assert.equal(await readFile(page, 'utf8'), 'untouched');
      await writeFile(data, JSON.stringify({ credits: [good] }));
      await assert.rejects(run(process.execPath, ['--disable-proto=throw', script, '--check', '--data', data, '--page', page]), (error: { stderr: string }) => /not what docs\/security\/credits\.json says/.test(error.stderr));
      await run(process.execPath, ['--disable-proto=throw', script, '--data', data, '--page', page]);
      await run(process.execPath, ['--disable-proto=throw', script, '--check', '--data', data, '--page', page]);
      assert.match(await readFile(page, 'utf8'), /octo-reporter/);
    });
  });

  it('the command passes --check on the committed data and page', async () => {
    const real = await run(process.execPath, ['--disable-proto=throw', script, '--check']);
    assert.match(real.stdout, /hall of fame is current/);
  });
});
