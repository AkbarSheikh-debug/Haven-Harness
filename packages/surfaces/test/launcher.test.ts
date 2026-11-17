import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));
const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

describe('launcher', () => {
  it('starts hn with __proto__ disabled', () => {
    const run = spawnSync(process.execPath, [launcher, '--version'], { encoding: 'utf8' });
    assert.equal(run.status, 0);
    assert.equal(run.stdout, 'hn from source\n');
  });

  it('refuses to run without the launcher', () => {
    const run = spawnSync(process.execPath, ['--no-warnings', main, '--version'], { encoding: 'utf8' });
    assert.equal(run.status, 2);
    assert.match(run.stderr, /launcher/);
  });
});
