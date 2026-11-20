import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { withTempDir } from '@hn/testkit';

const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));

describe('hn -p --prompt-origin', () => {
  it('can only lower trust: any value but "event" is refused before a session starts', async () => {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      for (const origin of ['user', 'harness', 'human-selected', 'EVENT', '']) {
        const ran = spawnSync(process.execPath, [launcher, '-p', 'hello', '--prompt-origin', origin, '--model', 'fake', '--base-url', 'http://127.0.0.1:9'], { cwd: top, env: { ...process.env, HN_HOME: join(top, 'home') }, encoding: 'utf8' });
        assert.notEqual(ran.status, 0, `--prompt-origin "${origin}" was accepted`);
        assert.match(`${ran.stdout}${ran.stderr}`, /can only be "event"/, origin);
      }
    });
  });
});
