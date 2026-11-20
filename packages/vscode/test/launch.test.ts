import assert from 'node:assert/strict';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { withTempDir } from '@hn/testkit';
import { AcpClient } from '../src/acp-client.ts';
import { resolveLaunch } from '../src/launch.ts';

const agentScript = fileURLToPath(new URL('./fixtures/fake-agent.mjs', import.meta.url));
const none = { path: '', model: '', baseUrl: '' };

describe('how hn acp is started', () => {
  it('passes arguments as a list where there is no cmd.exe, and never through a shell', () => {
    const spec = resolveLaunch({ path: '/opt/my tools/hn', model: 'qwen3:14b', baseUrl: 'http://localhost:11434' }, '/work', {}, 'linux');
    assert.deepEqual(spec, { command: '/opt/my tools/hn', args: ['acp', '--model', 'qwen3:14b', '--base-url', 'http://localhost:11434'], cwd: '/work', env: {} });
    assert.equal(resolveLaunch(none, '/w', {}, 'darwin').command, 'hn');
  });

  it('puts a Windows shim on one cmd.exe line only when every value is plain, and refuses anything else', () => {
    const spec = resolveLaunch({ path: 'C:\\Users\\me\\AppData\\Roaming\\npm\\hn.cmd', model: 'qwen3:14b', baseUrl: '' }, 'C:\\w', { ComSpec: 'C:\\Windows\\System32\\cmd.exe' }, 'win32');
    assert.equal(spec.command, 'C:\\Windows\\System32\\cmd.exe');
    assert.deepEqual(spec.args, ['/d', '/s', '/c', '""C:\\Users\\me\\AppData\\Roaming\\npm\\hn.cmd" acp --model qwen3:14b"']);
    assert.equal(spec.verbatim, true);
    for (const model of ['x & calc', 'x"y', 'a b', 'x|y', '%PATH%', 'x\ny', 'a;b', '$(id)']) {
      assert.throws(() => resolveLaunch({ path: 'hn', model, baseUrl: '' }, 'C:\\w', {}, 'win32'), /cannot go on a Windows command line safely/, model);
    }
    assert.throws(() => resolveLaunch({ path: 'C:\\a"&calc&"\\hn.cmd', model: '', baseUrl: '' }, 'C:\\w', {}, 'win32'), /hn\.path/);
    // A real .exe needs no cmd.exe, so nothing is parsed.
    assert.deepEqual(resolveLaunch({ path: 'C:\\Program Files\\hn\\hn.exe', model: 'a b', baseUrl: '' }, 'C:\\w', {}, 'win32').args, ['acp', '--model', 'a b']);
  });

  it('really starts a .cmd shim in a folder with a space in its path', { skip: process.platform === 'win32' ? false : 'Windows only' }, async () => {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const folder = join(top, 'my tools');
      await mkdir(folder);
      const shim = join(folder, 'hn.cmd');
      // The shim stands in for npm's: it runs node on a script and passes its arguments on.
      await writeFile(shim, `@echo off\r\n"${process.execPath}" "${agentScript}" hostile\r\n`);
      const events: string[] = [];
      const client = await AcpClient.start(resolveLaunch({ path: shim, model: 'qwen3:14b', baseUrl: '' }, top, process.env), {
        event: (event) => void events.push(event.type),
        approve: async () => 'reject',
        exited: () => undefined,
      });
      try {
        const { sessionId } = await client.newSession(top);
        assert.match(sessionId, /^s1$/);
      } finally {
        await client.close();
      }
    });
  });
});
