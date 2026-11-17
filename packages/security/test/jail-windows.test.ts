import assert from 'node:assert/strict';
import { mkdir, realpath, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { withTempDir } from '@hn/testkit';
import { Jail, JailError, isSecretPath } from '@hn/security';

const windowsJail = (root = 'D:\\repo'): Jail => new Jail({ root, platform: 'win32', realpath: async (path) => path });

describe('the jail on Windows paths', () => {
  const rejected: [string, RegExp][] = [
    ['.env::$DATA', /alternate data streams/],
    ['.env:stream', /alternate data streams/],
    ['dir\\file.txt::$INDEX_ALLOCATION', /alternate data streams/],
    ['name.', /dot or space/],
    ['name ', /dot or space/],
    ['dir.\\file', /dot or space/],
    ['CON', /reserved/],
    ['nul.txt', /reserved/],
    ['sub\\COM1', /reserved/],
    ['LPT9.log', /reserved/],
    ['COM\u00b9', /reserved/],
    ['CONIN$', /reserved/],
    ['conout$', /reserved/],
    ['\\\\server\\share\\x', /network and device/],
    ['\\\\?\\D:\\repo\\x', /network and device/],
    ['\\\\.\\PhysicalDrive0', /network and device/],
    ['//server/share', /network and device/],
    ['ENV~1', /8\.3/],
    ['PROGRA~1\\x', /8\.3/],
    ['sub\\SECRET~2.TXT', /8\.3/],
    ['D:foo.txt', /drive-relative/],
    ['C:..\\x', /drive-relative/],
    ['..\\outside.txt', /outside the project/],
    ['sub\\..\\..\\outside.txt', /outside the project/],
    ['D:\\repo\\..\\other\\x', /outside the project/],
    ['C:\\Windows\\win.ini', /outside the project/],
  ];
  for (const [input, message] of rejected) {
    it(`rejects ${JSON.stringify(input)}`, async () => {
      await assert.rejects(windowsJail().resolve(input), (error: Error) => error instanceof JailError && message.test(error.message));
    });
  }

  it('accepts ordinary names, mixed separators and drive-letter case', async () => {
    assert.equal(await windowsJail().resolve('src/index.ts'), 'D:\\repo\\src\\index.ts');
    assert.equal(await windowsJail().resolve('d:/REPO/Src\\a.ts'), 'D:\\REPO\\Src\\a.ts');
    assert.equal(await windowsJail('d:\\repo').resolve('x.txt'), 'D:\\repo\\x.txt');
    assert.equal(await windowsJail().resolve('~tilde-start.txt'), 'D:\\repo\\~tilde-start.txt');
    assert.equal(await windowsJail().resolve('my~file-long-name.txt'), 'D:\\repo\\my~file-long-name.txt');
  });

  it('does not let a trailing-dot or case variant of a secret name through the secret rule', () => {
    for (const path of ['.ENV', '.env.', '.env ', '.Env\\', 'sub\\.env::$DATA', 'C:\\Users\\x\\.SSH\\id_rsa', '.AWS/credentials']) {
      assert.equal(isSecretPath(path), true, path);
    }
  });
});

describe('the jail against real links on this machine', { skip: process.platform !== 'win32' }, () => {
  it('attack: a junction pointing outside the project is refused', async () => {
    await withTempDir(async (dir) => {
      const root = join(await realpath(dir), 'project');
      const outside = join(await realpath(dir), 'outside');
      await mkdir(root);
      await mkdir(outside);
      await writeFile(join(outside, 'secret.txt'), 'x');
      await symlink(outside, join(root, 'link'), 'junction');
      const jail = new Jail({ root, realpath: (path) => realpath(path) });
      await assert.rejects(jail.resolve('link\\secret.txt'), JailError);
      await assert.rejects(jail.resolve('link\\new-file.txt'), JailError);
      assert.equal(await jail.resolve('ok.txt'), join(root, 'ok.txt'));
    });
  });
});
