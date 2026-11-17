import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { loadMcpConfig } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

const abs = process.platform === 'win32' ? 'C:/tools/server.exe' : '/usr/bin/server';
const write = async (dir: string, value: unknown): Promise<string> => {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'mcp.json'), typeof value === 'string' ? value : JSON.stringify(value));
  return dir;
};

describe('the user-level MCP configuration', () => {
  it('means no servers when the file is missing', async () => {
    await withTempDir(async (dir) => assert.deepEqual(await loadMcpConfig(dir), []));
  });

  it('reads a well-formed file', async () => {
    await withTempDir(async (dir) => {
      await write(dir, { servers: [{ name: 'docs', command: abs, args: ['--stdio'], env: { TOKEN_FILE: 'x' }, version: '1.2.3', effects: { search: 'external' } }, { name: 'plain', command: abs, version: '0.1.0' }] });
      const servers = await loadMcpConfig(dir);
      assert.deepEqual(servers.map((server) => [server.name, server.version]), [['docs', '1.2.3'], ['plain', '0.1.0']]);
      assert.deepEqual(servers[0]?.process.args, ['--stdio']);
      assert.equal(servers[0]?.effects?.['search'], 'external');
      assert.equal(servers[1]?.effects, undefined);
    });
  });

  it('refuses anything odd rather than ignoring it', async () => {
    await withTempDir(async (dir) => {
      const cases: [unknown, RegExp][] = [
        ['not json', /not valid JSON/],
        [{ servers: 'x' }, /expected/],
        [{ servers: [], extra: 1 }, /expected/],
        [[], /expected/],
        [{ servers: [{ name: 'a', command: abs, version: '1', mystery: true }] }, /unknown field "mystery"/],
        [{ servers: [{ name: 'A B', command: abs, version: '1' }] }, /name must be/],
        [{ servers: [{ name: 'a', command: 'node', version: '1' }] }, /absolute path/],
        [{ servers: [{ name: 'a', command: abs }] }, /version is required/],
        [{ servers: [{ name: 'a', command: abs, version: '1', args: [1] }] }, /args must be a list of strings/],
        [{ servers: [{ name: 'a', command: abs, version: '1', env: { K: 1 } }] }, /env\.K must be a string/],
        [{ servers: [{ name: 'a', command: abs, version: '1', effects: { t: 'harmless' } }] }, /effects\.t must be one of/],
        [{ servers: [{ name: 'a', command: abs, version: '1' }, { name: 'a', command: abs, version: '1' }] }, /used twice/],
        [{ servers: Array.from({ length: 21 }, (_, i) => ({ name: `s${i}`, command: abs, version: '1' })) }, /more than 20/],
        ['{"servers":[{"name":"a","command":"/x","version":"1","__proto__":{"polluted":true}}]}', /unknown field "__proto__"/],
        ['x'.repeat(70_000), /larger than/],
      ];
      for (const [value, message] of cases) {
        await write(dir, value);
        await assert.rejects(loadMcpConfig(dir), (error: Error) => message.test(error.message), JSON.stringify(value).slice(0, 60));
      }
      assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
    });
  });
});
