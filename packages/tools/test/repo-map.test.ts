import assert from 'node:assert/strict';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { localOperations } from '@hn/operations';
import { fileSymbols, type FileSymbols } from '@hn/security';
import { createRepoMapTool, rankFiles, renderMap } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

const toolsRoot = fileURLToPath(new URL('../', import.meta.url));
const context = (workdir: string) => ({ workdir, ops: localOperations(join(workdir, '..', 'spill')), signal: new AbortController().signal, callId: 'c' });
const defs = (names: string[]): FileSymbols['defs'] => names.map((name, i) => ({ name, kind: 'function', line: i + 1 }));

describe('the repo map', () => {
  it('finds definitions and uses with the real grammars', async () => {
    const ts = await fileSymbols('a.ts', 'export class Store { get(k: string) { return k; } }\ninterface Shape { x: number }\nexport function load(s: Store) { return helper(s); }\nconst helper = (s: Store) => s;\ntype Id = string;\n');
    assert.ok(ts !== null);
    assert.deepEqual(ts.defs.map((def) => `${def.kind} ${def.name}`), ['class Store', 'method get', 'interface Shape', 'function load', 'function helper', 'type Id']);
    assert.equal(ts.refs.get('Store'), 3);
    const py = await fileSymbols('b.py', 'class Cart:\n    def total(self):\n        return 1\n\ndef checkout(cart):\n    return cart.total()\n');
    assert.deepEqual(py?.defs.map((def) => def.name), ['Cart', 'total', 'checkout']);
    assert.equal(await fileSymbols('notes.txt', 'class X {}'), null, 'no grammar, no symbols');
  });

  it('ranks the file everyone depends on first, and a mentioned file rises above it', () => {
    const symbols = new Map<string, FileSymbols>([
      ['core.ts', { defs: defs(['Store', 'Query']), refs: new Map() }],
      ['a.ts', { defs: defs(['pageA']), refs: new Map([['Store', 3], ['Query', 1]]) }],
      ['b.ts', { defs: defs(['pageB']), refs: new Map([['Store', 2]]) }],
      ['c.ts', { defs: defs(['pageC']), refs: new Map([['Query', 1], ['pageB', 1]]) }],
      ['lonely.ts', { defs: defs(['island']), refs: new Map() }],
    ]);
    const plain = [...rankFiles({ symbols, personal: new Map() }).entries()].sort((x, y) => y[1] - x[1]).map(([file]) => file);
    assert.equal(plain[0], 'core.ts');
    const total = [...rankFiles({ symbols, personal: new Map() }).values()].reduce((sum, value) => sum + value, 0);
    assert.ok(Math.abs(total - 1) < 1e-9, `rank is conserved, got ${total}`);
    const anchored = [...rankFiles({ symbols, personal: new Map([['lonely.ts', 10]]) }).entries()].sort((x, y) => y[1] - x[1]).map(([file]) => file);
    assert.equal(anchored[0], 'lonely.ts');
  });

  it('keeps to its budget and says how much it left out', () => {
    const symbols = new Map<string, FileSymbols>();
    for (let i = 0; i < 200; i += 1) symbols.set(`src/file${String(i).padStart(3, '0')}.ts`, { defs: defs([`fn${i}a`, `fn${i}b`, `fn${i}c`]), refs: new Map() });
    const text = renderMap(symbols, rankFiles({ symbols, personal: new Map() }), 200, []);
    assert.ok(text.length <= 200 * 4 + 120, `the map is ${text.length} characters`);
    assert.match(text, /more files not shown/);
  });

  it('maps a real project folder, never reading secrets or .git, and comes back as wrapped project data', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = join(await realpath(dir), 'project');
      await mkdir(join(root, 'src'), { recursive: true });
      await mkdir(join(root, '.git'), { recursive: true });
      await writeFile(join(root, 'src', 'db.ts'), 'export class Database { query() { return 1; } }\n');
      await writeFile(join(root, 'src', 'users.ts'), "import { Database } from './db';\nexport function listUsers(db: Database) { return db.query(); }\n");
      await writeFile(join(root, 'src', 'orders.ts'), "import { Database } from './db';\nexport function listOrders(db: Database) { return db.query(); }\n");
      await writeFile(join(root, '.env'), 'API_KEY=sk-live-supersecret\n');
      await writeFile(join(root, '.git', 'hooks.ts'), 'export function hiddenInGit() {}\n');
      const result = await createRepoMapTool().execute({}, context(root));
      assert.equal(result.origin, 'workspace');
      assert.match(result.content, /^<untrusted source="workspace" label="repo map">/);
      assert.ok(result.content.indexOf('src/db.ts') < result.content.indexOf('src/users.ts'), 'the shared file is not first');
      assert.match(result.content, /class Database \(1\)/);
      assert.doesNotMatch(result.content, /supersecret|hiddenInGit/);
      const focused = await createRepoMapTool().execute({ focus: ['listOrders'] }, context(root));
      assert.ok(focused.content.indexOf('src/orders.ts') < focused.content.indexOf('src/db.ts'), 'naming a symbol did not rank its file first');
      const byPath = await createRepoMapTool().execute({ focus: ['./src/users.ts'] }, context(root));
      // Positions of the file lines themselves: the header names the anchor too.
      const files = [...byPath.content.matchAll(/^(src\/\w+\.ts)$/gm)].map((match) => match[1]);
      assert.equal(files[0], 'src/users.ts', `naming a file did not rank it first: ${files.join(', ')}`);
    });
  });

  it('ranks this repository: the tools package puts its shared types first', { timeout: 60_000 }, async () => {
    const result = await createRepoMapTool().execute({ max_tokens: 400 }, context(join(toolsRoot, 'src')));
    const files = [...result.content.matchAll(/^([\w./-]+\.ts)$/gm)].map((match) => match[1]);
    assert.ok(files.length >= 3, result.content);
    assert.equal(files[0], 'types.ts', `ranked first: ${files.slice(0, 5).join(', ')}`);
  });
});
