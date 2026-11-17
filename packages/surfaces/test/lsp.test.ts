import assert from 'node:assert/strict';
import { access, mkdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { KeyStore } from '@hn/provider';
import type { ApprovalCard } from '@hn/security';
import { Harness } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const server = fileURLToPath(new URL('../../tools/test/fixtures/fake-lsp.mjs', import.meta.url));
const exists = (path: string): Promise<boolean> => access(path).then(() => true, () => false);
const toolResults = (request: { messages: readonly { role: string; content?: unknown }[] }): string[] =>
  request.messages.filter((message) => message.role === 'tool').map((message) => String(message.content));

// The toy server knows only open files, so the outline of math.js comes first and opens it. Column 16 is in `add`.
const STEPS = [
  { op: 'symbols', path: 'src/math.js' },
  { op: 'definition', path: 'src/app.js', line: 3, column: 16 },
  { op: 'references', path: 'src/app.js', line: 3, column: 16 },
  { op: 'hover', path: 'src/app.js', line: 3, column: 16 },
  { op: 'diagnostics', path: 'src/app.js' },
];

describe('the lsp tool in a session', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const results = toolResults(request);
      const step = STEPS[results.length];
      if (step !== undefined) return { calls: [{ id: `l${results.length}`, name: 'call_tool', args: { name: 'lsp', args: step } }] };
      if (results.length === STEPS.length) return { calls: [{ id: 'r1', name: 'read_file', args: { path: 'src/app.js' } }] };
      if (results.length === STEPS.length + 1) {
        return { calls: [{ id: 'w1', name: 'write_file', args: { path: 'src/app.js', content: "import { add } from './math.js';\n\nconst total = add(1, 2) + BROKEN;\n" } }] };
      }
      return { text: results.map((result, i) => `#${i} ${result}`).join('\n') };
    });
  });
  after(async () => {
    await model.close();
  });

  const project = async (top: string): Promise<{ root: string; home: string; marker: string }> => {
    const root = join(top, 'project');
    const home = join(top, '.home');
    await mkdir(join(root, 'src'), { recursive: true });
    await mkdir(home, { recursive: true });
    await writeFile(join(root, 'src', 'math.js'), 'export function add(a, b) {\n  return a + b;\n}\nexport function sub(a, b) {\n  return a - b;\n}\n');
    await writeFile(join(root, 'src', 'app.js'), "import { add } from './math.js';\n\nconst total = add(1, 2);\n");
    const marker = join(top, 'server-started.txt');
    await writeFile(join(home, 'lsp.json'), JSON.stringify({ servers: [{ name: 'fake', command: process.execPath, args: [server, marker], extensions: ['.js'] }] }));
    return { root, home, marker };
  };

  it('starts the server only after a person approves it, answers definition, references, hover, symbols and diagnostics, and reports errors after an edit', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const { root, home, marker } = await project(await realpath(dir));
      const cards: ApprovalCard[] = [];
      const harness = new Harness({ workdir: root, mode: 'safe', approver: async (card) => (cards.push(card), 'once'), model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: home } });
      try {
        const { text } = await harness.run('use the language server');
        const lspCards = cards.filter((card) => card.tool === 'harness:lsp');
        assert.equal(lspCards.length, 1, 'the server is started once, after one approval');
        assert.match(lspCards[0]?.summary ?? '', /fake-lsp\.mjs/);
        assert.ok(await exists(marker));
        assert.match(text, /#0 [\s\S]*add \(line 1\)\s+sub \(line 4\)/);
        assert.match(text, /#1 [^#]*src\/math\.js:1:\d+ {2}export function add\(a, b\) \{/);
        const references = /#2 ([^#]*)/.exec(text)?.[1] ?? '';
        for (const where of [/src\/app\.js:1:/, /src\/app\.js:3:/, /src\/math\.js:1:/]) assert.match(references, where);
        assert.match(text, /#3 [^#]*function add\(\): number/);
        assert.match(text, /#4 [^#]*No problems reported in src\/app\.js/);
        assert.match(text, /#6 [\s\S]*The language server reports errors after this change[\s\S]*3:\d+ error BROKEN is not defined/);
        assert.match(text, /<untrusted source="workspace" label="lsp definition">/);
      } finally {
        await harness.close();
      }
    });
  });

  it('never starts the server unattended below tier 3, because a language server runs project code', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const { root, home, marker } = await project(await realpath(dir));
      const harness = new Harness({ workdir: root, mode: 'dont-ask', allow: ['call_tool', 'lsp', 'write_file'], model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: home } });
      try {
        const { text } = await harness.run('use the language server');
        assert.match(text, /#0 .*was not started/s);
        assert.equal(await exists(marker), false, 'the server started with nobody there to approve it');
      } finally {
        await harness.close();
      }
    });
  });
});
