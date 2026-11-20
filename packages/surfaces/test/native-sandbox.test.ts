import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { detectLinuxSupport, findHelper } from '@hn/operations';
import { KeyStore } from '@hn/provider';
import { Harness } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const toolResults = (request: { messages: readonly { role: string; content?: unknown }[] }): string[] =>
  request.messages.filter((message) => message.role === 'tool').map((message) => String(message.content));

describe('a session in the Windows native box', { skip: process.platform === 'win32' ? false : 'Windows only' }, () => {
  let model: FakeOpenAI;
  let secret = '';
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const results = toolResults(request);
      if (results.length === 0) {
        return { calls: [{ id: 'b1', name: 'bash', args: { command: `Set-Content -Path made.txt -Value 'from the box'; Get-Content made.txt; Get-Content -LiteralPath '${secret}'` } }] };
      }
      return { text: `saw: ${results[0]}` };
    });
  });
  after(async () => {
    await model.close();
  });

  it('runs the bash tool in the box at tier 3, in yolo, keeps the host file out of reach, and brings the change back at close', { timeout: 180_000 }, async () => {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const project = join(top, 'project');
      const outside = join(top, 'outside');
      await mkdir(project);
      await mkdir(outside);
      await writeFile(join(project, 'a.txt'), 'a\n');
      secret = join(outside, 'secret.txt');
      await writeFile(secret, 'HOST-ONLY-SECRET\n');
      const harness = new Harness({ workdir: project, mode: 'yolo', sandbox: { kind: 'native' }, model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: join(top, '.home') } });
      try {
        const result = await harness.run('make a file');
        assert.match(result.text, /from the box/);
        assert.doesNotMatch(result.text, /HOST-ONLY-SECRET/);
        const state = await harness.state();
        assert.equal(state.tier, 3);
        assert.equal(state.mode, 'yolo');
        // Found in the live bench: told nothing, a model writes bash in a PowerShell box and every command fails.
        const bash = (model.requests[0]?.tools ?? []).find((tool) => tool.function?.name === 'bash') as { function?: { description?: string } } | undefined;
        assert.match(bash?.function?.description ?? '', /Windows PowerShell 5\.1, in the Windows box: not bash/);
        // Until the session ends, the change lives only in the box's copy.
        assert.deepEqual((await readdir(project)).sort(), ['a.txt']);
      } finally {
        await harness.close();
      }
      assert.equal((await readFile(join(project, 'made.txt'), 'utf8')).trim(), 'from the box');
    });
  });
});

const posix = process.platform === 'linux' || process.platform === 'darwin';
const required = process.env['HN_REQUIRE_BOX'] === '1';
let posixWhyNot: string | null = null;
if (process.platform === 'linux') {
  const helper = await findHelper({ env: {}, repoRoot: fileURLToPath(new URL('../../../', import.meta.url)) });
  const support = await detectLinuxSupport(helper === null ? {} : { helper });
  posixWhyNot = helper === null ? 'hn-sandbox is not built (pnpm build:sandbox)' : support.namespaces ? null : (support.namespaceProblem ?? 'bubblewrap cannot start a box here');
}

describe('a session in the Linux or macOS native box', { skip: !posix ? 'Linux and macOS only' : posixWhyNot === null || required ? false : `not available: ${posixWhyNot}` }, () => {
  let model: FakeOpenAI;
  let secret = '';
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const results = toolResults(request);
      if (results.length === 0) {
        return { calls: [{ id: 'b1', name: 'bash', args: { command: `echo 'from the box' > made.txt; cat made.txt; cat '${secret}'; echo "key=[$ANTHROPIC_API_KEY]"` } }] };
      }
      return { text: `saw: ${results[0]}` };
    });
  });
  after(async () => {
    await model.close();
  });

  it('runs the bash tool in the box at tier 3, in yolo, names its layers, keeps the host file and the key out of reach, and brings the change back at close', { timeout: 180_000 }, async () => {
    if (posixWhyNot !== null) assert.fail(posixWhyNot);
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const project = join(top, 'project');
      const outside = join(top, 'outside');
      await mkdir(project);
      await mkdir(outside);
      await writeFile(join(project, 'a.txt'), 'a\n');
      secret = join(outside, 'secret.txt');
      await writeFile(secret, 'HOST-ONLY-SECRET\n');
      process.env['ANTHROPIC_API_KEY'] = 'sk-ant-must-not-reach-the-box';
      const harness = new Harness({ workdir: project, mode: 'yolo', sandbox: { kind: 'native' }, model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: join(top, '.home') } });
      try {
        const result = await harness.run('make a file');
        assert.match(result.text, /from the box/);
        assert.doesNotMatch(result.text, /HOST-ONLY-SECRET/);
        assert.doesNotMatch(result.text, /sk-ant-must-not-reach-the-box/);
        assert.match(result.text, /key=\[\]/);
        const state = await harness.state();
        assert.equal(state.tier, 3);
        assert.equal(state.mode, 'yolo');
        // The box has bash, so the model is told nothing about another shell.
        const bash = (model.requests[0]?.tools ?? []).find((tool) => tool.function?.name === 'bash') as { function?: { description?: string } } | undefined;
        assert.doesNotMatch(bash?.function?.description ?? '', /PowerShell/);
        // Until the session ends, the change lives only in the box's copy.
        assert.deepEqual((await readdir(project)).sort(), ['a.txt']);
      } finally {
        delete process.env['ANTHROPIC_API_KEY'];
        await harness.close();
      }
      assert.equal((await readFile(join(project, 'made.txt'), 'utf8')).trim(), 'from the box');
    });
  });

  it('refuses a box whose canary cannot run: nothing was verified, so no session opens and no file of the project is touched', { timeout: 180_000 }, async () => {
    if (posixWhyNot !== null) assert.fail(posixWhyNot);
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const project = join(top, 'project');
      await mkdir(project);
      await writeFile(join(project, 'a.txt'), 'a\n');
      const real = process.execPath;
      // The interpreter that runs the canary is cat, which prints its input and proves nothing.
      Object.defineProperty(process, 'execPath', { value: '/bin/cat', configurable: true, writable: true });
      try {
        const harness = new Harness({ workdir: project, mode: 'yolo', sandbox: { kind: 'native' }, model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: join(top, '.home') } });
        try {
          await assert.rejects(harness.run('make a file'), /did not pass the outside-in check/);
        } finally {
          await harness.close().catch(() => undefined);
        }
      } finally {
        Object.defineProperty(process, 'execPath', { value: real, configurable: true, writable: true });
      }
      assert.deepEqual(await readdir(project), ['a.txt']);
    });
  });
});
