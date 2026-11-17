import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { resolvePaths } from '@hn/config';
import { ContainerBox, dockerIsUp, findDocker } from '@hn/operations';
import { AuditChain, openAuditFile } from '@hn/security';
import { loadOrCreateLogKey } from '@hn/session';
import { doctorExitCode, formatDoctor, runDoctor, type Check } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));

const byName = (checks: readonly Check[], name: string): Check => {
  const found = checks.find((check) => check.name === name);
  assert.ok(found, `no check named ${name}: ${checks.map((check) => check.name).join(', ')}`);
  return found;
};

const homeIn = async (dir: string): Promise<{ env: NodeJS.ProcessEnv; home: string; keyPath: string }> => {
  const home = join(dir, 'hn-home');
  await mkdir(home, { recursive: true });
  const env = { ...process.env, HN_HOME: home };
  return { env, home, keyPath: resolvePaths(env).logKey };
};

describe('hn doctor on a healthy machine', () => {
  it('reports every protection, and nothing that fails', async () => {
    await withTempDir(async (dir) => {
      const { env } = await homeIn(dir);
      const checks = await runDoctor({ repoRoot, env });
      for (const name of ['node', '__proto__ disabled', 'hn-sandbox helper', 'OS keychain', 'bash parser', 'syntax grammars', 'shell', 'ripgrep', 'log key', 'mcp.json', 'policy.json', 'external sandbox']) byName(checks, name);
      assert.deepEqual(checks.filter((check) => check.status === 'fail'), []);
      assert.equal(doctorExitCode(checks), 0);
      assert.match(byName(checks, 'hn-sandbox helper').detail, /a path outside the root is refused/);
    });
  });
});

describe('hn doctor finds what is broken', () => {
  it('fails when the helper is missing, and says how to build it', async () => {
    await withTempDir(async (dir) => {
      const { env } = await homeIn(dir);
      const checks = await runDoctor({ repoRoot: join(dir, 'nowhere'), env: { ...env, HN_SANDBOX_BIN: join(dir, 'missing') } });
      const helper = byName(checks, 'hn-sandbox helper');
      assert.equal(helper.status, 'fail');
      assert.match(helper.detail, /pnpm build:sandbox/);
      assert.equal(doctorExitCode(checks), 1);
    });
  });

  it('fails on a trust store that does not pass its integrity check', async () => {
    await withTempDir(async (dir) => {
      const { env, home, keyPath } = await homeIn(dir);
      await loadOrCreateLogKey(keyPath);
      await writeFile(join(home, 'trust'), JSON.stringify({ version: 1, entries: { '/repo/AGENTS.md': 'a'.repeat(64) }, mac: 'b'.repeat(64) }));
      const trust = byName(await runDoctor({ repoRoot, env }), 'trust store');
      assert.equal(trust.status, 'fail');
      assert.match(trust.detail, /integrity check/);
    });
  });

  it('fails on an audit chain that was edited, and names the file and the row', async () => {
    await withTempDir(async (dir) => {
      const { env, home, keyPath } = await homeIn(dir);
      const key = await loadOrCreateLogKey(keyPath);
      const file = await openAuditFile(join(home, 'audit', 'session-1.jsonl'), key);
      await file.record('audit/decision', { callId: 'c1', decision: 'rejected' });
      await file.record('audit/decision', { callId: 'c2', decision: 'rejected' });
      assert.equal(byName(await runDoctor({ repoRoot, env }), 'audit chains').status, 'ok');
      const path = join(home, 'audit', 'session-1.jsonl');
      await writeFile(path, (await readFile(path, 'utf8')).replace('"rejected"', '"allowed-once"'));
      const audit = byName(await runDoctor({ repoRoot, env }), 'audit chains');
      assert.equal(audit.status, 'fail');
      assert.match(audit.detail, /session-1\.jsonl/);
      assert.match(audit.detail, /Row 1 was changed after it was written/);
      assert.ok(AuditChain);
    });
  });

  it('fails on a configuration file that is wrong, rather than passing over it', async () => {
    await withTempDir(async (dir) => {
      const { env, home } = await homeIn(dir);
      await writeFile(join(home, 'mcp.json'), JSON.stringify({ servers: [{ name: 'x', command: 'node', version: '1' }] }));
      await writeFile(join(home, 'policy.json'), JSON.stringify({ version: 1, toolz: {} }));
      const checks = await runDoctor({ repoRoot, env });
      assert.equal(byName(checks, 'mcp.json').status, 'fail');
      assert.match(byName(checks, 'mcp.json').detail, /absolute path/);
      assert.equal(byName(checks, 'policy.json').status, 'fail');
      assert.match(byName(checks, 'policy.json').detail, /unknown field "toolz"/);
    });
  });

  it('says whether an operator allow entry exists for an external sandbox', async () => {
    await withTempDir(async (dir) => {
      const { env, home } = await homeIn(dir);
      assert.match(byName(await runDoctor({ repoRoot, env }), 'external sandbox').detail, /no operator allow entry/);
      await writeFile(join(home, 'external-sandbox-allowed'), '');
      assert.match(byName(await runDoctor({ repoRoot, env }), 'external sandbox').detail, /an operator allow entry exists/);
    });
  });
});

describe('hn doctor and a real container engine', async () => {
  const docker = await findDocker();
  const up = docker !== null && (await dockerIsUp(docker));
  const options = { skip: up ? false : 'Docker is not running' };
  const imageRef = (): string => {
    const run = (...args: string[]): string => execFileSync(docker as string, args, { encoding: 'utf8' }).trim();
    try {
      return run('image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}').replace(/^docker\.io\/library\//, '');
    } catch {
      run('pull', '-q', 'alpine:3.20');
      return run('image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}').replace(/^docker\.io\/library\//, '');
    }
  };

  it('verifies a real box from outside when given an image', options, async () => {
    await withTempDir(async (dir) => {
      const { env } = await homeIn(dir);
      const tier = byName(await runDoctor({ repoRoot, env, image: imageRef() }), 'container tier');
      assert.equal(tier.status, 'ok', tier.detail);
      assert.match(tier.detail, /passed the outside-in check: tier 4/);
      assert.match(tier.detail, /Not covered: DNS egress/);
    });
  });

  it('refuses an image that is only a tag', options, async () => {
    await withTempDir(async (dir) => {
      const { env } = await homeIn(dir);
      const tier = byName(await runDoctor({ repoRoot, env, image: 'alpine:3.20' }), 'container tier');
      assert.equal(tier.status, 'fail');
      assert.match(tier.detail, /pinned by digest/);
    });
  });

  it('warns about a box left running from an earlier session, and names it', options, async () => {
    await withTempDir(async (dir) => {
      const { env } = await homeIn(dir);
      const copy = join(dir, 'copy');
      await mkdir(copy);
      const box = await ContainerBox.start({ image: imageRef(), sessionId: `stray${process.pid}`, workDir: copy, docker: docker as string });
      try {
        const strays = byName(await runDoctor({ repoRoot, env }), 'stray boxes');
        assert.equal(strays.status, 'warn');
        assert.match(strays.detail, new RegExp(`hn-stray${process.pid}`));
        assert.match(strays.detail, /docker rm -f/);
      } finally {
        await box.stop();
      }
      assert.equal(byName(await runDoctor({ repoRoot, env }), 'stray boxes').status, 'ok');
    });
  });
});

describe('hn doctor output', () => {
  const sample: Check[] = [
    { name: 'a', status: 'ok', detail: 'fine' },
    { name: 'longer name', status: 'warn', detail: 'careful' },
    { name: 'b', status: 'fail', detail: 'broken' },
  ];

  it('lines the checks up, says what failed, and exits non-zero only on a failure', () => {
    const text = formatDoctor(sample);
    assert.match(text, /^ok    a            fine$/m);
    assert.match(text, /^warn  longer name  careful$/m);
    assert.match(text, /^FAIL  b            broken$/m);
    assert.match(text, /1 check\(s\) failed/);
    assert.match(text, /1 warning\(s\)/);
    assert.equal(doctorExitCode(sample), 1);
    assert.equal(doctorExitCode(sample.slice(0, 2)), 0);
    assert.match(formatDoctor(sample.slice(0, 1)), /Nothing that protects you is broken\./);
  });

  it('runs from the command line, and the exit code follows the result', async () => {
    await withTempDir(async (dir) => {
      const { env, home } = await homeIn(dir);
      const run = async (): Promise<{ code: number | null; stdout: string }> => {
        const child = spawn(process.execPath, [launcher, 'doctor'], { env, stdio: ['ignore', 'pipe', 'ignore'] });
        let stdout = '';
        child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
        const [code] = (await once(child, 'close')) as [number | null];
        return { code, stdout };
      };
      const healthy = await run();
      assert.equal(healthy.code, 0, healthy.stdout);
      assert.match(healthy.stdout, /Nothing that protects you is broken\./);
      await writeFile(join(home, 'policy.json'), 'not json');
      const broken = await run();
      assert.equal(broken.code, 1);
      assert.match(broken.stdout, /FAIL {2}policy\.json/);
    });
  });
});
