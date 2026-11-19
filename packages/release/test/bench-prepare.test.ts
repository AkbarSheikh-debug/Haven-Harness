import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SCRIPT = join(ROOT, 'scripts', 'bench', 'prepare.ts');

interface Step {
  what: string;
  command: string;
  args: string[];
}
interface Plan {
  version: string;
  platform: string;
  package: string;
  helpers: string;
  steps: Step[];
  rustImage: string;
  keyId: string;
}

const hn = (...args: string[]): Promise<{ stdout: string; stderr: string; code: number }> =>
  run(process.execPath, ['--disable-proto=throw', SCRIPT, ...args]).then(
    (done) => ({ stdout: done.stdout, stderr: done.stderr, code: 0 }),
    (error: { stdout: string; stderr: string; code: number }) => ({ stdout: error.stdout, stderr: error.stderr, code: error.code }),
  );

const planFor = async (...args: string[]): Promise<Plan> => JSON.parse((await hn('--out', join(ROOT, '..', 'never-created-by-a-dry-run'), '--dry-run', '--json', ...args)).stdout.trim()) as Plan;

/** The script is run, not imported: the release build type-checks tests, and nothing under packages may reach into scripts. */
describe('preparing what a benchmark installs', () => {
  it('builds the helper in a Rust image pinned by digest, from the locked dependencies', async () => {
    const built = await planFor();
    assert.match(built.rustImage, /^rust@sha256:[0-9a-f]{64}$/, 'a tag can move; a digest cannot');
    const docker = built.steps.find((step) => step.command === 'docker');
    assert.ok(docker !== undefined);
    assert.ok(docker.args.includes(built.rustImage));
    assert.match(docker.args.at(-1) as string, /cargo build --release --locked/);
    assert.match(docker.args.at(-1) as string, new RegExp(`hn-sandbox-${built.version}-linux-x64`));
    assert.ok(docker.args.some((arg) => arg.endsWith(':/src:ro')), 'the source is mounted read-only');
  });

  it('packs and signs with the benchmark key and never the release key, in this order: pack, build, sign', async () => {
    const built = await planFor();
    assert.deepEqual(built.steps.map((step) => step.what.split(' ')[0]), ['pack', 'build', 'hash']);
    for (const step of built.steps.filter((entry) => entry.command !== 'docker')) {
      assert.equal(step.args[step.args.indexOf('--key-id') + 1], built.keyId);
      assert.match(step.args[step.args.indexOf('--key') + 1] as string, /bench-key\.pem$/);
      assert.ok(!step.args.some((arg) => /release-key|RELEASE-KEY/i.test(arg)), 'the release key is never used');
    }
  });

  it('maps the architecture to the helper platform hn looks for, and names where the results go', async () => {
    assert.equal((await planFor('--arch', 'arm64')).platform, 'linux-arm64');
    const built = await planFor();
    assert.equal(built.platform, 'linux-x64');
    assert.match(built.package, new RegExp(`package[\\\\/]haven-harness-${built.version.replaceAll('.', '\\.')}\\.tgz$`));
    assert.match(built.helpers, /helpers-signed$/);
  });

  it('prints its plan on a dry run without running or creating anything, and refuses a missing folder or architecture', async () => {
    const dry = await hn('--out', join(ROOT, '..', 'never-created-by-a-dry-run'), '--dry-run');
    assert.equal(dry.code, 0, dry.stderr);
    assert.equal((dry.stdout.match(/^\S.*:$/gm) ?? []).length, 3, dry.stdout);
    assert.match(dry.stdout, /cargo build --release --locked/);
    assert.equal((await hn()).code, 2);
    assert.equal((await hn('--out', 'x', '--arch', 'riscv')).code, 2);
  });
});
