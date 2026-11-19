import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const BENCH = join(ROOT, 'scripts', 'bench');

/** A Python that has Harbor: HN_BENCH_PYTHON, or the `bench-env` virtual environment beside the repository. */
function harborPython(): string | null {
  const given = process.env['HN_BENCH_PYTHON'];
  if (given !== undefined && given !== '') return existsSync(given) ? given : null;
  const beside = join(dirname(ROOT), 'bench-env', process.platform === 'win32' ? join('Scripts', 'python.exe') : join('bin', 'python'));
  return existsSync(beside) ? beside : null;
}

const python = harborPython();

/**
 * The Harbor adapter is Python, so its own tests are Python's `unittest`. They need Harbor installed, which only a
 * machine set up for benchmarks has; anywhere else this is skipped and says why.
 */
describe('the Harbor adapter', { skip: python === null ? 'Harbor is not installed (set HN_BENCH_PYTHON to a Python that has it)' : false }, () => {
  it('passes its unit tests: model flags, the narrow container claim, the key kept out of the command, a result read all-or-nothing', { timeout: 180_000 }, async () => {
    const result = await run(python as string, ['-m', 'unittest', 'discover', '-s', BENCH, '-p', 'test_*.py'], { cwd: BENCH, env: { ...process.env, PYTHONPATH: BENCH, PYTHONIOENCODING: 'utf-8' }, maxBuffer: 1 << 24 }).catch((error: { stdout?: string; stderr?: string }) => {
      assert.fail(`${error.stderr ?? ''}${error.stdout ?? ''}`);
    });
    assert.match(result.stderr, /\nOK\s*$/);
  });
});
