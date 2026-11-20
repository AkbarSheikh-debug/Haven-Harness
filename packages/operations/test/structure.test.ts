import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const packages = fileURLToPath(new URL('../../', import.meta.url));

/** Where a process may be started, and why. Everything else goes through `Operations`, so the gate and the sandbox see it. */
const ALLOWED: Readonly<Record<string, string>> = {
  'operations/src': 'the local backend: the only place a tool or the harness reaches the machine',
  'evals/src': 'the task-suite runner starts `hn` and its own hidden checks; it is a developer tool and does not ship in `hn`',
  'surfaces/bin': 'the launcher starts node with --disable-proto=throw and the user\'s own arguments',
  'vscode/src': 'the editor extension starts the user\'s own `hn acp` and nothing else; it is a separate program, not the agent, and does not ship in `hn`',
  'action/src': 'the GitHub Action\'s stages start `hn` (in its verified box) and `git` on a checked patch, never a command the model chose; they do not ship in `hn`',
};

async function sourceFiles(): Promise<string[]> {
  const found: string[] = [];
  for (const name of await readdir(packages)) {
    for (const folder of ['src', 'bin']) {
      const root = join(packages, name, folder);
      const files = await readdir(root, { recursive: true }).catch(() => [] as string[]);
      for (const file of files) if (/\.(ts|mjs|js|cjs)$/.test(file)) found.push(`${name}/${folder}/${file.replaceAll('\\', '/')}`);
    }
  }
  return found;
}

const STARTS_PROCESSES = /child_process|process\.binding|\bspawn(Sync)?\(|\bexecFile(Sync)?\(|\bexecSync\(/;

/** A file offends when it starts processes and is not on the list. */
const offends = (file: string, text: string): boolean =>
  STARTS_PROCESSES.test(text) && !Object.keys(ALLOWED).some((prefix) => file.startsWith(`${prefix}/`));

describe('where processes may start (invariant 14)', () => {
  it('uses child_process only in the places on the list', async () => {
    const offenders: string[] = [];
    for (const file of await sourceFiles()) if (offends(file, await readFile(join(packages, file), 'utf8'))) offenders.push(file);
    assert.deepEqual(offenders, [], 'start processes through Operations, so the gate sees them');
  });

  it('keeps the list short and every entry explained', () => {
    // Three places inside the harness's own tree, plus the two separate programs that drive it (the editor extension and the Action).
    assert.ok(Object.keys(ALLOWED).length <= 5);
    for (const reason of Object.values(ALLOWED)) assert.ok(reason.length > 20);
  });

  it('names no allowed place that does not exist, so the list cannot rot', async () => {
    for (const prefix of Object.keys(ALLOWED)) {
      const files = (await sourceFiles()).filter((file) => file.startsWith(`${prefix}/`));
      assert.ok(files.length > 0, `${prefix} has no files`);
    }
  });

  it('catches a planted offender and lets the listed places through, so the scan itself works', () => {
    const planted = "import { spawn } from 'node:child_process';\nspawn('git', ['status']);";
    assert.equal(offends('security/src/sneaky.ts', planted), true);
    assert.equal(offends('tools/src/shell-tools.ts', 'execSync("id")'), true);
    assert.equal(offends('tools/src/clean.ts', 'export const x = 1;'), false);
    assert.equal(offends('operations/src/local.ts', planted), false);
    assert.equal(offends('operations-evil/src/local.ts', planted), true);
  });
});
