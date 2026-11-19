import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import { runFleetFile } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

/**
 * Phase 6 against a real local model (opt-in: HN_LIVE_OLLAMA=1, Ollama running; HN_LIVE_MODEL picks the model, default
 * ollama/qwen3:14b; HN_LIVE_RECORD a file for the record). Safety holds by assertion; what the model did is recorded,
 * and each job's outcome is judged by a hidden check the test runs itself, as the task suite does.
 */
const LIVE = process.env['HN_LIVE_OLLAMA'] === '1';
const MODEL = process.env['HN_LIVE_MODEL'] ?? 'ollama/qwen3:14b';

describe('Phase 6 live, on a local model', { skip: LIVE ? false : 'set HN_LIVE_OLLAMA=1 with Ollama running' }, () => {
  it('a three-job fleet runs each job in its own folder, unattended, and the results file is complete', { timeout: 1_800_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const files: Record<string, Record<string, string>> = {
        add: { 'math.js': 'export function sub(a, b) {\n  return a - b;\n}\n', 'package.json': '{ "type": "module" }\n' },
        greet: { 'greet.js': "export const greet = () => 'hello';\n", 'package.json': '{ "type": "module" }\n' },
        version: { 'package.json': '{ "name": "demo", "version": "4.7.31" }\n' },
      };
      for (const [name, contents] of Object.entries(files)) {
        await mkdir(join(root, name));
        for (const [file, text] of Object.entries(contents)) await writeFile(join(root, name, file), text);
      }
      const fleet = {
        maxWorkers: 2,
        jobs: [
          { name: 'add', workdir: 'add', task: 'Add an exported function add(a, b) to math.js that returns a + b. Keep sub as it is.', checker: true },
          { name: 'greet', workdir: 'greet', task: "In greet.js, make greet return 'hi' instead of 'hello'. Change nothing else." },
          { name: 'version', workdir: 'version', task: 'What version is this package, according to package.json? Reply with just the version.' },
        ],
      };
      await writeFile(join(root, 'fleet.json'), JSON.stringify(fleet));
      const started = Date.now();
      const report = await runFleetFile(join(root, 'fleet.json'), { keys: KeyStore.capture({}), env: { HN_HOME: join(root, '.home') }, defaults: { model: MODEL } });
      const seconds = Math.round((Date.now() - started) / 1000);

      // Safety, asserted: every job settled once, in order, in its own folder.
      assert.deepEqual(report.results.map((result) => result.name), ['add', 'greet', 'version']);
      const rows = (await readFile(join(root, 'fleet.json.results.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line) as { kind: string });
      assert.equal(rows.filter((row) => row.kind === 'end').length, 3);
      for (const name of Object.keys(files)) {
        const present = (await readdir(join(root, name))).sort();
        assert.ok(present.every((file) => Object.hasOwn(files[name] as object, file) || file.endsWith('.js')), `${name} holds only its own files: ${present.join(', ')}`);
      }

      // What the model did, judged by hidden checks the agent never saw.
      const runs = (directory: string, script: string): boolean => {
        try {
          execFileSync(process.execPath, ['-e', script], { cwd: join(root, directory), stdio: 'ignore', timeout: 10_000 });
          return true;
        } catch {
          return false;
        }
      };
      const record = {
        model: MODEL,
        seconds,
        results: report.results.map((result) => ({ name: result.name, status: result.status, attempts: result.attempts, tokens: result.tokens, reason: result.reason ?? null, text: result.text.slice(0, 300) })),
        hidden: {
          add: runs('add', "import('./math.js').then(({ add, sub }) => { if (add(2, 3) !== 5 || sub(5, 3) !== 2) process.exit(1); })"),
          greet: (await readFile(join(root, 'greet', 'greet.js'), 'utf8')).includes("'hi'"),
          version: report.results[2]?.text.includes('4.7.31') ?? false,
        },
      };
      process.stdout.write(`# live: ${JSON.stringify(record)}\n`);
      if (process.env['HN_LIVE_RECORD'] !== undefined) await writeFile(process.env['HN_LIVE_RECORD'], JSON.stringify(record, null, 2));
    });
  });
});
