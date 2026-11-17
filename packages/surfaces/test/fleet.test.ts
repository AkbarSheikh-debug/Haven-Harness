import assert from 'node:assert/strict';
import { access, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import { parseFleet, parseVerdict, runFleetFile } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const exists = (path: string): Promise<boolean> => access(path).then(() => true, () => false);

describe('the fleet through the real stack', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const users = request.messages.filter((message) => message.role === 'user').map((message) => String(message.content));
      const all = users.join('\n');
      const tools = request.messages.filter((message) => message.role === 'tool').length;
      if (all.includes('You are checking work')) return { text: 'Looks right.\n{"verdict": "approve", "reason": "done.txt holds the name"}' };
      const job = /TASK ([\w-]+)/.exec(all)?.[1] ?? 'unknown';
      if (job === 'mallory' && tools === 0) return { calls: [{ id: 'm1', name: 'write_file', args: { path: '../repo-1/pwned.txt', content: 'gotcha' } }] };
      if (tools === 0) return { calls: [{ id: 'w1', name: 'write_file', args: { path: 'done.txt', content: `${job}\n` } }] };
      return { text: `finished ${job}: ${String(request.messages.at(-1)?.content).slice(0, 60)}` };
    });
  });
  after(async () => {
    await model.close();
  });

  it('runs each job as a harness in its own folder, writes the results file, keeps each job in its jail, and reports a check it could not run', { timeout: 180_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      for (const name of ['repo-1', 'repo-2', 'repo-3', 'repo-4', 'evil', 'checked']) await mkdir(join(root, name));
      const fleet = {
        model: 'fake',
        baseUrl: model.url,
        window: 64_000,
        maxWorkers: 3,
        jobs: [
          ...[1, 2, 3, 4].map((n) => ({ name: `job-${n}`, workdir: `repo-${n}`, task: `TASK job-${n}: write done.txt with your name`, ...(n === 4 ? { checker: true } : {}) })),
          { name: 'mallory', workdir: 'evil', task: 'TASK mallory: write somewhere' },
          { name: 'checked', workdir: 'checked', task: 'TASK checked: write done.txt', checks: ['node -e "process.exit(0)"'] },
        ],
      };
      await writeFile(join(root, 'fleet.json'), JSON.stringify(fleet));
      const seen: string[] = [];
      const report = await runFleetFile(join(root, 'fleet.json'), { keys: KeyStore.capture({}), env: { HN_HOME: join(root, '.home') }, onResult: (result) => seen.push(result.name) });
      assert.deepEqual(report.results.map((result) => result.name), ['job-1', 'job-2', 'job-3', 'job-4', 'mallory', 'checked']);
      for (const n of [1, 2, 3, 4]) assert.equal(await readFile(join(root, `repo-${n}`, 'done.txt'), 'utf8'), `job-${n}\n`);
      assert.deepEqual(report.results.slice(0, 4).map((result) => result.status), ['done', 'done', 'done', 'done']);
      assert.ok(report.results[3]?.tokens !== undefined && report.results[3].tokens > (report.results[0]?.tokens ?? 0), 'the checker\'s tokens count for its job');
      // Mallory's folder is its jail: the write outside it was refused, and the job still ended.
      assert.equal(await exists(join(root, 'repo-1', 'pwned.txt')), false);
      assert.match(report.results[4]?.text ?? '', /outside|Blocked/i);
      // Below tier 3 nobody is there to approve the check, so the job is not passed.
      assert.equal(report.results[5]?.status, 'unchecked');
      assert.match(report.results[5]?.reason ?? '', /nobody|human|never asks/i);
      assert.equal(seen.length, 6);
      const rows = (await readFile(join(root, 'fleet.json.results.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line) as Record<string, unknown>);
      assert.equal(rows.filter((row) => row['kind'] === 'start').length, 6);
      assert.equal(rows.filter((row) => row['kind'] === 'end').length, 6);
      assert.ok(report.results.every((result) => typeof result.sessionId === 'string'));

      // A second run finds everything done and asks the model nothing.
      const before = model.requests.length;
      const again = await runFleetFile(join(root, 'fleet.json'), { keys: KeyStore.capture({}), env: { HN_HOME: join(root, '.home') } });
      assert.equal(model.requests.length, before);
      assert.equal(again.resumedFromFile, 6);
    });
  });

  it('refuses a fleet file with unknown keys, an attended mode, or a bad job before anything runs', () => {
    assert.throws(() => parseFleet('{', '/x'), /not JSON/);
    assert.throws(() => parseFleet('{"jobs": [], "colour": 1}', '/x'), /unknown key: colour/);
    assert.throws(() => parseFleet('{"jobs": [{"name": "a", "workdir": "a", "task": "t"}], "mode": "safe"}', '/x'), /unattended/);
    assert.throws(() => parseFleet('{"jobs": [{"name": "a", "workdir": "a", "task": "t", "sudo": true}]}', '/x'), /unknown key: sudo/);
    assert.throws(() => parseFleet('{"jobs": [{"name": "a", "workdir": "a", "task": "t"}], "maxWorkers": 0}', '/x'), /positive/);
    const spec = parseFleet('{"jobs": [{"name": "a", "workdir": "sub", "task": "t", "checks": ["npm test", {"command": "lint", "cost": 1}]}]}', join('/', 'base'));
    assert.equal(spec.jobs[0]?.workdir, resolve(join('/', 'base'), 'sub'));
    assert.deepEqual(spec.jobs[0]?.checks, [{ command: 'npm test' }, { command: 'lint', cost: 1 }]);
  });

  it('reads a checker verdict strictly: anything that is not a verdict is a rejection', () => {
    assert.deepEqual(parseVerdict('fine {"verdict":"approve","reason":"ok"}'), { approve: true, reason: 'ok' });
    assert.deepEqual(parseVerdict('{"verdict":"reject","reason":"no test"}'), { approve: false, reason: 'no test' });
    assert.equal(parseVerdict('I approve!').approve, false);
    assert.equal(parseVerdict('{"verdict":"APPROVE"}').approve, false);
  });
});
