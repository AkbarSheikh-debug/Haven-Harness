import assert from 'node:assert/strict';
import { readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { projectKey } from '@hn/config';
import { KeyStore } from '@hn/provider';
import type { ApprovalCard } from '@hn/security';
import { loadOrCreateLogKey, parseLog } from '@hn/session';
import { openSession, runPreset } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

/**
 * Phase 5 against a real local model (opt-in: HN_LIVE_OLLAMA=1, Ollama running; HN_LIVE_MODEL picks the model, default
 * ollama/qwen3:14b; HN_LIVE_RECORD a file for the record). Safety holds by assertion; what the model chose to do is
 * recorded, because a small model varies.
 */
const LIVE = process.env['HN_LIVE_OLLAMA'] === '1';
const MODEL = process.env['HN_LIVE_MODEL'] ?? 'ollama/qwen3:14b';
const record: Record<string, unknown> = {};

async function save(): Promise<void> {
  if (process.env['HN_LIVE_RECORD'] !== undefined) await writeFile(process.env['HN_LIVE_RECORD'], JSON.stringify(record, null, 2));
}

async function childLogsVerify(home: string, root: string, parent: string): Promise<{ verified: number; total: number }> {
  const key = await loadOrCreateLogKey(join(home, 'log.key'));
  const folder = join(home, 'sessions', projectKey(root), `${parent}.children`);
  const names = await readdir(folder).catch(() => [] as string[]);
  let verified = 0;
  for (const name of names) if (parseLog(await readFile(join(folder, name)), key).trust === 'verified') verified += 1;
  return { verified, total: names.length };
}

describe('Phase 5 live, on a local model', { skip: LIVE ? false : 'set HN_LIVE_OLLAMA=1 with Ollama running' }, () => {
  it('/implement in safe: scout, planner and worker as real processes, the worker edit approved through routing', { timeout: 1_800_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const home = join(root, '.home');
      await writeFile(join(root, 'math.js'), 'export function sub(a, b) {\n  return a - b;\n}\n');
      const cards: ApprovalCard[] = [];
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'safe', model: MODEL, window: 32_000, env: { HN_HOME: home }, verify: 'off', approver: async (card) => (cards.push(card), 'once') }, KeyStore.capture({}));
        let out = '';
        const began = Date.now();
        await runPreset(session, '/implement Add an exported function add(a, b) to math.js that returns a + b. Keep sub as it is.', (text) => (out += text));
        const math = await readFile(join(root, 'math.js'), 'utf8');
        const logs = await childLogsVerify(home, root, session.sessionId);
        record['implement'] = {
          seconds: Math.round((Date.now() - began) / 1000),
          steps: session.subagents.list().map((child) => `${child.role}:${child.status}`),
          cards: cards.map((card) => ({ tool: card.tool, routed: card.summary.startsWith('child '), target: card.target ?? null })),
          mathAfter: math,
          addDefined: /export function add\s*\(\s*a\s*,\s*b\s*\)/.test(math) || /export const add\s*=/.test(math),
          subKept: math.includes('return a - b'),
          childLogs: logs,
          output: out.slice(0, 6_000),
        };
        await save();
        // Safety, whatever the model did: every write was a routed card a person saw; every child log verifies.
        assert.ok(cards.every((card) => card.summary.startsWith('child ')), 'no child wrote without the parent person');
        assert.equal(logs.verified, logs.total);
        assert.ok(logs.total >= 1);
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });

  it('the model delegates an investigation to a scout and gets a report back as child data', { timeout: 900_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const home = join(root, '.home');
      for (let i = 0; i < 6; i += 1) await writeFile(join(root, `part${i}.js`), `// part ${i}\nexport const value${i} = ${i * 7};\n${i === 4 ? 'export const RETRY_LIMIT = 9;\n' : ''}`);
      const before = process.env['HN_PARENT_SESSION'];
      try {
        const session = await openSession({ workdir: root, mode: 'read-only', model: MODEL, window: 32_000, env: { HN_HOME: home }, verify: 'off' }, KeyStore.capture({}));
        const result = await session.agent.run('Use the subagent tool to start a scout that finds which of part0.js to part5.js defines RETRY_LIMIT. Then tell me the file and the value.');
        const calls = session.agent.events.filter((event) => event.type === 'tool/call').map((event) => String(event.data['name']));
        const reports = session.agent.events.filter((event) => event.type === 'tool/result' && event.origin === 'child').map((event) => String(event.data['content']).slice(0, 1_000));
        record['scout'] = { end: result.end, calls, reports, answer: result.text.slice(0, 1_000), named: result.text.includes('part4') };
        await save();
        assert.ok(reports.every((report) => report.includes('<child-report') || report.includes('did not finish')), 'a report is framed as child data');
        await session.agent.close();
        await session.close();
      } finally {
        if (before === undefined) delete process.env['HN_PARENT_SESSION'];
        else process.env['HN_PARENT_SESSION'] = before;
      }
    });
  });
});
