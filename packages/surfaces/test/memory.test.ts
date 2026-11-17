import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { Agent, type LoopConfig, type ToolDispatcher } from '@hn/loop';
import { MemoryFile, appendProposal, dailyNotePath, memoryPaths, newProposalId, readProposals } from '@hn/memory';
import { resolveCaps, type ModelProvider, type ModelReply, type ModelRequest } from '@hn/provider';
import { MemoryDoor, REVIEW_PROMPT, createReviewer, parseLearnSource, userTurns } from '@hn/surfaces';
import { parseLog } from '@hn/session';
import { withTempDir } from '@hn/testkit';

const key = randomBytes(32);
const usage = { input: 100, output: 10, cacheRead: 0, cacheWrite: 0 };

/** Replies in order and keeps every request, so the test can compare what each side sent. */
class Scripted implements ModelProvider {
  readonly route = 'fake';
  readonly requests: ModelRequest[] = [];
  readonly #replies: ModelReply[];
  constructor(replies: ModelReply[]) {
    this.#replies = replies;
  }
  async complete(request: ModelRequest): Promise<ModelReply> {
    this.requests.push(request);
    return this.#replies.shift() ?? { parts: [{ type: 'text', text: 'done' }], stopReason: 'end', usage, model: 'fake' };
  }
}

const say = (text: string): ModelReply => ({ parts: [{ type: 'text', text }], stopReason: 'end', usage, model: 'fake' });
const call = (...calls: [string, string, unknown][]): ModelReply => ({
  parts: calls.map(([id, name, args]) => ({ type: 'tool_call' as const, id, name, args })),
  stopReason: 'tool_use',
  usage,
  model: 'fake',
});

const parentTools: ToolDispatcher = {
  specs: [
    { name: 'memory', description: 'Save what should outlast this session.', parameters: { type: 'object' } },
    { name: 'bash', description: 'Run a command.', parameters: { type: 'object' } },
  ],
  check: (request) => ({ kind: 'ok', name: request.name, args: request.args }),
  isConcurrencySafe: () => false,
  touches: () => ({ reads: [], writes: [] }),
  run: async () => ({ content: 'ok', isError: false, origin: 'harness' }),
};

const loopConfig = (provider: ModelProvider): LoopConfig => ({
  provider,
  caps: resolveCaps('fake', { window: 64_000, maxOutput: 4_000, usage: 'full' }),
  model: 'fake',
  system: 'You are hn.',
  tools: parentTools,
  maxOutputTokens: 4_000,
  maxIterations: 20,
  maxParallelToolCalls: 4,
});

describe('background review', () => {
  it('writes notes and proposals only, never MEMORY.md, sends the parent\'s exact prefix, and leaves the parent\'s log alone', async () => {
    await withTempDir(async (dir) => {
      const paths = memoryPaths(join(dir, 'home'), join(dir, 'project'));
      const parentPath = join(dir, 'sessions', 'parent');
      const parentModel = new Scripted([say('Moved the queue to SQS.')]);
      const parent = await Agent.open({ config: loopConfig(parentModel), path: parentPath, sessionId: 'parent', key, lockDir: join(dir, 'locks') });
      await parent.run('Move the queue to SQS; we decided that today.');
      const before = await readFile(parentPath);

      const reviewModel = new Scripted([
        call(
          ['r1', 'memory', { action: 'add', text: 'The queue moved to SQS on 2026-11-14.' }],
          ['r2', 'memory', { action: 'add', target: 'memory', text: 'The queue runs on SQS.', why: 'decided in this session' }],
          ['r3', 'bash', { command: 'rm -rf /' }],
          ['r4', 'memory', { action: 'remove', target: 'memory', match: 'anything' }],
        ),
        say('Saved.'),
      ]);
      const review = createReviewer({
        parentPath,
        childrenDir: join(dir, 'sessions', 'parent.children'),
        key,
        lockDir: join(dir, 'locks'),
        config: loopConfig(reviewModel),
        paths,
        worst: () => 'harness',
      });
      const result = await review();
      assert.deepEqual([result.notes, result.proposals, result.end], [1, 1, 'done']);
      assert.ok(result.usage.input > 0, 'its cost is its own and is reported');

      assert.equal(await readFile(paths.memory, 'utf8').catch(() => null), null, 'MEMORY.md was not written');
      const proposals = await readProposals(paths);
      assert.deepEqual(proposals.map((p) => [p.kind, p.text, p.source]), [['memory', 'The queue runs on SQS.', 'review']]);
      assert.match(proposals[0]?.evidence[0]?.quote ?? '', /Move the queue to SQS/);
      const note = await MemoryFile.open({ path: dailyNotePath(paths, new Date()), scope: 'daily', project: paths.projectKey });
      assert.deepEqual(note.entries.map((entry) => [entry.text, entry.who]), [['The queue moved to SQS on 2026-11-14.', 'review']]);

      const first = reviewModel.requests[0] as ModelRequest;
      const parentRequest = parentModel.requests[0] as ModelRequest;
      assert.equal(first.system, parentRequest.system);
      assert.equal(JSON.stringify(first.tools), JSON.stringify(parentRequest.tools), 'byte-identical tools, so the cache still hits');
      assert.equal(JSON.stringify(first.messages[0]), JSON.stringify(parentRequest.messages[0]), 'the same conversation prefix');
      const toolResults = JSON.stringify(reviewModel.requests[1]?.messages.slice(-4));
      assert.match(toolResults, /can only use the memory tool/);
      assert.match(toolResults, /can only propose new entries/);

      assert.deepEqual(await readFile(parentPath), before, "the parent's log is unchanged");
      await parent.close();
      const children = join(dir, 'sessions', 'parent.children');
      const [name] = (await readdir(children)).filter((file) => file.startsWith('review-') && !file.includes('.'));
      const reviewLog = parseLog(await readFile(join(children, name as string)), key);
      assert.equal(reviewLog.trust, 'verified');
      const asked = reviewLog.events.find((event) => event.type === 'user/message' && event.data['text'] === REVIEW_PROMPT);
      assert.equal(asked?.origin, 'harness');
    });
  });

  it('asks with the harness as the speaker, never the user', () => {
    assert.match(REVIEW_PROMPT, /comes from the harness, not from the user/);
  });
});

describe('the memory door', () => {
  const turns = (count: number, origin: 'user' | 'harness' = 'user') =>
    Array.from({ length: count }, (_, i) => [
      { seq: i * 2 + 1, ts: '2026-11-14T00:00:00Z', type: 'turn/start' as const, origin: 'harness' as const, data: {} },
      { seq: i * 2 + 2, ts: '2026-11-14T00:00:00Z', type: 'user/message' as const, origin, data: { text: 't' } },
    ]).flat();

  it('runs background review on every tenth user turn, one at a time, and reports its cost', async () => {
    const said: string[] = [];
    let runs = 0;
    let events = turns(9);
    const review = async () => (runs += 1, { notes: 2, proposals: 1, usage: { input: 1200, output: 80, cacheRead: 0, cacheWrite: 0 }, steps: 3, end: 'done' });
    const door = new MemoryDoor({ review, agent: { get events() { return events; } } }, (text) => said.push(text));
    assert.equal(door.afterTurn(), null);
    events = turns(10);
    const first = door.afterTurn();
    assert.ok(first !== null);
    assert.equal(door.afterTurn(), null, 'not a second one while the first runs');
    await door.settle();
    assert.equal(runs, 1);
    assert.match(said.join(''), /\[background review\] 2 notes, 1 proposal \(1,200 in, 80 out, 3 steps\)/);
    events = [...turns(10), ...turns(10, 'harness')];
    assert.equal(userTurns(events), 10, 'a turn the harness started is not a user turn');
  });
});

describe('hn dream', () => {
  it('--dry-run sweeps the project, asks no model and writes nothing', async () => {
    await withTempDir(async (dir) => {
      const { spawn } = await import('node:child_process');
      const { mkdir } = await import('node:fs/promises');
      const { fileURLToPath } = await import('node:url');
      const project = join(dir, 'project');
      await mkdir(project);
      const launcher = fileURLToPath(new URL('../bin/hn.mjs', import.meta.url));
      const child = spawn(process.execPath, [launcher, 'dream', '--dry-run'], { cwd: project, env: { ...process.env, HN_HOME: join(dir, 'home'), HN_PARENT_SESSION: '' }, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
      child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
      const [code] = (await once(child, 'close')) as [number | null];
      assert.equal(code, 0, stderr);
      assert.match(stdout, /^Dry run: nothing was asked or written\. 0 themes/);
      const paths = memoryPaths(join(dir, 'home'), project);
      assert.equal(await readFile(paths.dreams, 'utf8').catch(() => null), null);
    });
  });
});

describe('the memory commands and cards at the door', () => {
  const scripted = (answers: string[]) => async () => answers.shift() ?? '';
  const proposal = (text: string, kind: 'memory' | 'rule' = 'memory') => ({
    v: 1 as const, id: newProposalId(), kind, text, why: 'asked five times', source: 'dream' as const, origin: 'user' as const, score: 0.8,
    evidence: [{ session: 's1', seq: 2, origin: 'user' as const, quote: 'how does the alias work?' }],
    created: new Date().toISOString(), expires: new Date(Date.now() + 86_400_000).toISOString(),
  });

  it('shows cards at launch: y saves to MEMORY.md, a rule needs its diff, and the user\'s AGENTS.md gets the line', async () => {
    await withTempDir(async (dir) => {
      const home = join(dir, 'home');
      const paths = memoryPaths(home, join(dir, 'project'));
      await appendProposal(paths, proposal('The db alias is db.'));
      await appendProposal(paths, proposal('Run the tests before every commit.', 'rule'));
      const said: string[] = [];
      const door = new MemoryDoor({ review: null, memoryPaths: paths, dream: null, agent: { events: [] } }, (text) => said.push(text), { ask: scripted(['y', 'd', 'y']), home, person: 'tester' });
      await door.start();
      assert.match(said.join(''), /Memory card 1 of 2[\s\S]*Would store exactly/);
      assert.match(said.join(''), /\+- Run the tests before every commit\./);
      assert.deepEqual((await MemoryFile.open({ path: paths.memory, scope: 'project', project: paths.projectKey })).entries.map((entry) => entry.text), ['The db alias is db.']);
      assert.equal(await readFile(join(home, 'AGENTS.md'), 'utf8'), '- Run the tests before every commit.\n');
    });
  });

  it('/memory shows the files, /memory undo takes back the last write, /memory accept keeps a hand edit', async () => {
    await withTempDir(async (dir) => {
      const paths = memoryPaths(join(dir, 'home'), join(dir, 'project'));
      const file = await MemoryFile.open({ path: paths.memory, scope: 'project', project: paths.projectKey });
      await file.apply([{ op: 'add', text: 'Uses pnpm.' }], { who: 'agent', sourceSession: 's', origin: 'user', taint: 'clean', why: 't', approvedBy: 'user-request' });
      const said: string[] = [];
      const door = new MemoryDoor({ review: null, memoryPaths: paths, agent: { events: [] } }, (text) => said.push(text), { person: 'tester' });
      assert.equal(await door.command('/memory'), true);
      assert.match(said.join(''), /MEMORY\.md \(10 of 2200 characters\)\n1\. \[user\] Uses pnpm\./);
      await door.command('/memory history memory');
      assert.match(said.join(''), /1\. .*: 0 entries/);
      await door.command('/memory undo memory');
      assert.deepEqual((await MemoryFile.open({ path: paths.memory, scope: 'project', project: paths.projectKey })).entries, []);
      const { writeFile } = await import('node:fs/promises');
      await writeFile(paths.memory, 'Deploys on Fridays.\n');
      await door.command('/memory');
      assert.match(said.join(''), /changed by hand, not loaded until you \/memory accept it/);
      await door.command('/memory accept memory');
      assert.deepEqual((await MemoryFile.open({ path: paths.memory, scope: 'project', project: paths.projectKey })).entries.map((e) => [e.text, e.approvedBy]), [['Deploys on Fridays.', 'tester']]);
      assert.equal(await door.command('/compact'), false, 'not a memory command');
    });
  });

  it('/learn runs one harness turn, checks the reply against what was read, and saves only on a yes', async () => {
    await withTempDir(async (dir) => {
      const home = join(dir, 'home');
      const sections = ['When to Use', 'Prerequisites', 'How to Run', 'Quick Reference', 'Procedure', 'Pitfalls', 'Verification'];
      const skill = `---\nname: make-build\ndescription: Build with make\n---\n${sections.map((s) => `## ${s}\nmake build --release`).join('\n')}`;
      const asked: { input: string; origin?: string }[] = [];
      const events = [{ seq: 1, ts: '2026-11-14T00:00:00Z', type: 'tool/result' as const, origin: 'workspace' as const, data: { callId: 'c', content: 'Run make build --release to build.' } }];
      const agent = {
        events,
        run: async (input: string, options?: { origin?: 'user' | 'harness' }) => (asked.push({ input, ...(options?.origin === undefined ? {} : { origin: options.origin }) }), { text: `<<<FILE SKILL.md>>>\n${skill}\n<<<END FILE>>>` }),
      };
      const said: string[] = [];
      const door = new MemoryDoor({ review: null, memoryPaths: memoryPaths(home, dir), agent }, (text) => said.push(text), { ask: scripted(['y']), home });
      await door.command('/learn docs/build');
      assert.equal(asked[0]?.origin, 'harness');
      assert.match(asked[0]?.input ?? '', /the folder docs\/build/);
      assert.match(said.join(''), /Saved to/);
      assert.match(await readFile(join(home, 'skills', 'make-build', 'SKILL.md'), 'utf8'), /^---\ncreated_by: agent\n/);
      assert.deepEqual(parseLearnSource('https://example.com/docs'), { kind: 'url', value: 'https://example.com/docs' });
      assert.deepEqual(parseLearnSource(''), { kind: 'conversation' });
    });
  });
});

describe('the frozen snapshot', () => {
  it('is the same frame all session, even after a write to memory', async () => {
    await withTempDir(async (dir) => {
      const { TaintTracker } = await import('@hn/security');
      const { openMemory } = await import('@hn/surfaces');
      const home = join(dir, 'home');
      const options = { home, workdir: join(dir, 'project'), taint: new TaintTracker(), sessionId: 's', attended: true, approver: 'tester', events: () => [], sessionLogs: join(dir, 'logs'), logKey: key, record: () => undefined };
      const wiring = await openMemory(options);
      const before = await wiring.hooks.snapshot();
      await (await MemoryFile.open({ path: wiring.paths.memory, scope: 'project', project: wiring.paths.projectKey })).apply([{ op: 'add', text: 'Written mid-session.' }], { who: 'agent', sourceSession: 's', origin: 'user', taint: 'clean', why: 't', approvedBy: 'user-request' });
      assert.deepEqual(await wiring.hooks.snapshot(), before);
      assert.doesNotMatch(before.text, /Written mid-session/);
      const next = await openMemory(options);
      assert.match((await next.hooks.snapshot()).text, /Written mid-session/, 'the next session sees it');
      wiring.close();
      next.close();
    });
  });
});
