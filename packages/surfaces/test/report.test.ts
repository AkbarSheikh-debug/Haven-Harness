import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import { Harness, MAX_REPORT_CHARS, buildReport, code, renderReport, runReportCommand } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const toolResults = (request: { messages: readonly { role: string; content?: unknown }[] }): string[] => request.messages.filter((message) => message.role === 'tool').map((message) => String(message.content));

/** A command a model might write to attack the page that will show it: a link, a mention, HTML, a heading, a table break. */
const HOSTILE = 'echo "[click](http://evil.example/x) @octocat <img src=x onerror=alert(1)> | `injected` \n# Heading"';

/** Everything outside inline code spans. The report is allowed to say model text only inside them. */
const outsideCode = (markdown: string): string => markdown.replace(/`[^`\n]*`/g, '');

describe('hn report', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((request) => {
      const results = toolResults(request);
      const steps = [
        { id: 'w1', name: 'write_file', args: { path: 'new.txt', content: 'hello\n' } },
        { id: 'b1', name: 'bash', args: { command: 'node --version' } },
        { id: 'b2', name: 'bash', args: { command: 'node -e "process.exit(3)" # test' } },
        { id: 'r1', name: 'read_file', args: { path: '../outside.txt' } },
        { id: 'b3', name: 'bash', args: { command: 'echo deny-me' } },
        { id: 'b4', name: 'bash', args: { command: HOSTILE } },
      ];
      const next = steps[results.length];
      return next === undefined ? { text: 'finished' } : { calls: [next] };
    });
  });
  after(async () => {
    await model.close();
  });

  /** Runs a real session and returns where its log is, so the report is made from a real log. */
  async function session(top: string): Promise<{ project: string; home: string; sessionId: string }> {
    const project = join(top, 'project');
    const home = join(top, 'home');
    await mkdir(project);
    const harness = new Harness({
      workdir: project,
      model: 'fake',
      baseUrl: model.url,
      window: 64_000,
      verify: 'off',
      mode: 'safe',
      keys: KeyStore.capture({}),
      env: { HN_HOME: home },
      // A person who refuses anything that says deny-me and allows the rest.
      approver: async (card) => (card.summary.includes('deny-me') ? 'deny' : 'once'),
    });
    try {
      const result = await harness.run('do the work');
      return { project, home, sessionId: result.sessionId };
    } finally {
      await harness.close();
    }
  }

  const report = async (project: string, home: string, sessionId: string, json = false): Promise<{ code: number; out: string }> => {
    let out = '';
    const status = await runReportCommand({ sessionId, workdir: project, json, env: { HN_HOME: home }, out: (text) => void (out += text) });
    return { code: status, out };
  };

  it('reports where it ran, the files changed, every command and result, every refusal and every approval, from a real session', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const { project, home, sessionId } = await session(await realpath(dir));
      const { code: status, out } = await report(project, home, sessionId);
      assert.equal(status, 0, out);
      assert.match(out, /Log integrity: \*\*verified\*\*/);
      assert.match(out, /\*\*Where it ran:\*\* no box \(local, tier 2\): the permission gate was the boundary/);
      assert.match(out, /\| `new\.txt` \| write_file \|/);
      assert.match(out, /\| `node --version` \| ok \|/);
      assert.match(out, /\| `node -e "process\.exit\(3\)" # test` \| failed \(exit 3\) \| yes \|/, 'a failed check was not reported as one');
      assert.match(out, /### Refused by the gate[\s\S]*\| read_file \| `\.\.\/outside\.txt` \|/);
      assert.match(out, /\*\*Approvals asked of a person or guardian:\*\* 5 \(4 allowed, 1 denied\)/);
      assert.match(out, /\| bash \| `echo deny-me` \| denied \| human \|/);
      assert.match(out, /\| write_file \| `new\.txt` \| allowed \| human \|/);
      // The jail refused one call and the person refused another: both are refusals, and a refused command never ran.
      assert.match(out, /\*\*Tool calls:\*\* 6, \*\*2 refused by the gate\*\*/, 'a call denied by the person was not counted as refused');
      assert.match(out, /\| `echo deny-me` \| not run: refused \|/, 'a command that never ran was reported as having run');
      assert.match(out, /guardian-or-human: The user said no/);
    });
  });

  it('attack: report_text_cannot_link_or_mention - shows what a model wrote only as inert code, so a pull request cannot be made to link, mention or render it', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const { project, home, sessionId } = await session(await realpath(dir));
      const { out } = await report(project, home, sessionId);
      const rest = outsideCode(out);
      for (const bad of ['@octocat', 'evil.example', '<img', 'onerror', '[click]', 'injected', 'Heading']) assert.ok(!rest.includes(bad), `${bad} appears outside a code span`);
      assert.ok(out.split('\n').every((line) => !line.startsWith('# ')), 'model text became a heading');
      assert.match(out, /`echo "\[click\]\(http:\/\/evil\.example\/x\) @octocat <img src=x onerror=alert\(1\)> ' 'injected' # Heading"`/, 'the command was not shown as one inert code span');
      assert.equal(code('a`b|c\nd'), "`a'b'c d`");
      assert.ok(code('x'.repeat(1000)).length < 200, 'a long value was not cut');
    });
  });

  it('attack: forged_log_report_refused - refuses a log that was edited, and says nothing about what is in it', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const { project, home, sessionId } = await session(await realpath(dir));
      const folder = join(home, 'sessions', (await readdir(join(home, 'sessions')))[0] as string);
      const file = join(folder, sessionId);
      const bytes = await readFile(file);
      // Change one byte in the middle of the log: a forged or damaged record.
      const at = Math.floor(bytes.length / 2);
      bytes.writeUInt8(bytes.readUInt8(at) ^ 0xff, at);
      await writeFile(file, bytes);
      const { code: status, out } = await report(project, home, sessionId);
      assert.equal(status, 2);
      assert.match(out, /REFUSED/);
      assert.ok(!out.includes('new.txt') && !out.includes('node --version'), 'a forged log was summarised');
      const json = JSON.parse((await report(project, home, sessionId, true)).out) as { trust: string; calls: unknown[] };
      assert.equal(json.trust, 'unverified');
      assert.deepEqual(json.calls, []);
    });
  });

  it('gives structured output with --json, refuses a bad id, and says so when there is no log', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const { project, home, sessionId } = await session(await realpath(dir));
      const json = JSON.parse((await report(project, home, sessionId, true)).out) as ReturnType<typeof buildReport>;
      assert.equal(json.trust, 'verified');
      assert.equal(json.sessionId, sessionId);
      assert.deepEqual(json.filesChanged, [{ path: 'new.txt', tool: 'write_file' }]);
      assert.equal(json.calls.length, 6);
      assert.equal((await report(project, home, '../../etc/passwd')).code, 1);
      assert.equal((await report(project, home, 'nosuchsession')).code, 1);
      assert.equal((await report(join(project, 'other'), home, sessionId)).code, 1, 'a session was reported from the wrong project');
    });
  });

  it('keeps a huge report inside what a pull request can hold', () => {
    const many = Array.from({ length: 5_000 }, (_, n) => ({ callId: `c${n}`, tool: 'bash', about: `echo ${'x'.repeat(150)} ${n}`, decision: 'allowed' as const, approvals: [{ answer: 'once', by: 'human' }], outcome: 'ok' as const, exitCode: 0 }));
    const markdown = renderReport({ sessionId: 's', createdAt: null, trust: 'verified', box: null, turns: 1, calls: many, filesChanged: [], commands: many.map((call) => ({ ...call, isCheck: false })), refused: [], approvalsAsked: 5_000, approvalsAllowed: 5_000, taint: [], cost: null });
    assert.ok(markdown.length <= MAX_REPORT_CHARS + 200, `${markdown.length} characters`);
    assert.match(markdown, /and 4960 more/);
  });
});
