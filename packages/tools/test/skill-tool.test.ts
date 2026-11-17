import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import type { ExecResult, Operations } from '@hn/operations';
import { approvalHash, Gate, Jail, loadBashParser, type ApprovalCard, type BashParser } from '@hn/security';
import {
  createSkillTool,
  HarnessExec,
  MAX_VALIDATE_RUNS,
  SkillValidator,
  type HarnessExecResult,
  type SkillCatalog,
  type SkillEntry,
  type ToolContext,
} from '@hn/tools';

let bash: BashParser;
before(async () => {
  bash = await loadBashParser();
});

const signal = new AbortController().signal;
const context = { signal } as unknown as ToolContext;
const passing = new SkillValidator(async () => ({ ok: true, code: 0, output: '' }));

const skill = (over: Partial<SkillEntry> = {}): SkillEntry => ({
  name: 'release',
  description: 'Cut a release.',
  body: 'Follow the steps.\n- [ ] bump the version\n- [ ] write the changelog',
  checklist: ['bump the version', 'write the changelog'],
  validate: 'pnpm test',
  path: '/repo/.hn/skills/release/SKILL.md',
  hash: 'aaa',
  ...over,
});

function catalog(entries: SkillEntry[], files: Record<string, string> = {}): SkillCatalog {
  return {
    find: (name) => entries.find((entry) => entry.name === name) ?? null,
    names: () => entries.map((entry) => entry.name),
    readFile: async (_name, path) => files[path] ?? null,
  };
}

describe('the skill tool', () => {
  it('is deferred and returns the body, the checklist for todo_write, and the validate note', async () => {
    const tool = createSkillTool(catalog([skill()]), passing);
    assert.equal(tool.deferred, true);
    assert.equal(tool.effect, 'observe');
    const result = await tool.execute({ name: 'release' }, context);
    assert.match(result.content, /<skill name="release">/);
    assert.match(result.content, /Track them with todo_write/);
    assert.match(result.content, /1\. bump the version\n2\. write the changelog/);
    assert.match(result.content, /check: `pnpm test`/);
  });

  it('reads one bundled file (level 3), and says which skills exist when the name is wrong', async () => {
    const tool = createSkillTool(catalog([skill()], { 'reference.md': 'How to tag.' }), passing);
    assert.match((await tool.execute({ name: 'release', file: 'reference.md' }, context)).content, /How to tag\./);
    assert.equal((await tool.execute({ name: 'release', file: 'missing.md' }, context)).isError, true);
    const unknown = await tool.execute({ name: 'nope' }, context);
    assert.equal(unknown.isError, true);
    assert.match(unknown.content, /Loaded skills: release/);
  });
});

describe('validate: the feedback loop', () => {
  function runner(results: HarnessExecResult[]) {
    const calls: { command: string; scripts: Readonly<Record<string, string>> }[] = [];
    const run = async (command: string, scripts: Readonly<Record<string, string>>): Promise<HarnessExecResult> => {
      calls.push({ command, scripts });
      return results.shift() ?? { ok: true, code: 0, output: 'ok' };
    };
    return { calls, validator: new SkillValidator(run) };
  }

  it('runs only after a round that changed something, bound to the skill file hash', async () => {
    const { calls, validator } = runner([]);
    validator.activate(skill());
    assert.equal(await validator.afterRound(['read_file', 'grep'], signal), null);
    const message = await validator.afterRound(['edit_file'], signal);
    assert.match(message?.text ?? '', /validate passed/);
    assert.deepEqual(calls, [{ command: 'pnpm test', scripts: { '/repo/.hn/skills/release/SKILL.md': 'aaa' } }]);
    assert.equal(validator.active, null, 'a pass ends the loop');
  });

  it(`repeats until pass, and stops after ${MAX_VALIDATE_RUNS} failed runs`, async () => {
    const failing = { ok: false, code: 1, output: '1 test failed', reason: 'It exited with code 1.' };
    const { calls, validator } = runner([failing, failing, failing, failing]);
    validator.activate(skill());
    assert.match((await validator.afterRound(['bash'], signal))?.text ?? '', /run 1 of 3/);
    assert.match((await validator.afterRound(['bash'], signal))?.text ?? '', /run 2 of 3/);
    assert.match((await validator.afterRound(['bash'], signal))?.text ?? '', /failed 3 times and will not run again/);
    assert.equal(await validator.afterRound(['bash'], signal), null);
    assert.equal(calls.length, 3);
  });

  it('stops, and says not to claim a pass, when a person or the gate refuses the run', async () => {
    const { validator } = runner([{ ok: false, code: null, output: '', reason: 'A person declined.' }]);
    validator.activate(skill());
    const message = await validator.afterRound(['write_file'], signal);
    assert.match(message?.text ?? '', /did not run: A person declined\.\. Do not claim it passed/);
    assert.equal(message?.origin, 'harness');
    assert.equal(validator.active, null);
  });

  it('a skill without validate: starts no loop', async () => {
    const { calls, validator } = runner([]);
    validator.activate(skill({ validate: null }));
    assert.equal(await validator.afterRound(['bash'], signal), null);
    assert.equal(calls.length, 0);
  });
});

describe('validate: through the real gate below tier 3', () => {
  function kit() {
    const cards: ApprovalCard[] = [];
    const ran: string[] = [];
    const ops = {
      bash: {
        exec: async (command: string): Promise<ExecResult> => {
          ran.push(command);
          return { code: 0, stdout: Buffer.from('ok'), stderr: Buffer.alloc(0), timedOut: false, cancelled: false, clipped: false };
        },
      },
    } as unknown as Operations;
    const gate = new Gate({
      mode: 'accept-edits',
      workdir: '/repo',
      jail: new Jail({ root: '/repo', platform: 'linux', realpath: async (path) => path }),
      audit: () => undefined,
      bash,
      tier: 2,
      approver: async (card: ApprovalCard) => {
        cards.push(card);
        return 'session' as const;
      },
    });
    const exec = new HarnessExec({ gate, ops, workdir: '/repo', tier: 2 });
    const validator = new SkillValidator((command, scripts, abort) => exec.run({ purpose: 'validate', command, scripts }, abort));
    return { cards, ran, validator };
  }

  it('asks a person for each run, and the approval is bound to the SKILL.md hash', async () => {
    const { cards, ran, validator } = kit();
    validator.activate(skill({ hash: 'aaa' }));
    await validator.afterRound(['edit_file'], signal);
    validator.activate(skill({ hash: 'aaa' }));
    await validator.afterRound(['edit_file'], signal);
    validator.activate(skill({ hash: 'bbb' }));
    await validator.afterRound(['edit_file'], signal);
    assert.equal(cards.length, 3, 'every run asks; nothing is remembered below tier 3');
    assert.deepEqual(ran, ['pnpm test', 'pnpm test', 'pnpm test']);
    assert.equal(cards[0]?.tool, 'harness:validate');
    // Any grant the gate keeps is keyed by this hash, which covers SKILL.md's own hash as a script.
    const grant = (hash: string): string =>
      approvalHash({
        tool: 'harness:validate',
        args: { purpose: 'validate', command: 'pnpm test' },
        workdir: '/repo',
        backend: 'local',
        scripts: { '/repo/.hn/skills/release/SKILL.md': hash },
      });
    assert.equal(grant('aaa'), grant('aaa'), 'same command, same skill file: the same grant');
    assert.notEqual(grant('aaa'), grant('bbb'), 'the skill file changed: a grant for the old one does not apply');
  });
});
