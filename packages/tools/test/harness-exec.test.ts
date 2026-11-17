import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import type { ExecResult, Operations } from '@hn/operations';
import { Gate, Jail, loadBashParser, type ApprovalCard, type BashParser } from '@hn/security';
import { HarnessExec } from '@hn/tools';

let bash: BashParser;
before(async () => {
  bash = await loadBashParser();
});

const done = (over: Partial<ExecResult> = {}): ExecResult => ({
  code: 0,
  stdout: Buffer.from('ok'),
  stderr: Buffer.alloc(0),
  timedOut: false,
  cancelled: false,
  clipped: false,
  ...over,
});

function kit(mode: string, tier: number, options: { human?: boolean; allow?: string[]; result?: ExecResult } = {}) {
  const ran: string[] = [];
  const cards: ApprovalCard[] = [];
  const ops = {
    bash: {
      exec: async (command: string) => {
        ran.push(command);
        return options.result ?? done();
      },
    },
  } as unknown as Operations;
  const gate = new Gate({
    mode,
    workdir: '/repo',
    jail: new Jail({ root: '/repo', platform: 'linux', realpath: async (path) => path }),
    audit: () => undefined,
    bash,
    tier,
    ...(options.human === false
      ? {}
      : {
          approver: async (card: ApprovalCard) => {
            cards.push(card);
            return 'session' as const;
          },
        }),
    ...(options.allow === undefined ? {} : { allow: options.allow }),
  });
  return { exec: new HarnessExec({ gate, ops, workdir: '/repo', tier }), ran, cards };
}

const signal = new AbortController().signal;

describe('HarnessExec below tier 3', () => {
  it('attack: harness_exec_requires_gate_below_tier3. asks a human before running verify, even in accept-edits', async () => {
    const { exec, ran, cards } = kit('accept-edits', 2);
    const result = await exec.run({ purpose: 'verify', command: 'pnpm test' }, signal);
    assert.equal(result.ok, true);
    assert.deepEqual(ran, ['pnpm test']);
    assert.equal(cards.length, 1);
    assert.equal(cards[0]?.tool, 'harness:verify');
    assert.equal(cards[0]?.target, 'pnpm test');
  });

  it('never remembers the answer, so each run asks again', async () => {
    const { exec, cards } = kit('safe', 2);
    await exec.run({ purpose: 'validate', command: 'make check' }, signal);
    await exec.run({ purpose: 'validate', command: 'make check' }, signal);
    assert.equal(cards.length, 2);
    assert.equal(cards[0]?.canRememberForSession, false);
  });

  it('does not run when nobody is there to ask', async () => {
    const { exec, ran } = kit('safe', 2, { human: false });
    const result = await exec.run({ purpose: 'lsp', command: 'typescript-language-server --stdio' }, signal);
    assert.equal(result.ok, false);
    assert.match(result.reason ?? '', /nobody is here/);
    assert.deepEqual(ran, []);
  });

  it('does not run for an unattended run, even if the tool is allowlisted', async () => {
    const { exec, ran } = kit('dont-ask', 2, { allow: ['harness:verify'] });
    const result = await exec.run({ purpose: 'verify', command: 'pnpm test' }, signal);
    assert.equal(result.ok, false);
    assert.deepEqual(ran, []);
  });

  it('does not run a hook, setup or lsp command that the gate would block anyway', async () => {
    for (const purpose of ['hook', 'setup', 'lsp'] as const) {
      const { exec, ran } = kit('safe', 2);
      const result = await exec.run({ purpose, command: "cat .e''nv" }, signal);
      assert.equal(result.ok, false, purpose);
      assert.match(result.reason ?? '', /not allowed/);
      assert.deepEqual(ran, []);
    }
    const { exec, ran } = kit('safe', 2);
    assert.equal((await exec.run({ purpose: 'setup', command: "r''m -rf /" }, signal)).ok, false);
    assert.deepEqual(ran, []);
  });
});

describe('HarnessExec at tier 3 and above', () => {
  it('runs an allowlisted unattended command without a human, because the box is the boundary', async () => {
    const { exec, ran, cards } = kit('dont-ask', 3, { allow: ['harness:verify'] });
    assert.equal((await exec.run({ purpose: 'verify', command: 'pnpm test' }, signal)).ok, true);
    assert.deepEqual(ran, ['pnpm test']);
    assert.equal(cards.length, 0);
  });

  it('still refuses what the floor and deny rules refuse', async () => {
    const { exec, ran } = kit('dont-ask', 3, { allow: ['harness:verify'] });
    assert.equal((await exec.run({ purpose: 'verify', command: 'cat .env' }, signal)).ok, false);
    assert.deepEqual(ran, []);
  });
});

describe('HarnessExec results', () => {
  it('reports a failing exit code, a timeout and a cancel as not ok, with output', async () => {
    const failed = await kit('safe', 2, { result: done({ code: 2, stdout: Buffer.from('boom') }) }).exec.run({ purpose: 'verify', command: 'x' }, signal);
    assert.deepEqual([failed.ok, failed.code, failed.output], [false, 2, 'boom']);
    assert.match(failed.reason ?? '', /code 2/);
    const slow = await kit('safe', 2, { result: done({ code: null, timedOut: true }) }).exec.run({ purpose: 'verify', command: 'x' }, signal);
    assert.match(slow.reason ?? '', /timed out/);
    const stopped = await kit('safe', 2, { result: done({ code: null, cancelled: true }) }).exec.run({ purpose: 'verify', command: 'x' }, signal);
    assert.match(stopped.reason ?? '', /cancelled/);
  });

  it('cuts very long output', async () => {
    const big = await kit('safe', 2, { result: done({ stdout: Buffer.from('x'.repeat(100_000)) }) }).exec.run({ purpose: 'verify', command: 'x' }, signal);
    assert.ok(big.output.length < 21_000);
    assert.match(big.output, /output cut/);
  });
});
