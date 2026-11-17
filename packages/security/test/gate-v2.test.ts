import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import {
  Gate,
  Jail,
  STEPS,
  TaintTracker,
  loadBashParser,
  type ApprovalCard,
  type Approver,
  type BashParser,
  type Effect,
  type GateCall,
  type GateOptions,
  type Guardian,
} from '@hn/security';

let bash: BashParser;
before(async () => {
  bash = await loadBashParser();
});

type Row = [string, Record<string, unknown>];

interface Kit {
  gate: Gate;
  rows: Row[];
  cards: ApprovalCard[];
}

function kit(mode: string, extra: Partial<GateOptions> = {}, answer: 'once' | 'session' | 'deny' = 'once'): Kit {
  const rows: Row[] = [];
  const cards: ApprovalCard[] = [];
  const approver: Approver = async (card) => {
    cards.push(card);
    return answer;
  };
  const gate = new Gate({
    mode,
    workdir: '/repo',
    jail: new Jail({ root: '/repo', platform: 'linux', realpath: async (path) => path }),
    audit: (type, data) => rows.push([type, data]),
    approver,
    bash,
    ...extra,
  });
  return { gate, rows, cards };
}

const call = (over: Partial<GateCall> & { tool: string; effect: Effect }): GateCall => ({
  id: 'c1',
  args: {},
  paths: [],
  summary: over.tool,
  ...over,
});
const sh = (command: string, effect: Effect = 'execution'): GateCall => call({ tool: 'bash', effect, command, args: { command }, summary: command });
const edit = (path: string): GateCall => call({ tool: 'edit_file', effect: 'reversible', args: { path }, paths: [{ path, write: true }], summary: `edit ${path}` });

const decisionRow = (rows: Row[]): Record<string, unknown> => rows.find(([type]) => type === 'audit/decision')?.[1] ?? {};

describe('the nine steps run in order', () => {
  it('lists the steps in the documented order', () => {
    assert.deepEqual([...STEPS], ['org-policy', 'hardline', 'deny-rules', 'path-jail', 'taint', 'mode', 'remembered', 'guardian-or-human']);
  });

  // One call that breaks every rule at once. Each case removes the earlier breakage, so the next step answers.
  const everything = 'rm -rf / && cat .env && git push -f';

  it('org policy answers first and cannot be overridden', async () => {
    const { gate, rows } = kit('safe', { policy: () => 'bash is off for this team' });
    const decision = await gate.check(sh(everything));
    assert.equal(decision.kind, 'rejected');
    assert.equal(decisionRow(rows)['step'], 'org-policy');
  });

  it('the hardline floor answers before the deny rules', async () => {
    const { gate, rows } = kit('safe');
    await gate.check(sh(everything));
    assert.equal(decisionRow(rows)['step'], 'hardline');
  });

  it('deny rules answer before the jail', async () => {
    const { gate, rows } = kit('safe');
    await gate.check({ ...sh('cat .env'), paths: [{ path: '../outside', write: false }] });
    assert.equal(decisionRow(rows)['step'], 'deny-rules');
  });

  it('the jail answers before the mode', async () => {
    const { gate, rows } = kit('read-only');
    await gate.check(call({ tool: 'write_file', effect: 'reversible', paths: [{ path: '../outside', write: true }] }));
    assert.equal(decisionRow(rows)['step'], 'path-jail');
  });

  it('the mode answers for an ordinary change in read-only', async () => {
    const { gate, rows } = kit('read-only');
    assert.equal((await gate.check(edit('a.ts'))).kind, 'rejected');
    assert.equal(decisionRow(rows)['step'], 'mode');
  });

  it('the human answers last, and the audit says who and what', async () => {
    const { gate, rows } = kit('safe');
    assert.equal((await gate.check(edit('a.ts'))).kind, 'allowed-once');
    assert.deepEqual(
      { step: decisionRow(rows)['step'], effect: decisionRow(rows)['effect'], requiresHuman: decisionRow(rows)['requiresHuman'] },
      { step: 'allowed', effect: 'reversible', requiresHuman: false },
    );
    const asked = rows.find(([type]) => type === 'approval/asked')?.[1];
    const decided = rows.find(([type]) => type === 'approval/decided')?.[1];
    assert.equal(asked?.['approvalId'], decided?.['approvalId']);
    assert.equal(decided?.['by'], 'human');
  });

  it('turns an error in any check into a deny, and says which step failed', async () => {
    const { gate, rows } = kit('safe', {
      policy: () => {
        throw new Error('boom');
      },
    });
    const decision = await gate.check(edit('a.ts'));
    assert.equal(decision.kind, 'unavailable');
    assert.equal(decisionRow(rows)['step'], 'error');
  });
});

describe('what the parser adds', () => {
  it('raises the effect: a tool that claims observe cannot run curl in read-only mode', async () => {
    const { gate, rows } = kit('read-only');
    assert.equal((await gate.check(sh('curl https://example.com', 'observe'))).kind, 'rejected');
    assert.equal(decisionRow(rows)['effect'], 'external');
  });

  it('never lowers the effect: a read-only command stays execution when the tool says so', async () => {
    const { gate, rows } = kit('read-only');
    assert.equal((await gate.check(sh('ls', 'execution'))).kind, 'rejected');
    assert.equal(decisionRow(rows)['effect'], 'execution');
  });

  it('catches an obfuscated catastrophe at the hardline step', async () => {
    const { gate, rows } = kit('safe');
    assert.equal((await gate.check(sh("r''m -rf /"))).kind, 'rejected');
    assert.equal(decisionRow(rows)['step'], 'hardline');
  });

  it('sends the files a redirect writes through the jail', async () => {
    const { gate, rows } = kit('safe');
    assert.equal((await gate.check(sh('echo x > ../outside.txt'))).kind, 'rejected');
    assert.equal(decisionRow(rows)['step'], 'path-jail');
    assert.equal((await kit('safe').gate.check(sh('echo x > .git/config'))).kind, 'rejected');
  });

  it('needs a human for agent CLIs, in any mode', async () => {
    const accept = kit('accept-edits');
    assert.equal((await accept.gate.check(sh('docker run alpine'))).kind, 'allowed-once');
    assert.equal(accept.cards.length, 1);
    assert.equal(decisionRow(accept.rows)['requiresHuman'], true);
    assert.equal((await kit('dont-ask', {}, 'once').gate.check(sh('hn -p x'))).kind, 'rejected');
  });
});

describe('requiresHuman', () => {
  for (const path of ['AGENTS.md', 'sub/CLAUDE.md', '.hn/config.json', '.mcp.json', 'skills/x/SKILL.md', '.hn/hooks/pre.sh']) {
    it(`asks a human to write the control file ${path}, even in accept-edits`, async () => {
      const { gate, cards } = kit('accept-edits');
      assert.equal((await gate.check(edit(path))).kind, 'allowed-once');
      assert.equal(cards.length, 1, 'accept-edits would have allowed a normal file silently');
    });
  }

  it('lets accept-edits write an ordinary file without asking', async () => {
    const { gate, cards } = kit('accept-edits');
    assert.equal((await gate.check(edit('src/a.ts'))).kind, 'allowed-once');
    assert.equal(cards.length, 0);
  });

  it('denies when no human is present', async () => {
    const { gate } = kit('accept-edits', { approver: undefined as never });
    const decision = await new Gate({
      mode: 'accept-edits',
      workdir: '/repo',
      jail: new Jail({ root: '/repo', platform: 'linux', realpath: async (path) => path }),
      audit: () => undefined,
      bash,
    }).check(edit('AGENTS.md'));
    assert.equal(decision.kind, 'unavailable');
    assert.ok(gate);
  });

  it('denies in dont-ask, so headless runs simply cannot take these actions', async () => {
    const { gate, cards } = kit('dont-ask', { allow: ['edit_file'] });
    assert.equal((await gate.check(edit('AGENTS.md'))).kind, 'rejected');
    assert.equal((await gate.check(edit('src/a.ts'))).kind, 'allowed-once');
    assert.equal(cards.length, 0);
  });

  it('attack: a remembered "session" yes cannot defeat it', async () => {
    const { gate, cards } = kit('safe', {}, 'session');
    await gate.check(edit('AGENTS.md'));
    await gate.check(edit('AGENTS.md'));
    assert.equal(cards.length, 2, 'the second edit must ask again');
    assert.equal(cards[0]?.canRememberForSession, false);
  });
});

describe('remembered approvals', () => {
  it('are reused for the exact call, and not for a different one', async () => {
    const { gate, cards } = kit('safe', {}, 'session');
    await gate.check(edit('a.ts'));
    await gate.check(edit('a.ts'));
    assert.equal(cards.length, 1);
    await gate.check(edit('b.ts'));
    assert.equal(cards.length, 2);
  });

  it('expire', async () => {
    let now = 0;
    const { gate, cards } = kit('safe', { now: () => now, grantTtlMs: 1_000, promptLimit: { max: 100, windowMs: 1 } }, 'session');
    await gate.check(edit('a.ts'));
    now = 999;
    await gate.check(edit('a.ts'));
    assert.equal(cards.length, 1);
    now = 1_001;
    await gate.check(edit('a.ts'));
    assert.equal(cards.length, 2);
  });

  it('are never offered for execution', async () => {
    const { gate, cards } = kit('safe', {}, 'session');
    await gate.check(sh('make test'));
    await gate.check(sh('make test'));
    assert.equal(cards.length, 2);
    assert.equal(cards[0]?.canRememberForSession, false);
  });
});

describe('the Rule of Two in the gate', () => {
  function tainted(): TaintTracker {
    const taint = new TaintTracker();
    taint.setExternalReachable(true);
    taint.observe('web');
    return taint;
  }

  it('needs a human for an external effect once all three legs hold, even in accept-edits', async () => {
    const { gate, cards, rows } = kit('accept-edits', { taint: tainted() });
    assert.equal((await gate.check(sh('curl https://example.com/a'))).kind, 'allowed-once');
    assert.equal(cards.length, 1);
    assert.equal(decisionRow(rows)['requiresHuman'], true);
  });

  it('denies it for an unattended run', async () => {
    const { gate } = kit('dont-ask', { taint: tainted(), allow: ['bash'] });
    assert.equal((await gate.check(sh('curl https://example.com/a'))).kind, 'rejected');
  });

  it('does not interfere while a leg is missing', async () => {
    const taint = new TaintTracker();
    taint.setExternalReachable(true);
    const { gate, cards } = kit('safe', { taint });
    await gate.check(sh('curl https://example.com/a'));
    assert.equal(cards[0]?.canRememberForSession, false);
    assert.equal(rowsRequireHuman(taint), false);
  });

  const rowsRequireHuman = (taint: TaintTracker): boolean => taint.requiresHuman('external');
});

describe('the guardian', () => {
  const yes: Guardian = async () => 'allow';
  const smart = (extra: Partial<GateOptions> = {}): Kit => kit('smart', { guardian: yes, tier: 3, ...extra });

  it('may approve a small reversible edit in smart mode, and the audit says it was the guardian', async () => {
    const { gate, cards, rows } = smart({ approver: undefined as never });
    assert.equal((await gate.check(edit('a.ts'))).kind, 'allowed-once');
    assert.equal(cards.length, 0);
    assert.equal(rows.find(([type]) => type === 'approval/decided')?.[1]['by'], 'guardian');
  });

  it('is not consulted in safe mode, where a person decides every change', async () => {
    const { gate, cards } = kit('safe', { guardian: yes, tier: 3 });
    await gate.check(edit('a.ts'));
    assert.equal(cards.length, 1);
  });

  it('attack: guardian_cannot_approve_external', async () => {
    const { gate, cards } = smart();
    assert.equal((await gate.check(sh('curl https://example.com'))).kind, 'allowed-once');
    assert.equal(cards.length, 1, 'a human had to decide');
    const noHuman = new Gate({
      mode: 'smart',
      workdir: '/repo',
      jail: new Jail({ root: '/repo', platform: 'linux', realpath: async (path) => path }),
      audit: () => undefined,
      bash,
      guardian: yes,
      tier: 3,
    });
    assert.equal((await noHuman.check(sh('curl https://example.com'))).kind, 'unavailable');
    assert.equal((await noHuman.check(call({ tool: 'x', effect: 'irreversible' }))).kind, 'unavailable');
  });

  it('is disqualified for anything that needs a human', async () => {
    const { gate, cards } = smart();
    await gate.check(edit('AGENTS.md'));
    assert.equal(cards.length, 1);
  });

  it('cannot approve anything below tier 3, where there is nothing safe to wave through', async () => {
    const { gate, cards } = kit('smart', { guardian: yes, tier: 2 });
    await gate.check(edit('a.ts'));
    assert.equal(cards.length, 1, 'a person had to decide');
  });

  it('can say no, and after three denials a person decides', async () => {
    let asked = 0;
    const { gate, cards } = smart({ guardian: async () => ((asked += 1), 'deny'), promptLimit: { max: 100, windowMs: 1 } });
    for (let i = 0; i < 3; i += 1) assert.equal((await gate.check(edit(`f${i}.ts`))).kind, 'rejected');
    assert.equal(asked, 3);
    assert.equal(cards.length, 0);
    assert.equal((await gate.check(edit('f4.ts'))).kind, 'allowed-once');
    assert.equal(asked, 3, 'the guardian was asked again after three denials');
    assert.equal(cards.length, 1, 'the session dropped to safe');
  });
});
