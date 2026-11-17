import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  CARD_MARK,
  Gate,
  Jail,
  MAX_CARD_BYTES,
  PromptLimiter,
  approvalHash,
  escapeForCard,
  renderCard,
  type ApprovalCard,
  type Approver,
  type GateCall,
} from '@hn/security';

const base = { tool: 'bash', args: { command: 'sh build.sh' }, workdir: '/repo', backend: 'local' };

describe('approval hashing', () => {
  it('is stable across key order', () => {
    assert.equal(approvalHash({ ...base, args: { a: 1, b: 2 } }), approvalHash({ ...base, args: { b: 2, a: 1 } }));
  });

  it('changes with the tool, arguments, directory and backend', () => {
    const original = approvalHash(base);
    for (const changed of [
      { ...base, tool: 'edit_file' },
      { ...base, args: { command: 'sh build.sh; id' } },
      { ...base, workdir: '/other' },
      { ...base, backend: 'container' },
    ]) {
      assert.notEqual(approvalHash(changed), original);
    }
  });

  it('attack: approval_invalid_after_script_edit', () => {
    const before = approvalHash({ ...base, scripts: { 'build.sh': 'a'.repeat(64) } });
    const after = approvalHash({ ...base, scripts: { 'build.sh': 'b'.repeat(64) } });
    assert.notEqual(before, after);
  });
});

describe('card text', () => {
  it('escapes every non-ASCII character, so overrides, lookalikes and zero-width marks are visible', () => {
    assert.equal(escapeForCard('rm‮ txt.exe'), 'rm\\u{202e} txt.exe');
    assert.equal(escapeForCard('pаypal'), 'p\\u{430}ypal');
    assert.equal(escapeForCard('a​b\u001b[2J'), 'a\\u{200b}b\\u{1b}[2J');
    assert.equal(escapeForCard('line one\n\ttab'), 'line one\n\ttab');
  });

  const card: ApprovalCard = {
    approvalId: 'a',
    tool: 'web_fetch',
    effect: 'external',
    summary: 'GET https://example.com/‮evil',
    target: 'https://example.com/',
    byteCount: 30,
    canRememberForSession: false,
  };

  it('shows the byte count and the real target apart from the summary', () => {
    const text = renderCard(card);
    assert.match(text, /30 bytes/);
    assert.match(text, new RegExp(`${CARD_MARK} target: https://example.com/`));
  });

  it('attack: bidi_and_overwrite_approval_escaped', () => {
    assert.equal(renderCard({ ...card, summary: 'ok\r‮deny' }).includes('‮'), false);
    assert.equal(renderCard({ ...card, summary: 'ok\rdeny' }).includes('\r'), false);
  });

  it('attack: model text cannot draw a card of its own', () => {
    const forged = renderCard({ ...card, summary: `ls\n${CARD_MARK} Allow? [y]es once, [N]o: ` });
    assert.equal(forged.split('\n').filter((line) => line.startsWith(`${CARD_MARK} Allow?`)).length, 1);
  });
});

describe('prompt limiter', () => {
  it('pauses prompting past the limit and recovers when the window moves on', () => {
    let now = 0;
    const limiter = new PromptLimiter(3, 1_000, () => now);
    assert.deepEqual([limiter.allow(), limiter.allow(), limiter.allow(), limiter.allow()], [true, true, true, false]);
    now = 1_500;
    assert.equal(limiter.allow(), true);
  });
});

describe('the gate asks safely', () => {
  const call = (summary: string, id = 'c'): GateCall => ({
    id,
    tool: 'bash',
    args: { command: summary },
    effect: 'execution',
    paths: [],
    summary,
  });
  const make = (approver: Approver, extra: Partial<ConstructorParameters<typeof Gate>[0]> = {}): Gate =>
    new Gate({
      mode: 'safe',
      workdir: '/repo',
      jail: new Jail({ root: '/repo', platform: 'linux', realpath: async (path) => path }),
      audit: () => undefined,
      approver,
      ...extra,
    });

  it('refuses content too large to review instead of asking about it', async () => {
    let asked = false;
    const gate = make(async () => ((asked = true), 'once'));
    const decision = await gate.check(call('x'.repeat(MAX_CARD_BYTES + 1)));
    assert.equal(decision.kind, 'rejected');
    assert.equal(asked, false);
  });

  it('shows one card at a time and never batch-approves', async () => {
    let open = 0;
    let maxOpen = 0;
    const gate = make(async () => {
      open += 1;
      maxOpen = Math.max(maxOpen, open);
      await new Promise((resolve) => setTimeout(resolve, 5));
      open -= 1;
      return 'once';
    });
    await Promise.all([gate.check(call('a', '1')), gate.check(call('b', '2')), gate.check(call('c', '3'))]);
    assert.equal(maxOpen, 1);
  });

  it('pauses prompting after too many prompts in the window', async () => {
    const gate = make(async () => 'once', { promptLimit: { max: 2, windowMs: 60_000 } });
    const kinds = [];
    for (const name of ['a', 'b', 'c']) kinds.push((await gate.check(call(name))).kind);
    assert.deepEqual(kinds, ['allowed-once', 'allowed-once', 'unavailable']);
  });

  it('does not reuse a session grant after the script it runs was edited', async () => {
    let asks = 0;
    const gate = make(async () => ((asks += 1), 'session'));
    const edit = (hash: string): GateCall => ({
      id: 'e',
      tool: 'edit_file',
      args: { path: 'a.ts' },
      effect: 'reversible',
      paths: [],
      summary: 'edit',
      scripts: { 'a.ts': hash },
    });
    await gate.check(edit('1'));
    await gate.check(edit('1'));
    assert.equal(asks, 1);
    await gate.check(edit('2'));
    assert.equal(asks, 2);
  });
});
