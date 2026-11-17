import assert from 'node:assert/strict';
import { realpath } from 'node:fs/promises';
import { describe, it } from 'node:test';
import { ParentChannel, newChannelToken, parseChildMessage, serveChild, type ChildPort } from '@hn/delegate';
import { Gate, Jail, type ApprovalCard } from '@hn/security';

const card = (over: Partial<ApprovalCard> = {}): ApprovalCard => ({
  approvalId: 'a1',
  tool: 'write_file',
  effect: 'reversible',
  summary: 'write hello.txt',
  target: 'hello.txt',
  byteCount: 15,
  canRememberForSession: true,
  ...over,
});

/** A child and parent joined in memory, as the IPC pipe joins them. */
function pair(token: string, approve: (card: ApprovalCard) => Promise<'once' | 'deny'>) {
  const toChild: ((message: unknown) => void)[] = [];
  const closers: (() => void)[] = [];
  const dropped: unknown[] = [];
  const serve = serveChild(token, { approve, onDropped: (raw) => dropped.push(raw) });
  const port: ChildPort = {
    send: (message) => serve(JSON.parse(JSON.stringify(message)), (reply) => toChild.forEach((listener) => listener(JSON.parse(JSON.stringify(reply))))),
    onMessage: (listener) => toChild.push(listener),
    onClose: (listener) => closers.push(listener),
  };
  return { channel: new ParentChannel(token, port), dropped, close: () => closers.forEach((close) => close()) };
}

describe('the child channel', () => {
  it('carries a card to the parent and the answer back, and never lets a child remember a yes', async () => {
    const seen: ApprovalCard[] = [];
    const { channel } = pair(newChannelToken(), async (shown) => (seen.push(shown), 'once'));
    assert.equal(await channel.approve(card()), 'once');
    assert.equal(seen[0]?.canRememberForSession, false, 'the child said true; the parent ignores it');
    assert.equal(seen[0]?.byteCount, Buffer.byteLength('write hello.txt'), 'the size is measured, not believed');
  });

  it('drops a message with no token or the wrong one, an unknown kind and a malformed card', () => {
    const token = newChannelToken();
    const good = { t: token, kind: 'approve', id: 1, card: card() };
    assert.notEqual(parseChildMessage(good, token), null);
    for (const bad of [
      { ...good, t: undefined },
      { ...good, t: newChannelToken() },
      { ...good, kind: 'run-tool' },
      { ...good, id: -1 },
      { ...good, card: { ...card(), effect: 'godlike' } },
      { ...good, card: { ...card(), summary: 'x'.repeat(70_000) } },
      { t: token, kind: 'rate-acquire', id: 2, tokens: -5 },
      'approve',
      null,
    ]) {
      assert.equal(parseChildMessage(bad, token), null, JSON.stringify(bad)?.slice(0, 80));
    }
  });

  it('answers no to everything once the pipe is gone, including a card already waiting', async () => {
    let release: (() => void) | undefined;
    const { channel, close } = pair(newChannelToken(), () => new Promise((resolve) => (release = () => resolve('once'))));
    const waiting = channel.approve(card());
    close();
    assert.equal(await waiting, 'deny');
    assert.equal(await channel.approve(card()), 'deny');
    release?.();
  });

  it('a parent handler that throws is a no, never a yes', async () => {
    const { channel } = pair(newChannelToken(), async () => {
      throw new Error('door closed');
    });
    assert.equal(await channel.approve(card()), 'deny');
  });
});

describe('the parent gate relays a child card', () => {
  const audit: [string, Record<string, unknown>][] = [];
  const gate = (mode: string, approver?: (card: ApprovalCard) => Promise<'once' | 'session' | 'deny'>) =>
    new Gate({ mode, workdir: process.cwd(), jail: new Jail({ root: process.cwd(), realpath: (path) => realpath(path) }), audit: (type, data) => audit.push([type, data]), ...(approver === undefined ? {} : { approver }) });

  it('labels it with the child, counts a session yes once, and audits the pair', async () => {
    const shown: ApprovalCard[] = [];
    const parent = gate('safe', async (c) => (shown.push(c), 'session'));
    assert.equal(await parent.relay(card(), 'worker c-1'), 'once');
    assert.match(shown[0]?.summary ?? '', /^child worker c-1 asks:\nwrite hello\.txt$/);
    assert.equal(shown[0]?.canRememberForSession, false);
    const types = audit.slice(-2).map(([type]) => type);
    assert.deepEqual(types, ['approval/asked', 'approval/decided']);
    assert.equal(audit.at(-1)?.[1]['relayedFrom'], 'worker c-1');
  });

  it('says no with nobody at the parent, and in a mode that never asks', async () => {
    assert.equal(await gate('safe').relay(card(), 'c'), 'deny');
    let asked = false;
    assert.equal(await gate('dont-ask', async () => ((asked = true), 'once')).relay(card(), 'c'), 'deny');
    assert.equal(asked, false);
  });

  it('keeps a hostile child label from drawing on the card', async () => {
    const shown: ApprovalCard[] = [];
    await gate('safe', async (c) => (shown.push(c), 'deny')).relay(card(), 'x\n\u001b[2Jfake card');
    assert.doesNotMatch(shown[0]?.summary.split('\n')[0] ?? '', /\u001b|\n/);
  });
});
