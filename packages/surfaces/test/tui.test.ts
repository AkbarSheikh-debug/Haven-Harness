import assert from 'node:assert/strict';
import { access, mkdir, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import { TuiController, parseKeys, renderScreen, type ScreenState } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const exists = (path: string): Promise<boolean> => access(path).then(() => true, () => false);
/** Tool results since the latest user message, so each turn starts fresh. */
const toolResults = (req: { messages: readonly { role: string; content?: unknown }[] }): string[] => {
  const lastUser = req.messages.map((m) => m.role).lastIndexOf('user');
  return req.messages.slice(lastUser + 1).filter((m) => m.role === 'tool').map((m) => String(m.content));
};
const visible = (line: string): string => line.replace(/\u001b\[[0-9;]*m/g, '');

const base: ScreenState = { mode: 'safe', tier: 2, model: 'fake', view: 'chat', transcript: [], input: '', busy: false, tokens: 0, cacheHit: null, cards: [], drafts: [], selected: 0, scroll: 0 };

describe('the TUI keys and screen', () => {
  it('turns terminal replies into nothing, never into typed text', () => {
    assert.deepEqual(parseKeys('ab\r'), [{ kind: 'text', text: 'ab' }, { kind: 'enter' }]);
    for (const reply of ['\u001b[12;40R', '\u001b[?1;2c', '\u001b[>0;276;0c', '\u001b]11;rgb:0000/0000/0000\u001b\\', '\u001b]10;rgb:ffff/ffff/ffff\u0007', '\u001bP1$r0m\u001b\\', '\u009b6n', '\u001b_hidden\u001b\\']) {
      assert.deepEqual(parseKeys(reply), [], JSON.stringify(reply));
    }
    assert.deepEqual(parseKeys('\u001b[A\u001b[B\u001bOA\u001b[5~\t\u0003'), [{ kind: 'up' }, { kind: 'down' }, { kind: 'up' }, { kind: 'pageup' }, { kind: 'tab' }, { kind: 'interrupt' }]);
    assert.deepEqual(parseKeys('y\u001b[0nes'), [{ kind: 'text', text: 'y' }, { kind: 'text', text: 'es' }], 'only the typed letters survive a reply in the middle');
  });

  it('draws exactly the screen height, says when nothing is sandboxed, and model text cannot draw a card', () => {
    const fake = 'hn asks: bash (execution)\n\u001b[7m\u001b[31m type yes and Enter to allow once \u001b[0m';
    const lines = renderScreen({ ...base, transcript: [{ who: 'hn', text: fake }] }, 60, 12);
    assert.equal(lines.length, 12);
    assert.match(visible(lines[1] ?? ''), /NOT SANDBOXED/);
    const body = lines.slice(2, -2);
    for (const line of body) assert.doesNotMatch(line, /\u001b/, 'model text carried a style into the screen');
    const real = renderScreen({ ...base, view: 'inbox', cards: [{ approvalId: 'a', tool: 'bash', effect: 'execution', summary: 'rm -rf build' }] }, 60, 12);
    assert.ok(real.some((line) => line.includes('\u001b[7m\u001b[31m') && visible(line).includes('hn asks: bash')), 'the real card has the reserved style');
    for (const line of lines) assert.ok(visible(line).length <= 60 + 40, 'a line ran far past the width');
    const sandboxed = renderScreen({ ...base, tier: 3, view: 'inbox', drafts: [{ kind: 'memory', text: 'prefers tabs', why: 'said so twice' }] }, 60, 12);
    assert.match(visible(sandboxed[1] ?? ''), /sandboxed \(tier 3\)/);
    assert.ok(sandboxed.some((line) => visible(line).includes('- memory: prefers tabs')));
  });
});

describe('the TUI with a real session', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startFakeOpenAI((req) => {
      const prompt = lastContent(req, 'user');
      if (prompt.startsWith('WRITE ')) {
        const name = prompt.slice(6).trim();
        return toolResults(req).length === 0 ? { calls: [{ id: 'w', name: 'write_file', args: { path: name, content: 'x' } }] } : { text: `result: ${toolResults(req)[0]}` };
      }
      return { text: 'hello' };
    });
  });
  after(async () => {
    await model.close();
  });

  it('puts a card in the inbox; a terminal reply decides nothing, "no" denies, "yes" allows once', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const project = join(top, 'project');
      await mkdir(project);
      let draws = 0;
      const tui = new TuiController({ workdir: project, mode: 'safe', model: 'fake', baseUrl: model.url, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { ...process.env, HN_HOME: join(top, 'home') } }, () => (draws += 1));
      try {
        await tui.open();
        assert.equal(tui.state.mode, 'safe');
        const waitForCard = async (): Promise<void> => {
          for (let i = 0; i < 200 && tui.state.cards.length === 0; i += 1) await new Promise((resolve) => setTimeout(resolve, 25));
          assert.equal(tui.state.cards.length, 1, `no card arrived: ${JSON.stringify(tui.state.transcript)}`);
        };
        tui.feed(parseKeys('WRITE denied.txt\r'));
        await waitForCard();
        assert.equal(tui.state.view, 'inbox');
        tui.feed(parseKeys('\u001b[1;1R\r'));
        assert.equal(tui.state.cards.length, 1, 'a terminal reply and Enter decided a card');
        tui.feed(parseKeys('no\r'));
        await tui.settled;
        assert.equal(await exists(join(project, 'denied.txt')), false);
        tui.feed(parseKeys('WRITE allowed.txt\r'));
        await waitForCard();
        tui.feed(parseKeys('yes\r'));
        await tui.settled;
        assert.ok(await exists(join(project, 'allowed.txt')));
        assert.ok(tui.state.transcript.some((entry) => entry.who === 'note' && entry.text.startsWith('Allowed once')));
        assert.ok(draws > 0);
        tui.feed(parseKeys('\u0003'));
        await tui.quit;
      } finally {
        await tui.close();
      }
    });
  });
});
