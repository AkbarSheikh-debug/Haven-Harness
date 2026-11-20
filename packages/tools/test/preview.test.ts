import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { revealHidden } from '@hn/core';
import { localOperations } from '@hn/operations';
import { Gate, Jail, MAX_CHANGE_CHARS, type ApprovalCard } from '@hn/security';
import { createDispatcher, type ToolDefinition } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

/** A session in `safe` mode whose approver records every card it is shown and says yes. */
async function setup(directory: string, extraTools: ToolDefinition[] = []) {
  const dir = await realpath(directory);
  const ops = localOperations(join(dir, '..', 'spill'));
  const cards: ApprovalCard[] = [];
  const audit: [string, Record<string, unknown>][] = [];
  const gate = new Gate({
    mode: 'safe',
    workdir: dir,
    audit: (type, data) => audit.push([type, data]),
    jail: new Jail({ root: dir, realpath: ops.read.realpath }),
    approver: async (card) => (cards.push(card), 'once'),
  });
  const tools = createDispatcher({ gate, ops, workdir: dir, extraTools });
  let n = 0;
  const call = (name: string, args: unknown) => tools.run({ id: `c${(n += 1)}`, name, args }, new AbortController().signal);
  return { dir, cards, audit, call };
}

describe('the change an approval card carries', () => {
  it('shows an edit as the whole file before and after, and writes exactly what it showed', async () => {
    await withTempDir(async (directory) => {
      const { dir, cards, audit, call } = await setup(directory);
      await writeFile(join(dir, 'a.txt'), 'one\ntwo\nthree\n');
      await call('read_file', { path: 'a.txt' });
      const outcome = await call('edit_file', { path: 'a.txt', old_string: 'two', new_string: '2' });
      assert.equal(outcome.isError, false, outcome.content);
      const change = cards.at(-1)?.change;
      assert.deepEqual(change, { path: 'a.txt', oldText: 'one\ntwo\nthree\n', newText: 'one\n2\nthree\n', partial: false, truncated: false });
      assert.equal(await readFile(join(dir, 'a.txt'), 'utf8'), change?.newText);
      const asked = audit.find(([type]) => type === 'approval/asked');
      assert.match(String(asked?.[1]['changeDigest']), /^[0-9a-f]{16}$/, 'the log does not say what the person was shown');
    });
  });

  it('shows a write over an existing file as that file before and the new content after', async () => {
    await withTempDir(async (directory) => {
      const { dir, cards, call } = await setup(directory);
      await writeFile(join(dir, 'old.txt'), 'before\n');
      await call('read_file', { path: 'old.txt' });
      await call('write_file', { path: 'old.txt', content: 'after\n' });
      assert.deepEqual(cards.at(-1)?.change, { path: 'old.txt', oldText: 'before\n', newText: 'after\n', partial: false, truncated: false });
      assert.equal(await readFile(join(dir, 'old.txt'), 'utf8'), 'after\n');
    });
  });

  it('shows a new file with no old text, and a CRLF file as the model will leave it', async () => {
    await withTempDir(async (directory) => {
      const { dir, cards, call } = await setup(directory);
      await call('write_file', { path: 'new.txt', content: 'hello\n' });
      assert.deepEqual(cards.at(-1)?.change, { path: 'new.txt', oldText: null, newText: 'hello\n', partial: false, truncated: false });
      await writeFile(join(dir, 'crlf.txt'), 'a\r\nb\r\n');
      await call('read_file', { path: 'crlf.txt' });
      await call('edit_file', { path: 'crlf.txt', old_string: 'b', new_string: 'c' });
      assert.equal(cards.at(-1)?.change?.newText, 'a\r\nc\r\n');
      assert.equal(await readFile(join(dir, 'crlf.txt'), 'utf8'), 'a\r\nc\r\n');
    });
  });

  it('shows only the changed part of a file too big to show, and says a cut side is cut', async () => {
    await withTempDir(async (directory) => {
      const { dir, cards, call } = await setup(directory);
      await writeFile(join(dir, 'big.txt'), `${'x'.repeat(MAX_CHANGE_CHARS)}\nneedle\n`);
      await call('read_file', { path: 'big.txt' });
      await call('edit_file', { path: 'big.txt', old_string: 'needle', new_string: 'thread' });
      assert.deepEqual(cards.at(-1)?.change, { path: 'big.txt', oldText: 'needle', newText: 'thread', partial: true, truncated: false });

      await call('write_file', { path: 'huge.txt', content: 'y'.repeat(MAX_CHANGE_CHARS + 500) });
      const huge = cards.at(-1)?.change;
      assert.equal(huge?.truncated, true, 'a cut write was shown as if it were whole');
      assert.equal(huge?.newText.length, MAX_CHANGE_CHARS);
      assert.equal((await readFile(join(dir, 'huge.txt'), 'utf8')).length, MAX_CHANGE_CHARS + 500, 'the whole content is still what is written');
    });
  });

  it('has no change to show for an edit that will be refused, and the card still appears', async () => {
    await withTempDir(async (directory) => {
      const { dir, cards, call } = await setup(directory);
      await writeFile(join(dir, 'a.txt'), 'one\n');
      await call('read_file', { path: 'a.txt' });
      const outcome = await call('edit_file', { path: 'a.txt', old_string: 'absent', new_string: 'x' });
      assert.equal(outcome.isError, true);
      assert.equal(cards.length, 1);
      assert.equal(cards[0]?.change, undefined);
    });
  });

  it('never builds a preview for a call the gate refuses, so it never reads a path the jail would stop', async () => {
    await withTempDir(async (directory) => {
      let previews = 0;
      const spy: ToolDefinition = {
        name: 'spy_write',
        description: 'test',
        parameters: { type: 'object', properties: { path: { type: 'string' } }, additionalProperties: true },
        effect: 'reversible',
        concurrencySafe: true,
        paths: (args) => [{ path: String(args['path']), write: true }],
        summary: () => 'spy',
        preview: async () => {
          previews += 1;
          return null;
        },
        execute: async () => ({ content: 'ran' }),
      };
      const { dir, cards, call } = await setup(directory, [spy]);
      await mkdir(join(dir, 'sub'));
      const outside = await call('spy_write', { path: '../outside.txt' });
      assert.equal(outside.isError, true);
      const secret = await call('spy_write', { path: '.env' });
      assert.equal(secret.isError, true);
      assert.equal(previews, 0, 'a preview was built for a refused call');
      assert.equal(cards.length, 0);
      await call('spy_write', { path: 'sub/ok.txt' });
      assert.equal(previews, 1);
    });
  });
});

describe('revealHidden', () => {
  it('writes hidden characters out and removes nothing', () => {
    assert.equal(revealHidden('a‮b​c\u0007d\u{e0041}'), 'a\\u{202e}b\\u{200b}c\\u{7}d\\u{e0041}');
    assert.equal(revealHidden('line\n\tindented\r\n'), 'line\n\tindented\r\n', 'newlines, tabs and carriage returns stay so a diff can be compared');
    assert.equal(revealHidden('naïve café 日本語'), 'naïve café 日本語', 'ordinary non-ASCII text is left alone');
  });
});
