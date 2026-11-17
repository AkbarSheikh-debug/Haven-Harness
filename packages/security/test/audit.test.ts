import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { withTempDir } from '@hn/testkit';
import { AuditChain, AuditError, GENESIS, openAuditFile, verifyAudit } from '@hn/security';

const KEY = Buffer.from('k'.repeat(32));
const clock = (): (() => Date) => {
  let tick = 0;
  return () => new Date(Date.UTC(2026, 10, 4, 0, 0, (tick += 1)));
};

function sample(): string {
  const chain = new AuditChain({ key: KEY, now: clock() });
  const rows = [
    chain.append('approval/asked', { approvalId: 'a1', tool: 'bash' }),
    chain.append('approval/decided', { approvalId: 'a1', answer: 'once' }),
    chain.append('audit/decision', { callId: 'c1', decision: 'allowed-once' }),
    chain.append('audit/decision', { callId: 'c2', decision: 'rejected' }),
  ];
  return `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;
}

const rows = (text: string): string[] => text.split('\n').filter((line) => line !== '');

describe('the audit chain', () => {
  it('verifies an untouched log and reports its head', () => {
    const result = verifyAudit(sample(), KEY);
    assert.equal(result.ok, true);
    assert.equal(result.entries.length, 4);
    assert.equal(result.head.n, 4);
    assert.notEqual(result.head.mac, GENESIS);
  });

  it('verifies an empty log', () => {
    assert.equal(verifyAudit('', KEY).ok, true);
  });

  it('breaks when any field of a row is edited', () => {
    const original = rows(sample());
    const edits: ((row: Record<string, unknown>) => void)[] = [
      (row) => (row['type'] = 'audit/decision'),
      (row) => (row['ts'] = '2030-01-01T00:00:00.000Z'),
      (row) => ((row['data'] as Record<string, unknown>)['answer'] = 'session'),
    ];
    for (const edit of edits) {
      const row = JSON.parse(original[1] as string) as Record<string, unknown>;
      edit(row);
      const tampered = [original[0], JSON.stringify(row), original[2], original[3]].join('\n');
      const result = verifyAudit(tampered, KEY);
      assert.equal(result.ok, false);
      assert.equal(result.brokenAt, 2);
    }
  });

  it('breaks when a row is removed, duplicated or reordered', () => {
    const original = rows(sample());
    const cases: Record<string, string[]> = {
      removed: [original[0], original[2], original[3]] as string[],
      duplicated: [original[0], original[1], original[1], original[2]] as string[],
      reordered: [original[0], original[2], original[1], original[3]] as string[],
    };
    for (const [name, lines] of Object.entries(cases)) assert.equal(verifyAudit(lines.join('\n'), KEY).ok, false, name);
  });

  it('breaks under the wrong key, so a forger without the key is caught', () => {
    const forger = new AuditChain({ key: Buffer.from('x'.repeat(32)), now: clock() });
    const forged = JSON.stringify(forger.append('audit/decision', { decision: 'allowed-once' }));
    assert.equal(verifyAudit(forged, KEY).ok, false);
  });

  it('rejects rows with unknown fields or bad JSON', () => {
    const row = JSON.parse(rows(sample())[0] as string) as Record<string, unknown>;
    assert.equal(verifyAudit(JSON.stringify({ ...row, extra: 1 }), KEY).ok, false);
    assert.equal(verifyAudit('not json', KEY).ok, false);
  });

  it('is not changed by key order inside data', () => {
    const a = new AuditChain({ key: KEY, now: clock() }).append('audit/decision', { x: 1, y: 2 });
    const b = new AuditChain({ key: KEY, now: clock() }).append('audit/decision', { y: 2, x: 1 });
    assert.equal(a.mac, b.mac);
  });

  it('detects a cut-off tail only against an anchored head', () => {
    const full = verifyAudit(sample(), KEY);
    const cut = `${rows(sample()).slice(0, 3).join('\n')}\n`;
    assert.equal(verifyAudit(cut, KEY).ok, true, 'without an anchor a short log looks complete');
    const anchored = verifyAudit(cut, KEY, full.head);
    assert.equal(anchored.ok, false);
    assert.match(anchored.reason ?? '', /cut off/);
  });
});

describe('paired approval ids', () => {
  it('refuses a decision that was never asked, an ask twice, and a decision twice', () => {
    const chain = new AuditChain({ key: KEY });
    assert.throws(() => chain.append('approval/decided', { approvalId: 'nope' }), AuditError);
    chain.append('approval/asked', { approvalId: 'a' });
    assert.throws(() => chain.append('approval/asked', { approvalId: 'a' }), AuditError);
    chain.append('approval/decided', { approvalId: 'a' });
    assert.throws(() => chain.append('approval/decided', { approvalId: 'a' }), AuditError);
    assert.throws(() => chain.append('approval/asked', {}), AuditError);
  });

  it('lists asks that were never decided', () => {
    const chain = new AuditChain({ key: KEY });
    chain.append('approval/asked', { approvalId: 'open' });
    assert.deepEqual(chain.openApprovals, ['open']);
  });

  it('reports an ask with no decision when a log is verified', () => {
    const chain = new AuditChain({ key: KEY });
    const text = `${JSON.stringify(chain.append('approval/asked', { approvalId: 'open' }))}\n`;
    const result = verifyAudit(text, KEY);
    assert.equal(result.ok, true);
    assert.deepEqual(result.openApprovals, ['open']);
  });
});

describe('the audit file', () => {
  it('writes rows that verify, and resumes after a restart', async () => {
    await withTempDir(async (dir) => {
      const path = join(dir, 'audit', 'chain.jsonl');
      const first = await openAuditFile(path, KEY);
      await first.record('approval/asked', { approvalId: 'a' });
      const second = await openAuditFile(path, KEY);
      await second.record('approval/decided', { approvalId: 'a', answer: 'deny' });
      const result = verifyAudit(await readFile(path, 'utf8'), KEY);
      assert.equal(result.ok, true);
      assert.equal(result.entries.length, 2);
    });
  });

  it('keeps enforcing pairing after a restart', async () => {
    await withTempDir(async (dir) => {
      const path = join(dir, 'chain.jsonl');
      await (await openAuditFile(path, KEY)).record('approval/asked', { approvalId: 'a' });
      const reopened = await openAuditFile(path, KEY);
      assert.deepEqual(reopened.chain.openApprovals, ['a']);
      assert.throws(() => reopened.chain.append('approval/asked', { approvalId: 'a' }), AuditError);
    });
  });

  it('refuses to open a tampered file instead of repairing it', async () => {
    await withTempDir(async (dir) => {
      const path = join(dir, 'chain.jsonl');
      await writeFile(path, sample().replace('"bash"', '"ls"'));
      await assert.rejects(openAuditFile(path, KEY), /failed verification/);
    });
  });

  it('writes concurrent rows in order', async () => {
    await withTempDir(async (dir) => {
      const path = join(dir, 'chain.jsonl');
      const file = await openAuditFile(path, KEY);
      await Promise.all(Array.from({ length: 25 }, (_, i) => file.record('audit/decision', { i })));
      const result = verifyAudit(await readFile(path, 'utf8'), KEY);
      assert.equal(result.ok, true);
      assert.deepEqual(
        result.entries.map((entry) => entry.data['i']),
        Array.from({ length: 25 }, (_, i) => i),
      );
    });
  });
});
