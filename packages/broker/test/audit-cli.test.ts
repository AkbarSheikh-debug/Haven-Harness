import assert from 'node:assert/strict';
import { createPrivateKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { runPolicyTool } from '@hn/broker';
import { AuditChain, openAuditFile, signCheckpoint, type AuditEntry } from '@hn/security';
import { anchorVerdict, runAuditCommand, type AuditFlags, type TeamLogin } from '@hn/surfaces';
import { baseTree, startTeam, type Team } from './fixture.ts';

const tree = baseTree({ org: { version: 1, name: 'org', models: { allow: ['team-*'] }, approvers: { roles: ['lead'] }, audit: { readers: { roles: ['auditor'] } } } });

interface Setup {
  readonly team: Team;
  readonly work: string;
  /** Runs `hn audit ...` as the auditor, returning what it printed and its exit code. */
  run(args: readonly string[], flags?: AuditFlags, as?: string, extra?: { maxRows?: number; fetch?: typeof fetch }): Promise<{ code: number | null; text: string }>;
  write(type: string, data: Record<string, unknown>): Promise<void>;
  /** The files an operator hands an auditor. */
  keys(): Promise<{ hmac: string; pub: string }>;
}

async function saveLogin(home: string, team: Team, person: { loginToken: string; sid: string }, user: string): Promise<void> {
  await mkdir(home, { recursive: true });
  const login: TeamLogin = { url: team.broker.url, loginToken: person.loginToken, sid: person.sid, expires: Date.now() + 3600_000, identity: { user, ou: ['eng'], roles: [] }, policyKeys: {}, seen: null };
  await writeFile(join(home, 'team.json'), JSON.stringify(login));
}

async function withCli(body: (setup: Setup) => Promise<void>): Promise<void> {
  const team = await startTeam({ tree });
  const work = await mkdtemp(join(tmpdir(), 'hn-audit-cli-'));
  try {
    const sam = await team.login({ email: 'sam@example.com', department: 'eng', groups: ['auditor'] });
    const ana = await team.login({ email: 'ana@example.com', department: 'eng', groups: [] });
    await saveLogin(join(work, 'sam'), team, sam, 'sam@example.com');
    await saveLogin(join(work, 'ana'), team, ana, 'ana@example.com');
    await body({
      team,
      work,
      async run(args, flags = {}, as = 'sam', extra = {}) {
        let text = '';
        const code = await runAuditCommand({ positionals: ['audit', ...args], flags, home: join(work, as), out: (chunk) => void (text += chunk), ...extra });
        return { code, text };
      },
      async write(type, data) {
        team.broker.context.audit(type, data);
        await team.broker.audit.settle();
      },
      async keys() {
        await team.broker.audit.settle();
        const folder = join(work, 'handed-over');
        let said = '';
        assert.equal(await runPolicyTool(['broker', 'audit-key', join(team.dir, 'state'), folder], (chunk) => void (said += chunk)), 0);
        assert.match(said, /key id [0-9a-f]{16}/);
        return { hmac: join(folder, 'audit.key'), pub: join(folder, 'audit-public.pem') };
      },
    });
  } finally {
    await team.close();
    await rm(work, { recursive: true, force: true });
  }
}

describe('hn audit', () => {
  it('searches, lists approvals, sessions and anchors, and writes out what a row hides', async () => {
    await withCli(async ({ run, write, team }) => {
      await write('broker/approval-requested', { id: 'z1', user: 'ana@example.com', action: 'push main ‮evil\u001b]52;c;AAAA\u0007' });
      await write('broker/model', { user: 'ana@example.com', session: 's-1', model: 'team-large', usd: 0.01, tokens: 3 });
      const searched = await run(['search'], { type: 'broker/approval-' });
      assert.equal(searched.code, 0);
      assert.match(searched.text, /broker\/approval-requested/);
      // The bidi override and the terminal escape are written out, not sent to the terminal.
      assert.doesNotMatch(searched.text, /[‮\u001b\u0007]/);
      assert.match(searched.text, /\\u\{202e\}/);
      assert.match(searched.text, /\\u001b/, 'JSON already writes a control character out');
      const approvals = await run(['approvals']);
      assert.match(approvals.text, /z1 .*ana@example\.com asked: push main .*pending/);
      assert.doesNotMatch(approvals.text, /[‮\u001b\u0007]/);
      assert.match((await run(['sessions'], { user: 'ana@example.com' })).text, /ana@example\.com {2}s-1 .*1 model calls .*not anchored/);
      const asJson = JSON.parse((await run(['search'], { type: 'broker/model', json: true })).text) as { rows: AuditEntry[] };
      assert.equal(asJson.rows.length, 1);
      assert.match((await run(['anchors'])).text, /No anchors/);
      assert.equal(team.audit.filter((row) => row.type === 'broker/audit-read').length >= 5, true);
    });
  });

  it('tells someone who is not a reader that the broker will not show them', async () => {
    await withCli(async ({ run }) => {
      await assert.rejects(run(['search'], {}, 'ana'), /will not show you the audit/);
    });
  });

  it('exports a bundle and verifies it offline, and refuses each way of tampering with it, naming the row', async () => {
    await withCli(async ({ run, write, keys, work }) => {
      for (let i = 0; i < 4; i += 1) await write('broker/model', { user: 'ana@example.com', session: 's-1', model: 'team-large', usd: 0.01, tokens: i });
      const file = join(work, 'bundle.json');
      assert.match((await run(['export'], { out: file })).text, /Wrote rows 1 to \d+/);
      const { hmac, pub } = await keys();
      const check = async (path: string, extra: Partial<AuditFlags> = {}): Promise<{ code: number | null; text: string }> => run(['verify', path], { keyFile: hmac, pub, ...extra });
      const good = await check(file);
      assert.equal(good.code, 0, good.text);
      assert.match(good.text, /^VERIFIED: rows 1 to \d+/);

      const bundle = JSON.parse(await readFile(file, 'utf8')) as { rows: AuditEntry[]; count: number; to: number; checkpoints: unknown[] };
      const put = async (name: string, change: (copy: typeof bundle) => void): Promise<string> => {
        const copy = JSON.parse(JSON.stringify(bundle)) as typeof bundle;
        change(copy);
        const path = join(work, name);
        await writeFile(path, JSON.stringify(copy));
        return path;
      };
      const edited = await check(await put('edited.json', (copy) => void ((copy.rows[2] as AuditEntry & { data: Record<string, unknown> }).data['user'] = 'mallory')));
      assert.equal(edited.code, 1);
      assert.match(edited.text, /NOT VERIFIED \(row 3\)/);
      const removed = await check(await put('removed.json', (copy) => void copy.rows.splice(1, 1)));
      assert.equal(removed.code, 1);
      const cut = await check(await put('cut.json', (copy) => void ((copy.rows.length -= 2), (copy.count -= 2), (copy.to -= 2))));
      assert.equal(cut.code, 1);
      assert.match(cut.text, /cut off|No signed checkpoint/);
      const noChecks = await check(await put('nocheck.json', (copy) => void (copy.checkpoints.length = 0)));
      assert.equal(noChecks.code, 1);
      assert.match(noChecks.text, /No signed checkpoint covers/);

      const wrongKey = join(work, 'wrong.key');
      await writeFile(wrongKey, randomBytes(32));
      assert.equal((await check(file, { keyFile: wrongKey })).code, 1);
      const otherPub = join(work, 'other.pem');
      const { generateKeyPairSync } = await import('node:crypto');
      await writeFile(otherPub, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }));
      assert.equal((await check(file, { pub: otherPub })).code, 1);
      assert.match((await check(file, { pub: otherPub })).text, /not signed by the pinned/);
      await assert.rejects(check(join(work, 'missing.json')), /cannot be read/);
      await writeFile(join(work, 'junk.json'), 'not json');
      await assert.rejects(check(join(work, 'junk.json')), /not JSON/);
    });
  });

  it('refuses to call a filtered view verified', async () => {
    await withCli(async ({ run, keys, work, team }) => {
      await team.broker.audit.settle();
      const { hmac, pub } = await keys();
      const rows = (await team.broker.audit.store.read(1, team.broker.audit.store.head.n)).slice(0, 1);
      const view = join(work, 'view.json');
      await writeFile(view, JSON.stringify({ format: 1, kind: 'view', filter: { user: 'x' }, exportedAt: 'x', exportedBy: 'y', rows }));
      const result = await run(['verify', view], { keyFile: hmac, pub });
      assert.equal(result.code, 1);
      assert.match(result.text, /filtered view/);
    });
  });

  it('attack: audit_history_rewritten_after_pin audit_pinned_key_replaced - pins the broker key and its checkpoints, and later refuses a bundle that ends before a pinned checkpoint, a changed key, and a contradiction', async () => {
    await withCli(async ({ run, write, keys, work, team }) => {
      for (let i = 0; i < 3; i += 1) await write('broker/model', { user: 'ana@example.com', session: 's-1', model: 'm', usd: 0, tokens: 1 });
      const old = join(work, 'old.json');
      const exported = await run(['export'], { out: old, to: '3' });
      assert.equal(exported.code, 0, exported.text);
      for (let i = 0; i < 3; i += 1) await write('broker/model', { user: 'ana@example.com', session: 's-1', model: 'm', usd: 0, tokens: 1 });
      const folder = join(work, 'pins');
      const { hmac, pub } = await keys();
      const pinned = await run(['pin', folder], { pub });
      assert.equal(pinned.code, 0, pinned.text);
      assert.match(pinned.text, /matches the key you were given/);
      const again = await run(['pin', folder]);
      assert.match(again.text, /Pinned 1 new checkpoint|Pinned 0 new/);
      // The earlier, honest export is a good export on its own, and a stale one against what the auditor has pinned.
      assert.equal((await run(['verify', old], { keyFile: hmac, pub })).code, 0);
      const stale = await run(['verify', old], { keyFile: hmac, pub, pins: join(folder, 'pins.jsonl') });
      assert.equal(stale.code, 1);
      assert.match(stale.text, /cut off|out of date/);
      const fresh = join(work, 'fresh.json');
      await run(['export'], { out: fresh });
      assert.equal((await run(['verify', fresh], { keyFile: hmac, pub, pins: join(folder, 'pins.jsonl') })).code, 0);

      // Not the key the operator gave.
      const wrong = join(work, 'wrong.pem');
      const { generateKeyPairSync } = await import('node:crypto');
      await writeFile(wrong, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }));
      await assert.rejects(run(['pin', join(work, 'pins2')], { pub: wrong }), /different audit-signing key/);
      // A pinned key that is not the broker's now.
      await writeFile(join(folder, 'audit-public.pem'), await readFile(wrong));
      await assert.rejects(run(['pin', folder]), /not the one already pinned/);
      void team;
    });
  });

  it('refuses to pin a checkpoint its own key did not sign, and a head that contradicts one already pinned', async () => {
    await withCli(async ({ run, write, work, team, keys }) => {
      for (let i = 0; i < 3; i += 1) await write('broker/model', { user: 'ana@example.com', session: 's-1', model: 'm', usd: 0, tokens: 1 });
      const { pub } = await keys();
      const folder = join(work, 'pins');
      assert.equal((await run(['pin', folder], { pub })).code, 0);
      const pinned = (await readFile(join(folder, 'pins.jsonl'), 'utf8')).split(/\r?\n/).map((line) => line.trim()).filter((line) => line !== '').map((line) => JSON.parse(line) as { n: number });
      const last = pinned[pinned.length - 1] as { n: number };
      const brokerKey = createPrivateKey(await readFile(join(team.dir, 'state', 'audit-sign.key')));
      const broker = await readFile(pub, 'utf8');
      // A fetch that answers the checkpoint list with something the broker's own key signed for a different head of a pinned row.
      const lying = (checkpoints: unknown[]): typeof fetch => (async (input, init) => {
        const url = String(input);
        if (!url.endsWith('/v1/audit/checkpoints')) return fetch(input, init);
        return new Response(JSON.stringify({ keyId: 'x', publicKey: broker, checkpoints }), { status: 200, headers: { 'content-type': 'application/json' } });
      }) as typeof fetch;
      const contradicting = signCheckpoint({ n: last.n, mac: 'b'.repeat(64) }, new Date().toISOString(), brokerKey);
      await assert.rejects(run(['pin', folder], {}, 'sam', { fetch: lying([contradicting]) }), /different head for row/);
      // A checkpoint signed by some other key, offered as the broker's.
      const other = signCheckpoint({ n: last.n + 5, mac: 'c'.repeat(64) }, new Date().toISOString(), generateKeyPairSync('ed25519').privateKey);
      await assert.rejects(run(['pin', folder], {}, 'sam', { fetch: lying([other]) }), /did not sign/);
      // Neither left anything behind.
      assert.equal((await readFile(join(folder, 'pins.jsonl'), 'utf8')).includes('bbbbbbbb'), false);
    });
  });

  it('attack: laptop_audit_cut_tail_found_against_anchor - compares a laptop session audit with the head the broker anchored', async () => {
    await withCli(async ({ run, team, work }) => {
      const ana = await team.login({ email: 'ana@example.com', department: 'eng', groups: [] });
      const token = await ana.session('s-7');
      const key = randomBytes(32);
      const path = join(work, 's-7.jsonl');
      const file = await openAuditFile(path, key);
      const rows: AuditEntry[] = [];
      for (let n = 1; n <= 5; n += 1) rows.push(await file.record('audit/decision', { n }));
      const anchorAt = async (n: number): Promise<void> => void (await team.raw('/v1/audit/anchor', { token, session: 's-7', body: { n, mac: (rows[n - 1] as AuditEntry).mac } }));
      const keyFile = join(work, 'log.key');
      await writeFile(keyFile, key);
      const check = (): Promise<{ code: number | null; text: string }> => run(['check-session', path], { user: 'ana@example.com', keyFile });

      assert.match((await check()).text, /^UNKNOWN/, 'the broker never heard of it');
      await anchorAt(5);
      const same = await check();
      assert.equal(same.code, 0);
      assert.match(same.text, /^MATCH/);
      await anchorAt(5);
      await file.record('audit/decision', { n: 6 });
      const ahead = await check();
      assert.equal(ahead.code, 0);
      assert.match(ahead.text, /^AHEAD: .*1 more row/);
      // The last rows are cut from the laptop's file: it is behind what the broker saw.
      const lines = (await readFile(path, 'utf8')).split('\n').filter((line) => line !== '');
      await writeFile(path, `${lines.slice(0, 3).join('\n')}\n`);
      const behind = await check();
      assert.equal(behind.code, 1);
      assert.match(behind.text, /^BEHIND: .*2 rows were removed/);
      // A file made by someone else with the same number of rows is not the session the broker saw.
      const forged = new AuditChain({ key });
      await writeFile(path, `${Array.from({ length: 5 }, (_, index) => JSON.stringify(forged.append('audit/decision', { n: index + 1, forged: true }))).join('\n')}\n`);
      const differs = await check();
      assert.equal(differs.code, 1);
      assert.match(differs.text, /^DIFFERS/);
      // A file that does not verify with the key.
      const wrongKey = join(work, 'wrong.key');
      await writeFile(wrongKey, randomBytes(32));
      const refused = await run(['check-session', path], { user: 'ana@example.com', keyFile: wrongKey });
      assert.equal(refused.code, 1);
      assert.match(refused.text, /^REFUSED/);
      await assert.rejects(run(['check-session', path], { user: 'ana@example.com', keyFile, session: '../x' }), /session id/);
    });
  });

  it('decides each anchor case on its own, so no case can pass for another', () => {
    const entries = Array.from({ length: 4 }, (_, index) => ({ n: index + 1, mac: `m${index + 1}` })) as unknown as AuditEntry[];
    const states = [
      anchorVerdict(true, entries, 4, { n: 4, mac: 'm4' }).state,
      anchorVerdict(true, entries, 4, { n: 3, mac: 'm3' }).state,
      anchorVerdict(true, entries, 4, { n: 5, mac: 'm5' }).state,
      anchorVerdict(true, entries, 4, { n: 4, mac: 'other' }).state,
      anchorVerdict(true, entries, 4, null).state,
      anchorVerdict(false, entries, 4, { n: 4, mac: 'm4' }).state,
    ];
    assert.deepEqual(states, ['match', 'ahead', 'behind', 'differs', 'unknown', 'refused']);
  });

  it('follows the audit live from the command line, rows written as they come', async () => {
    await withCli(async ({ run, write, team }) => {
      await team.broker.audit.settle();
      const first = team.broker.audit.store.head.n;
      const following = run(['tail'], { from: String(first) }, 'sam', { maxRows: 3 });
      // The follower's own read is the first row; then what is written while it listens.
      await new Promise((resolve) => setTimeout(resolve, 100));
      await write('broker/login', { user: 'live-1' });
      await write('broker/login', { user: 'live-2' });
      const done = await following;
      assert.equal(done.code, 0);
      const lines = done.text.split(/\r?\n/).filter((line) => line !== '');
      assert.equal(lines.length, 3);
      assert.match(lines[0] ?? '', new RegExp(`^#${first + 1} .*broker/audit-read`));
      assert.match(lines[1] ?? '', /live-1/);
      assert.match(lines[2] ?? '', /live-2/);
    });
  });
});
