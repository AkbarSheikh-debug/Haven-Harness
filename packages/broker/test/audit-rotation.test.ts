import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { runPolicyTool } from '@hn/broker';
import { auditKeyId } from '@hn/security';
import { runAuditCommand, runTrustCommand, type AuditFlags, type TeamLogin } from '@hn/surfaces';
import { baseTree, startTeam, type Team } from './fixture.ts';

/** The audit-signing key rotates and is revoked on a real broker, and an auditor follows it with only the root (Phase 15, task 6). */

const tree = baseTree({ org: { version: 1, name: 'org', models: { allow: ['team-*'] }, approvers: { roles: ['lead'] }, audit: { readers: { roles: ['auditor'] } } } });

async function saveLogin(home: string, team: Team, person: { loginToken: string; sid: string }): Promise<void> {
  await mkdir(home, { recursive: true });
  const login: TeamLogin = { url: team.broker.url, loginToken: person.loginToken, sid: person.sid, expires: Date.now() + 3600_000, identity: { user: 'sam@example.com', ou: ['eng'], roles: [] }, policyKeys: {}, seen: null };
  await writeFile(join(home, 'team.json'), JSON.stringify(login));
}

async function audit(work: string, args: readonly string[], flags: AuditFlags = {}): Promise<{ code: number | null; text: string }> {
  let text = '';
  const code = await runAuditCommand({ positionals: ['audit', ...args], flags, home: join(work, 'sam'), out: (chunk) => void (text += chunk) });
  return { code, text };
}

async function trust(...rest: string[]): Promise<string> {
  let text = '';
  await runTrustCommand({ positionals: ['trust', ...rest], env: {}, out: (chunk) => void (text += chunk) });
  return text;
}

const rowsOf = async (team: Team, count: number, from = 0): Promise<void> => {
  for (let index = 0; index < count; index += 1) team.broker.context.audit('broker/model', { user: 'ana@example.com', session: `s-${from + index}`, model: 'team-large', usd: 0.01, tokens: 3 });
  await team.broker.audit.settle();
};

async function auditor(team: Team, work: string): Promise<void> {
  const sam = await team.login({ email: 'sam@example.com', department: 'eng', groups: ['auditor'] });
  await saveLogin(join(work, 'sam'), team, sam);
}

describe('rotating the audit-signing key on a real broker', () => {
  it('attack: audit_roster_stale_in_bundle - an auditor who pinned only the root follows a rotation and a revocation, and an old roster inside a bundle does not undo it', { timeout: 120_000 }, async () => {
    let team = await startTeam({ tree });
    const work = await mkdtemp(join(tmpdir(), 'hn-audit-rot-'));
    const dir = team.dir;
    const state = join(dir, 'state');
    try {
      await auditor(team, work);
      await rowsOf(team, 4);
      await trust('keygen-root', join(work, 'root'));
      const rootKey = join(work, 'root', 'root-key.pem');
      const rootPub = join(work, 'root', 'root-public.pem');

      // Nothing to follow until the operator has signed a roster.
      const hand = join(work, 'handed');
      assert.equal(await runPolicyTool(['broker', 'audit-key', state, hand], () => undefined), 0);
      const hmacFile = join(hand, 'audit.key');
      const firstPem = await readFile(join(hand, 'audit-public.pem'), 'utf8');
      const folder = join(work, 'pins');
      await assert.rejects(audit(work, ['pin', folder], { root: rootPub }), /no signed audit roster/);
      const firstId = auditKeyId(createPublicKey(firstPem));
      await writeFile(join(work, 'draft1.json'), JSON.stringify({ purpose: 'audit', serial: 1, keys: [{ keyId: firstId, publicKey: firstPem, fromRow: 0 }] }));
      await trust('sign', join(work, 'draft1.json'), rootKey, 'root-1', join(state, 'audit-roster.json'));
      const pinned = await audit(work, ['pin', folder], { root: rootPub });
      assert.match(pinned.text, /Following the roster signed by the root you pinned \(serial 1, 1 audit key\)/);
      const before = join(work, 'before.json');
      await audit(work, ['export', '--out', before], { out: before });
      assert.match((await audit(work, ['verify', before], { keyFile: hmacFile, trust: folder })).text, /^VERIFIED/);

      // A root the auditor did not pin cannot move them.
      await trust('keygen-root', join(work, 'root-b'));
      await assert.rejects(audit(work, ['pin', join(work, 'pins')], { root: join(work, 'root-b', 'root-public.pem') }), /not the one already pinned/);

      // Rotation, with the broker stopped. The old key keeps a copy here only to play a thief later.
      const oldPrivate = await readFile(join(state, 'audit-sign.key'));
      await team.close(true);
      let said = '';
      assert.equal(await runPolicyTool(['broker', 'rotate-audit-key', state, join(work, 'draft')], (chunk) => void (said += chunk)), 0);
      assert.match(said, new RegExp(`Retired audit-signing key ${firstId} at row \\d+`));
      assert.notDeepEqual(await readFile(join(state, 'audit-sign.key')), oldPrivate, 'the old private key is gone from the state folder');
      const draft = JSON.parse(await readFile(join(work, 'draft', 'audit-roster-draft.json'), 'utf8')) as { serial: number; keys: { keyId: string; fromRow: number; toRow?: number }[] };
      assert.equal(draft.serial, 2);
      assert.equal(draft.keys.length, 2);
      const boundary = draft.keys[0]?.toRow as number;
      assert.equal(draft.keys[1]?.fromRow, boundary + 1);
      await trust('sign', join(work, 'draft', 'audit-roster-draft.json'), rootKey, 'root-1', join(state, 'audit-roster.json'));
      assert.match(said, /hn trust sign/);

      team = await startTeam({ tree, dir });
      await auditor(team, work);
      await rowsOf(team, 3, 10);
      const followed = await audit(work, ['pin', folder]);
      assert.match(followed.text, /serial 2, 2 audit keys/);
      const across = join(work, 'across.json');
      await audit(work, ['export', '--out', across], { out: across });
      const verified = await audit(work, ['verify', across], { keyFile: hmacFile, trust: folder });
      assert.match(verified.text, /^VERIFIED: rows 1 to \d+/);
      const bundle = JSON.parse(await readFile(across, 'utf8')) as { from: number; to: number; roster: unknown };
      assert.ok(bundle.roster !== undefined && bundle.roster !== null, 'the export carries the roster');
      assert.ok(bundle.to > boundary, 'the export spans the rotation');

      // An export that ends in the old era ends at the old key's last word. It is checked without the pins kept since, which are for later rows.
      await writeFile(join(work, 'nopins.jsonl'), '');
      const old = join(work, 'old.json');
      await audit(work, ['export', '--out', old], { out: old, to: String(boundary) });
      assert.match((await audit(work, ['verify', old], { keyFile: hmacFile, trust: folder, pins: join(work, 'nopins.jsonl') })).text, /^VERIFIED/);
      // Where the old key left no checkpoint, nothing new can be signed for it, so the broker says where to end instead.
      let refusedAt = 0;
      for (let n = boundary - 1; n >= 1 && refusedAt === 0; n -= 1) {
        await audit(work, ['export', '--out', join(work, 'x.json')], { out: join(work, 'x.json'), to: String(n) }).catch((error: unknown) => {
          if (/retired audit-signing key/.test(String(error))) refusedAt = n;
        });
      }
      assert.ok(refusedAt > 0, 'some row in the old era has no checkpoint, and the broker refuses to sign one');

      // The thief has the old key and the audit key. Extending the chain and signing with the old key gets nowhere.
      const { AuditChain, signCheckpoint } = await import('@hn/security');
      const hmac = await readFile(hmacFile);
      const rows = bundle as unknown as { rows: { n: number; mac: string }[] };
      const last = rows.rows[rows.rows.length - 1] as { n: number; mac: string };
      const forger = new AuditChain({ key: hmac, head: { n: last.n, mac: last.mac }, now: () => new Date() });
      const extra = forger.append('broker/approval-decided', { id: 'z', approver: 'mallory', decision: 'approve' });
      const { createPrivateKey } = await import('node:crypto');
      const stolen = signCheckpoint(extra, new Date().toISOString(), createPrivateKey(oldPrivate));
      const forged = { ...bundle, rows: [...rows.rows, extra], to: extra.n, count: rows.rows.length + 1, checkpoints: [stolen] };
      await writeFile(join(work, 'forged.json'), JSON.stringify(forged));
      const refused = await audit(work, ['verify', join(work, 'forged.json')], { keyFile: hmacFile, trust: folder });
      assert.equal(refused.code, 1);
      assert.match(refused.text, /NOT VERIFIED.*only for rows 0 to \d+/);

      // The owner revokes the old key from a row before it retired. Its last word is no longer believed.
      const cut = Math.max(1, boundary - 2);
      await writeFile(join(work, 'draft3.json'), JSON.stringify({ purpose: 'audit', serial: 3, keys: draft.keys.map((item, index) => ({ ...item, publicKey: index === 0 ? firstPem : undefined })), revoked: [{ keyId: firstId, reason: 'leaked', afterRow: cut }] }));
      const second = draft.keys[1] as { keyId: string };
      const secondPem = (await readFile(join(state, 'audit-sign.pub.pem'), 'utf8')).toString();
      assert.equal(auditKeyId(createPublicKey(secondPem)), second.keyId);
      await writeFile(join(work, 'draft3.json'), JSON.stringify({ purpose: 'audit', serial: 3, keys: [{ keyId: firstId, publicKey: firstPem, fromRow: 0, toRow: boundary }, { keyId: second.keyId, publicKey: secondPem, fromRow: boundary + 1 }], revoked: [{ keyId: firstId, reason: 'leaked', afterRow: cut }] }));
      await trust('sign', join(work, 'draft3.json'), rootKey, 'root-1', join(state, 'audit-roster.json'));
      const revokedPin = await audit(work, ['pin', folder]);
      assert.match(revokedPin.text, /serial 3/);
      assert.match(revokedPin.text, /Set aside \d+ signed by a key after its cut-off/);
      const afterRevoke = await audit(work, ['verify', old], { keyFile: hmacFile, trust: folder, pins: join(work, 'nopins.jsonl') });
      assert.equal(afterRevoke.code, 1, 'the old era export ended at the leaked key\'s last word');
      assert.match(afterRevoke.text, /only for rows 0 to /);
      const stillGood = join(work, 'good.json');
      await audit(work, ['export', '--out', stillGood], { out: stillGood });
      assert.match((await audit(work, ['verify', stillGood], { keyFile: hmacFile, trust: folder })).text, /^VERIFIED/);

      // An older roster cannot be put back: not by the broker, and not inside a bundle.
      const older = JSON.parse(await readFile(join(state, 'audit-roster.json'), 'utf8')) as unknown;
      void older;
      await writeFile(join(work, 'draft-old.json'), JSON.stringify({ purpose: 'audit', serial: 2, keys: [{ keyId: firstId, publicKey: firstPem, fromRow: 0, toRow: boundary }, { keyId: second.keyId, publicKey: secondPem, fromRow: boundary + 1 }], revoked: [] }));
      await trust('sign', join(work, 'draft-old.json'), rootKey, 'root-1', join(work, 'roster-old.json'));
      await writeFile(join(state, 'audit-roster.json'), await readFile(join(work, 'roster-old.json')));
      await assert.rejects(audit(work, ['pin', folder]), /older than serial 3/);
      const replay = { ...JSON.parse(await readFile(old, 'utf8')) as Record<string, unknown>, roster: JSON.parse(await readFile(join(work, 'roster-old.json'), 'utf8')) as unknown };
      await writeFile(join(work, 'replay.json'), JSON.stringify(replay));
      const stale = await audit(work, ['verify', join(work, 'replay.json')], { keyFile: hmacFile, trust: folder, pins: join(work, 'nopins.jsonl') });
      assert.equal(stale.code, 1, 'a stale roster in the bundle does not un-revoke the key');
      // A roster in the bundle that the pinned root never signed is refused, not quietly ignored.
      await trust('keygen-root', join(work, 'root-c'));
      await writeFile(join(work, 'draft-c.json'), JSON.stringify({ purpose: 'audit', serial: 9, keys: [{ keyId: firstId, publicKey: firstPem, fromRow: 0 }] }));
      await trust('sign', join(work, 'draft-c.json'), join(work, 'root-c', 'root-key.pem'), 'root-c', join(work, 'roster-c.json'));
      await writeFile(join(work, 'foreign.json'), JSON.stringify({ ...(JSON.parse(await readFile(old, 'utf8')) as Record<string, unknown>), roster: JSON.parse(await readFile(join(work, 'roster-c.json'), 'utf8')) as unknown }));
      await assert.rejects(audit(work, ['verify', join(work, 'foreign.json')], { keyFile: hmacFile, trust: folder, pins: join(work, 'nopins.jsonl') }), /roster in the bundle was refused/);
    } finally {
      await team.close();
      await rm(work, { recursive: true, force: true });
    }
  });

  it('refuses to rotate when nothing new was signed, and a retired-key list that was edited', { timeout: 60_000 }, async () => {
    const team = await startTeam({ tree });
    const work = await mkdtemp(join(tmpdir(), 'hn-audit-rot2-'));
    const state = join(team.dir, 'state');
    try {
      await rowsOf(team, 2);
      await team.close(true);
      assert.equal(await runPolicyTool(['broker', 'rotate-audit-key', state, join(work, 'd1')], () => undefined), 0);
      await assert.rejects(runPolicyTool(['broker', 'rotate-audit-key', state, join(work, 'd2')], () => undefined), /signed nothing since the last rotation/);
      // Someone edits the list of retired keys so an old key can sign past its cut-off: the broker will not start.
      const path = join(state, 'audit-retired.json');
      const list = JSON.parse(await readFile(path, 'utf8')) as { keyId: string; publicKey: string; toRow: number }[];
      await writeFile(path, JSON.stringify([{ ...list[0], keyId: 'deadbeefdeadbeef' }]));
      await assert.rejects(startTeam({ tree, dir: team.dir }), /names a key id that is not its public key's/);
      // Or lowers the row an old key was retired at, so its own last checkpoint now looks like one signed after retirement.
      await writeFile(path, JSON.stringify([{ ...list[0], toRow: Math.max(0, (list[0]?.toRow ?? 1) - 1) }]));
      await assert.rejects(startTeam({ tree, dir: team.dir }), /signed after its retirement/);
    } finally {
      await rm(team.dir, { recursive: true, force: true });
      await rm(work, { recursive: true, force: true });
    }
  });
});
