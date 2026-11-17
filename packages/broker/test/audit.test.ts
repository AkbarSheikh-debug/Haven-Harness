import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { entriesFromOtlp } from '@hn/broker';
import { createBrokerProvider } from '@hn/provider';
import { openAuditFile, verifyAudit } from '@hn/security';
import { anchoredAudit, type TeamLogin } from '@hn/surfaces';
import { startTeam } from './fixture.ts';

const ANA = { email: 'ana@example.com', department: 'eng', groups: [] };
const request = { model: 'team-large', system: 's', tools: [], messages: [{ role: 'user' as const, parts: [{ type: 'text' as const, text: 'hi' }] }], maxOutputTokens: 64 };

async function collector(): Promise<{ url: string; records: Record<string, unknown>[]; headers: IncomingHttpHeaders[]; close(): Promise<void> }> {
  const records: Record<string, unknown>[] = [];
  const headers: IncomingHttpHeaders[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      headers.push(req.headers);
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { resourceLogs: { scopeLogs: { logRecords: Record<string, unknown>[] }[] }[] };
      for (const resource of body.resourceLogs) for (const scope of resource.scopeLogs) records.push(...scope.logRecords);
      res.writeHead(200).end('{}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, records, headers, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

const lines = (entries: readonly unknown[]): string => entries.map((entry) => JSON.stringify(entry)).join('\n');

describe('the broker audit', () => {
  it('chains every decision on the broker, and an edited row is caught', async () => {
    const team = await startTeam();
    try {
      const ana = await team.login(ANA);
      const token = await ana.session('a-1');
      await createBrokerProvider({ url: team.broker.url, token: () => token, session: 'a-1' }).complete(request);
      await team.broker.audit.flush();
      const text = await readFile(team.broker.audit.path, 'utf8');
      const verified = verifyAudit(text, team.broker.audit.key);
      assert.equal(verified.ok, true, verified.reason ?? '');
      assert.deepEqual(verified.entries.map((entry) => entry.type), ['broker/login', 'broker/session', 'broker/model']);
      const edited = text.replace('"user":"ana@example.com"', '"user":"someone-else"');
      assert.equal(verifyAudit(edited, team.broker.audit.key).ok, false);
    } finally {
      await team.close();
    }
  });

  it('ships rows to a SIEM over OTLP, and the shipped copy can be checked and a tampered one is caught', async () => {
    const siem = await collector();
    const team = await startTeam({ audit: { otlp: { url: siem.url, headers: { Authorization: 'SIEM_TOKEN' } } }, env: { SIEM_TOKEN: 'Bearer siem-secret' } });
    try {
      const ana = await team.login(ANA);
      await ana.session('a-2');
      await team.broker.audit.flush();
      assert.equal(siem.records.length, 2);
      assert.equal(siem.headers[0]?.['authorization'], 'Bearer siem-secret');
      const shipped = entriesFromOtlp(siem.records);
      assert.equal(verifyAudit(lines(shipped), team.broker.audit.key).ok, true);
      const tampered = shipped.map((entry, index) => (index === 1 ? { ...entry, data: { ...entry.data, user: 'mallory' } } : entry));
      assert.equal(verifyAudit(lines(tampered), team.broker.audit.key).ok, false);
      assert.equal(verifyAudit(lines(shipped.slice(1)), team.broker.audit.key).ok, false, 'a dropped row breaks the chain');
    } finally {
      await team.close();
      await siem.close();
    }
  });

  it('anchors a session head, so a cut tail on the laptop is caught, and refuses an anchor that goes back', async () => {
    const team = await startTeam();
    try {
      const ana = await team.login(ANA);
      const login: TeamLogin = { url: team.broker.url, loginToken: ana.loginToken, sid: ana.sid, expires: Date.now() + 3600_000, identity: { user: 'ana@example.com', ou: ['eng'], roles: [] }, policyKeys: {}, seen: null };
      const key = randomBytes(32);
      const path = join(team.dir, 'laptop-audit.jsonl');
      const file = anchoredAudit(await openAuditFile(path, key), login, 'a-3');
      for (const n of [1, 2, 3]) await file.record('audit/decision', { n });
      // The anchor is sent after the write; wait for it to land.
      let anchored = { n: 0, mac: '' };
      const token = await ana.session('a-3');
      for (let tries = 0; tries < 50 && anchored.n < 3; tries += 1) {
        anchored = (await (await team.raw('/v1/audit/anchor', { token, session: 'a-3' })).json()) as { n: number; mac: string };
        if (anchored.n < 3) await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.equal(anchored.n, 3);
      const whole = await readFile(path, 'utf8');
      assert.equal(verifyAudit(whole, key, anchored).ok, true);
      const cut = whole.split('\n').slice(0, 2).join('\n');
      await writeFile(path, cut);
      const check = verifyAudit(await readFile(path, 'utf8'), key, anchored);
      assert.equal(check.ok, false);
      assert.match(check.reason ?? '', /cut off/);
      const back = await team.raw('/v1/audit/anchor', { token, session: 'a-3', body: { n: 2, mac: 'a'.repeat(64) } });
      assert.equal(back.status, 409);
      const changed = await team.raw('/v1/audit/anchor', { token, session: 'a-3', body: { n: 3, mac: 'b'.repeat(64) } });
      assert.equal(changed.status, 409);
    } finally {
      await team.close();
    }
  });
});
