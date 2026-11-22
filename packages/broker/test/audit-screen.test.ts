import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { MAX_TAIL_SUBSCRIBERS, runPolicyTool } from '@hn/broker';
import { verifyBundle } from '@hn/security';
import { startAuditServe, type Served, type TeamLogin } from '@hn/surfaces';
import { baseTree, startTeam, type Person, type Team } from './fixture.ts';
import { Browser, findBrowser } from '../../surfaces/test/browser-fixture.ts';

/** A reflected-looking action: markup, a script, a terminal escape and a right-to-left override, as an approval request could carry. */
const HOSTILE = 'push main <img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script> ‮evil\u001b]52;c;AAAA\u0007';

const tree = baseTree({ org: { version: 1, name: 'org', models: { allow: ['team-*'] }, approvers: { roles: ['lead'] }, audit: { readers: { roles: ['auditor'] } } } });
const browserPath = findBrowser();
const required = process.env['HN_REQUIRE_BROWSER'] === '1';

interface Reply {
  readonly status: number;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: string;
}

function call(port: number, method: string, path: string, headers: Record<string, string> = {}, body = ''): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers: { host: `127.0.0.1:${port}`, ...headers, 'content-length': String(Buffer.byteLength(body)) } }, (res) => {
      let text = '';
      res.setEncoding('utf8').on('data', (chunk: string) => (text += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: text }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function cookieFor(served: Served): Promise<string> {
  const reply = await call(served.port, 'POST', '/login', { origin: `http://127.0.0.1:${served.port}`, 'content-type': 'application/x-www-form-urlencoded' }, `token=${served.token}`);
  assert.equal(reply.status, 303);
  const cookie = /hn_session=[0-9a-f]{64}/.exec(String(reply.headers['set-cookie']))?.[0];
  assert.ok(cookie !== undefined);
  return cookie;
}

async function saveLogin(home: string, team: Team, person: Person, user: string): Promise<void> {
  await mkdir(home, { recursive: true });
  const login: TeamLogin = { url: team.broker.url, loginToken: person.loginToken, sid: person.sid, expires: Date.now() + 3600_000, identity: { user, ou: ['eng'], roles: [] }, policyKeys: {}, seen: null };
  await writeFile(join(home, 'team.json'), JSON.stringify(login));
}

interface Setup {
  readonly team: Team;
  readonly work: string;
  readonly sam: Person;
  readonly keys: { hmac: string; pub: string };
  /** The screen for the auditor (or for `as`), with the cookie of a person who has typed the token in. */
  screen(extra?: { as?: string; pub?: string | null; hmac?: string | null }): Promise<{ served: Served; cookie: string; get(path: string, headers?: Record<string, string>): Promise<Reply> }>;
  write(type: string, data: Record<string, unknown>): Promise<void>;
}

async function withScreen(body: (setup: Setup) => Promise<void>, now?: () => number): Promise<void> {
  const team = await startTeam({ tree, ...(now === undefined ? {} : { now }) });
  const work = await mkdtemp(join(tmpdir(), 'hn-audit-screen-'));
  const open: Served[] = [];
  try {
    const sam = await team.login({ email: 'sam@example.com', department: 'eng', groups: ['auditor'] });
    await saveLogin(join(work, 'sam'), team, sam, 'sam@example.com');
    await saveLogin(join(work, 'ana'), team, await team.login({ email: 'ana@example.com', department: 'eng', groups: [] }), 'ana@example.com');
    await team.broker.audit.settle();
    const folder = join(work, 'handed-over');
    assert.equal(await runPolicyTool(['broker', 'audit-key', join(team.dir, 'state'), folder], () => undefined), 0);
    const keys = { hmac: join(folder, 'audit.key'), pub: join(folder, 'audit-public.pem') };
    await body({
      team,
      work,
      sam,
      keys,
      async screen(extra = {}) {
        const served = await startAuditServe({ home: join(work, extra.as ?? 'sam'), ...(extra.pub === null ? {} : { publicKeyFile: extra.pub ?? keys.pub }), ...(extra.hmac === null ? {} : { hmacKeyFile: extra.hmac ?? keys.hmac }) });
        open.push(served);
        const cookie = await cookieFor(served);
        return { served, cookie, get: (path, headers = {}) => call(served.port, 'GET', path, { cookie, ...headers }) };
      },
      async write(type, data) {
        team.broker.context.audit(type, data);
        await team.broker.audit.settle();
      },
    });
  } finally {
    for (const served of open) await served.close();
    await team.close();
    await rm(work, { recursive: true, force: true });
  }
}

describe('the auditor screen over HTTP', () => {
  it('attack: audit_screen_requires_login_host_and_origin audit_screen_is_read_only - shows nothing without the cookie, refuses a foreign Host or Origin, and is read-only', async () => {
    await withScreen(async ({ screen, write }) => {
      await write('broker/login', { user: 'secret-person@example.com' });
      const { served, cookie } = await screen();
      const port = served.port;
      for (const path of ['/audit', '/audit/api/rows', '/audit/api/approvals', '/audit/api/status', '/audit/api/export', '/audit/api/tail']) {
        const reply = await call(port, 'GET', path);
        assert.ok(reply.status === 303 || reply.status === 401, `${path} answered ${reply.status} with no cookie`);
        assert.ok(!reply.body.includes('secret-person'), path);
      }
      assert.equal((await call(port, 'GET', `/audit/api/rows?token=${served.token}`)).status, 401, 'the token worked in the address');
      assert.equal((await call(port, 'GET', '/audit/api/rows', { cookie, host: `evil.example:${port}` })).status, 421);
      assert.equal((await call(port, 'GET', '/audit/api/rows', { cookie, origin: 'http://evil.example' })).status, 403);
      assert.equal((await call(port, 'GET', '/audit/api/rows', { cookie, origin: 'null' })).status, 403);
      // Nothing but GET does anything: a POST with the right origin and cookie is refused, and starts nothing.
      const origin = `http://127.0.0.1:${port}`;
      for (const method of ['POST', 'PUT', 'DELETE']) assert.equal((await call(port, method, '/audit/api/rows', { cookie, origin, 'content-type': 'application/json' }, '{}')).status, 405, method);
      assert.equal((served.server.address() as { address: string }).address, '127.0.0.1');
    });
  });

  it('serves a page with no inline script, style or handler, under strict headers', async () => {
    await withScreen(async ({ screen }) => {
      const { get } = await screen();
      const page = await get('/audit');
      assert.equal(page.status, 200);
      assert.match(String(page.headers['content-security-policy']), /script-src 'self'/);
      assert.equal(page.headers['x-content-type-options'], 'nosniff');
      assert.doesNotMatch(page.body, /<script(?![^>]*\ssrc=)/i);
      assert.doesNotMatch(page.body, /<style|\sstyle=|\son[a-z]+=|javascript:|https?:\/\//i);
      const script = await get('/audit.js');
      assert.doesNotMatch(script.body, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|srcdoc/);
      assert.equal((await get('/audit.css')).status, 200);
      assert.equal((await get('/nothing')).status, 404);
      assert.equal((await get('/')).headers['location'], '/audit');
    });
  });

  it('attack: audit_row_hidden_characters_written_out - shows the broker\'s rows with hidden characters written out, and passes an export on untouched so it still verifies', async () => {
    await withScreen(async ({ screen, write, team, keys }) => {
      await write('broker/approval-requested', { id: 'h1', user: 'ana@example.com', action: HOSTILE });
      const { get } = await screen();
      const rows = await get('/audit/api/rows?type=broker/approval-');
      assert.equal(rows.status, 200);
      assert.doesNotMatch(rows.body, /[‮\u001b\u0007]/, 'a hidden character reached the page');
      assert.match(rows.body, /\\\\u\{202e\}/);
      assert.match(rows.body, /<img src=x onerror/, 'the text itself is kept: it is shown, as text');
      const approvals = JSON.parse((await get('/audit/api/approvals')).body) as { approvals: { action: string }[] };
      assert.match(approvals.approvals[0]?.action ?? '', /\\u\{202e\}/);

      const exported = await get('/audit/api/export');
      assert.equal(exported.status, 200);
      assert.match(String(exported.headers['content-disposition']), /attachment/);
      const { createPublicKey } = await import('node:crypto');
      const { readFile } = await import('node:fs/promises');
      const result = verifyBundle(JSON.parse(exported.body), { hmacKey: await readFile(keys.hmac), publicKey: createPublicKey(await readFile(keys.pub)) });
      assert.equal(result.ok, true, result.reason ?? '');
      void team;
    });
  });

  it('rebuilds each filter from a short list of names, and refuses the rest', async () => {
    await withScreen(async ({ screen }) => {
      const { get } = await screen();
      for (const bad of ['/audit/api/rows?frm=1', '/audit/api/rows?user=a&user=b', `/audit/api/rows?user=${'x'.repeat(201)}`, '/audit/api/approvals?limit=5', '/audit/api/export?user=x', '/audit/api/tail?type=x']) assert.equal((await get(bad)).status, 400, bad);
      // A value the broker would refuse comes back as the broker's refusal, shown as text.
      const refused = await get('/audit/api/rows?limit=9999');
      assert.equal(refused.status, 502);
      assert.match(JSON.parse(refused.body).error, /limit/);
      assert.equal((await get('/audit/api/nonsense')).status, 404);
    });
  });

  it('says plainly when the person is not a reader', async () => {
    await withScreen(async ({ screen }) => {
      const { get } = await screen({ as: 'ana' });
      const reply = await get('/audit/api/rows');
      assert.equal(reply.status, 403);
      assert.match(JSON.parse(reply.body).error, /not named as a reader/);
      assert.equal((await get('/audit/api/status')).status, 403);
    });
  });

  it('reports whether the broker\'s head is signed with the key that was pinned, and warns when none was', async () => {
    await withScreen(async ({ screen, work }) => {
      const pinned = await (await screen()).get('/audit/api/status');
      const ok = JSON.parse(pinned.body) as { pinned: boolean; keyMatches: boolean; signatureOk: boolean; head: number };
      assert.deepEqual([ok.pinned, ok.keyMatches, ok.signatureOk], [true, true, true]);
      assert.ok(ok.head >= 2);
      const other = join(work, 'other.pem');
      await writeFile(other, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }));
      const wrong = JSON.parse((await (await screen({ pub: other })).get('/audit/api/status')).body) as { pinned: boolean; keyMatches: boolean; signatureOk: boolean };
      assert.deepEqual([wrong.pinned, wrong.keyMatches, wrong.signatureOk], [true, false, false]);
      const none = JSON.parse((await (await screen({ pub: null })).get('/audit/api/status')).body) as { pinned: boolean; keyMatches: null };
      assert.deepEqual([none.pinned, none.keyMatches], [false, null]);
    });
  });

  it('checks an export here only when it has both keys, and says so otherwise', async () => {
    await withScreen(async ({ screen }) => {
      const full = JSON.parse((await (await screen()).get('/audit/api/verify')).body) as { ok: boolean; rows: number };
      assert.equal(full.ok, true);
      assert.ok(full.rows >= 2);
      const missing = JSON.parse((await (await screen({ hmac: null })).get('/audit/api/verify')).body) as { ok: null; message: string };
      assert.equal(missing.ok, null);
      assert.match(missing.message, /--pub/);
    });
  });

  it('does not call an export verified when the audit key it was given belongs to another broker', async () => {
    await withScreen(async ({ screen, work }) => {
      const wrong = join(work, 'wrong.key');
      await writeFile(wrong, randomBytes(32));
      const result = JSON.parse((await (await screen({ hmac: wrong })).get('/audit/api/verify')).body) as { ok: boolean; brokenAt: number | null };
      assert.equal(result.ok, false);
      assert.equal(result.brokenAt, 1);
    });
  });

  it('relays the broker\'s live stream with every line cleaned, and lets go of the broker when the browser leaves', async () => {
    await withScreen(async ({ screen, write, team, sam }) => {
      const { served, cookie } = await screen();
      const lines: string[] = [];
      const request_ = request({ host: '127.0.0.1', port: served.port, path: '/audit/api/tail', headers: { host: `127.0.0.1:${served.port}`, cookie } }, (res) => {
        assert.equal(res.statusCode, 200);
        res.setEncoding('utf8').on('data', (chunk: string) => lines.push(...chunk.split('\n').filter((line) => line !== '')));
      });
      request_.end();
      for (let tries = 0; tries < 100 && lines.length === 0; tries += 1) await new Promise((resolve) => setTimeout(resolve, 20));
      await write('broker/approval-requested', { id: 'live-1', user: 'ana@example.com', action: HOSTILE });
      for (let tries = 0; tries < 100 && !lines.some((line) => line.includes('live-1')); tries += 1) await new Promise((resolve) => setTimeout(resolve, 20));
      const seen = lines.find((line) => line.includes('live-1')) ?? '';
      assert.match(seen, /"type":"row"/);
      assert.doesNotMatch(seen, /[‮\u001b\u0007]/);
      assert.match(seen, /\\\\u\{202e\}/);
      request_.destroy();
      // The broker's follower slot is given back once the browser has gone: all eight slots can then be taken directly.
      let slots: Response[] = [];
      for (let tries = 0; tries < 100; tries += 1) {
        slots = [];
        for (let i = 0; i < MAX_TAIL_SUBSCRIBERS; i += 1) slots.push(await team.raw('/v1/audit/tail', { token: sam.loginToken, session: sam.sid }));
        if (slots.every((slot) => slot.status === 200)) break;
        for (const slot of slots) await slot.body?.cancel();
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.deepEqual(slots.map((slot) => slot.status), Array(MAX_TAIL_SUBSCRIBERS).fill(200), 'the screen kept a follower slot after the browser left');
      for (const slot of slots) await slot.body?.cancel();
    });
  });
});

describe('the auditor screen in a real browser', () => {
  it('a browser is available when one is required', () => {
    if (required) assert.ok(browserPath !== null, 'HN_REQUIRE_BROWSER=1 but no Chrome or Edge was found. Set HN_BROWSER to one.');
  });

  it('attack: audit_row_html_injection - logs in, searches, shows approvals, follows a new row live and checks an export, and an approval written to look like markup and script is shown as the characters it is', { timeout: 240_000 }, async (t) => {
    if (browserPath === null) {
      if (required) assert.fail('HN_REQUIRE_BROWSER=1 but no Chrome or Edge was found.');
      return t.skip('no Chrome or Edge on this machine (set HN_BROWSER to one)');
    }
    await withScreen(async ({ screen, write, work }) => {
      await write('broker/approval-requested', { id: 'h1', user: 'ana@example.com', action: HOSTILE });
      await write('broker/approval-decided', { id: 'h1', approver: 'cy@example.com', requester: 'ana@example.com', action: HOSTILE, decision: 'approve' });
      const { served } = await screen();
      const profile = join(work, 'browser-profile');
      await mkdir(profile);
      const browser = await Browser.launch(browserPath, profile);
      try {
        const page = await browser.page();
        const text = (selector: string): Promise<string | null> => page.eval<string | null>(`(function(){var n=document.querySelector(${JSON.stringify(selector)});return n===null?null:n.textContent;})()`);
        const click = (selector: string): Promise<boolean> => page.eval<boolean>(`(function(){var n=document.querySelector(${JSON.stringify(selector)});if(n===null)return false;n.click();return true;})()`);
        await page.goto(`http://127.0.0.1:${served.port}/audit`);
        assert.equal(await page.eval('location.pathname'), '/login', 'an unauthenticated page was not sent to the login');
        assert.equal(await page.eval('document.querySelectorAll("#rows tbody tr").length'), 0, 'rows were shown before login');
        await page.eval(`(function(){document.querySelector("input[name=token]").value=${JSON.stringify(served.token)};document.querySelector("form").submit();})()`);
        await page.waitFor('location.pathname === "/audit" && document.querySelectorAll("#rows tbody tr").length >= 3');
        assert.equal(await page.eval('document.title'), 'hn team audit');
        // The broker's current head is signed with the key that was pinned.
        await page.waitFor('document.getElementById("status").className === "ok"');
        assert.match((await text('#status')) ?? '', /signed row \d+ .* with the key you pinned/);

        // Search by type: only approval rows, and the action text is characters.
        await page.eval('(function(){var f=document.getElementById("search-form");f.elements.type.value="broker/approval-";f.requestSubmit();})()');
        await page.waitFor('document.querySelectorAll("#rows tbody tr").length === 2');
        const shown = (await text('#rows tbody')) ?? '';
        assert.match(shown, /<img src=x onerror=/, 'the markup in the action is shown as text');
        assert.match(shown, /\\u\{202e\}/, 'the override character is written out');
        assert.doesNotMatch(shown, /[‮\u001b\u0007]/);
        assert.equal(await page.eval('document.querySelectorAll("#rows img, #rows script, main img, main script").length'), 0, 'an element was made from broker text');
        assert.equal(await page.eval('window.__pwned === undefined'), true, 'a script from broker text ran');

        // Approvals: one line for the whole story.
        assert.ok(await click('#tabs button[data-tab="approvals"]'));
        await page.waitFor('document.querySelectorAll("#approval-table tbody tr").length === 1');
        const line = (await text('#approval-table tbody tr')) ?? '';
        assert.match(line, /h1/);
        assert.match(line, /ana@example\.com/);
        assert.match(line, /cy@example\.com/);
        assert.match(line, /approved/);
        assert.equal(await page.eval('document.querySelectorAll("#approval-table img, #approval-table script").length'), 0);

        // Live: a row written while the page is open appears at the top, without anyone touching it.
        assert.ok(await click('#tabs button[data-tab="live"]'));
        assert.ok(await click('#live-toggle'));
        await page.waitFor('document.getElementById("live-rows").children.length >= 1');
        await write('broker/login', { user: 'written-while-watching@example.com' });
        await page.waitFor('document.getElementById("live-rows").textContent.indexOf("written-while-watching@example.com") !== -1');
        assert.ok(await click('#live-toggle'));

        // Export: checked here with the two keys the screen was started with.
        assert.ok(await click('#tabs button[data-tab="export"]'));
        assert.ok(await click('#verify'));
        await page.waitFor('document.getElementById("verify-state").textContent === "VERIFIED"');
        assert.equal(await page.eval('window.__pwned === undefined'), true);
        assert.deepEqual(page.problems, []);
      } finally {
        await browser.close();
      }
    });
  });
});
