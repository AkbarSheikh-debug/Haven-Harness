import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { connect } from 'node:net';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { KeyStore } from '@hn/provider';
import { SESSION_ID, startReplayServe, startServe, type Replay, type Served } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';
import { recordSession, startScriptedModel, type Recorded } from './replay-fixture.ts';

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

/** Logs in as a browser would, and returns the cookie. */
async function login(served: Served): Promise<string> {
  const origin = `http://127.0.0.1:${served.port}`;
  const reply = await call(served.port, 'POST', '/login', { origin, 'content-type': 'application/x-www-form-urlencoded' }, `token=${served.token}`);
  assert.equal(reply.status, 303);
  const cookie = /hn_session=[0-9a-f]{64}/.exec(String(reply.headers['set-cookie']))?.[0];
  assert.ok(cookie !== undefined, 'no cookie came back');
  return cookie;
}

const entries = async (folder: string): Promise<string[]> => (await readdir(folder, { recursive: true }).catch(() => [])).sort();

describe('the replay screen over HTTP', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startScriptedModel();
  });
  after(async () => {
    await model.close();
  });

  /** A recorded session and a replay-only server for its project. */
  const withServer = async (body: (context: { recorded: Recorded; served: Served; cookie: string; get: (path: string, headers?: Record<string, string>) => Promise<Reply> }) => Promise<void>): Promise<void> =>
    withTempDir(async (dir) => {
      const recorded = await recordSession(await realpath(dir), model);
      const served = await startReplayServe({ cwd: recorded.project, env: { HN_HOME: recorded.home } });
      try {
        const cookie = await login(served);
        await body({ recorded, served, cookie, get: (path, headers = {}) => call(served.port, 'GET', path, { cookie, ...headers }) });
      } finally {
        await served.close();
      }
    });

  it('attack: replay_requires_login_host_and_origin - shows nothing without the token\'s cookie, and refuses a foreign Host or Origin', { timeout: 120_000 }, async () => {
    await withServer(async ({ recorded, served, cookie }) => {
      const port = served.port;
      const id = recorded.sessionId;
      for (const path of ['/replay', '/replay.js', '/replay.css', '/replay/api/sessions', `/replay/api/session/${id}`]) {
        const reply = await call(port, 'GET', path);
        assert.ok(reply.status === 303 || reply.status === 401, `${path} answered ${reply.status} with no cookie`);
        if (path !== '/replay.js' && path !== '/replay.css') assert.ok(!reply.body.includes('new.txt'), 'a log was shown with no login');
        assert.ok(!reply.body.includes('REPLAY_'), path);
      }
      // A cookie that is not the server's, a token in the address, and a wrong token.
      assert.equal((await call(port, 'GET', '/replay/api/sessions', { cookie: `hn_session=${'0'.repeat(64)}` })).status, 401);
      assert.equal((await call(port, 'GET', `/replay/api/sessions?token=${served.token}`)).status, 401, 'the token worked in the address');
      assert.equal((await call(port, 'POST', '/login', { origin: `http://127.0.0.1:${port}`, 'content-type': 'application/x-www-form-urlencoded' }, 'token=wrong')).status, 401);
      // DNS rebinding: the right cookie, the wrong Host. A page on another site: the right cookie, a foreign Origin.
      assert.equal((await call(port, 'GET', '/replay/api/sessions', { cookie, host: `evil.example:${port}` })).status, 421);
      assert.equal((await call(port, 'GET', '/replay/api/sessions', { cookie, host: `127.0.0.1:${port + 1}` })).status, 421);
      assert.equal((await call(port, 'GET', '/replay/api/sessions', { cookie, origin: 'http://evil.example' })).status, 403);
      assert.equal((await call(port, 'GET', '/replay/api/sessions', { cookie, origin: 'null' })).status, 403);
      // The login form itself is the one page that needs no cookie, and it holds no log.
      assert.equal((await call(port, 'GET', '/login')).status, 200);
      // And it answers on loopback only.
      assert.equal((served.server.address() as { address: string }).address, '127.0.0.1');
    });
  });

  it('shows a recorded session to someone logged in, with the page, its script and its sessions, under the strict headers', { timeout: 120_000 }, async () => {
    await withServer(async ({ recorded, get }) => {
      const page = await get('/replay');
      assert.equal(page.status, 200);
      assert.match(String(page.headers['content-type']), /text\/html/);
      assert.match(String(page.headers['content-security-policy']), /script-src 'self'/);
      assert.match(String(page.headers['content-security-policy']), /frame-ancestors 'none'/);
      assert.equal(page.headers['x-content-type-options'], 'nosniff');
      assert.equal(page.headers['cache-control'], 'no-store');
      // No inline script, no inline style, no event handler, and nothing loaded from another site.
      assert.doesNotMatch(page.body, /<script(?![^>]*\ssrc=)/i);
      assert.doesNotMatch(page.body, /<style|\sstyle=|\son[a-z]+=|javascript:|https?:\/\//i);
      assert.equal((await get('/')).status, 303);
      assert.equal((await get('/')).headers['location'], '/replay');
      const script = await get('/replay.js');
      assert.equal(script.status, 200);
      assert.doesNotMatch(script.body, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|srcdoc/, 'the script can put markup on the page');
      const css = await get('/replay.css');
      assert.equal(css.status, 200);
      assert.doesNotMatch(css.body, /url\(|@import/i, 'the stylesheet can fetch something');
      const list = JSON.parse((await get('/replay/api/sessions')).body) as { sessions: { id: string; modified: string; bytes: number }[] };
      assert.deepEqual(
        list.sessions.map((entry) => entry.id),
        [recorded.sessionId],
      );
      const replay = JSON.parse((await get(`/replay/api/session/${recorded.sessionId}`)).body) as Replay;
      assert.equal(replay.trust, 'verified');
      assert.ok(replay.steps.some((step) => step.diff?.kind === 'edit'));
      assert.ok(replay.steps.some((step) => step.kind === 'gate' && step.tone === 'refused'));
      assert.equal((await get('/replay/api/session/nosuchsession0')).status, 404);
      assert.equal((await get('/replay/nothing')).status, 404);
    });
  });

  it('attack: replay_session_id_cannot_leave_sessions_folder - an id that is a path, an escape, a null byte or enormous finds nothing and reads nothing', { timeout: 120_000 }, async () => {
    await withServer(async ({ recorded, get }) => {
      const key = await readFile(join(recorded.home, 'log.key'));
      const hostile = ['..%2F..%2Flog.key', '%2e%2e', '..', '.', 'a%2Fb', 'a%5Cb', `${recorded.sessionId}%2F..%2F${recorded.sessionId}`, 'a%00b', '%00', 'x'.repeat(65), 'x'.repeat(20_000), '%', '%E0%A4%A', 'C%3A%5Cwindows%5Cwin.ini', '..%5C..%5Clog.key', 'log.key', ''];
      for (const id of hostile) {
        const reply = await get(`/replay/api/session/${id}`);
        assert.ok([400, 404, 431].includes(reply.status), `${id.slice(0, 40)} answered ${reply.status}`);
        assert.ok(!reply.body.includes(key.toString('latin1')) && !reply.body.includes('"steps"'), `${id.slice(0, 40)} returned something`);
      }
      // The pattern a real id must match is the one the server uses.
      assert.match(recorded.sessionId, SESSION_ID);
      assert.doesNotMatch('../log.key', SESSION_ID);
    });
  });

  it('attack: forged_log_replay_refused - over HTTP, an edited log comes back as a refusal with no steps, and the original does not', { timeout: 120_000 }, async () => {
    await withServer(async ({ recorded, get }) => {
      const before = JSON.parse((await get(`/replay/api/session/${recorded.sessionId}`)).body) as Replay;
      assert.equal(before.trust, 'verified');
      const bytes = await readFile(recorded.file);
      bytes.writeUInt8(bytes.readUInt8(Math.floor(bytes.length / 2)) ^ 0xff, Math.floor(bytes.length / 2));
      await writeFile(recorded.file, bytes);
      const reply = await get(`/replay/api/session/${recorded.sessionId}`);
      assert.equal(reply.status, 200);
      const forged = JSON.parse(reply.body) as Replay;
      assert.equal(forged.trust, 'refused');
      assert.deepEqual(forged.steps, []);
      assert.match(forged.reason ?? '', /does not verify/);
      assert.doesNotMatch(reply.body, /new\.txt|node --version|do the work/, 'a forged log leaked through the refusal');
    });
  });

  it('attack: replay_page_is_read_only_and_starts_nothing - answers only GET, never starts a session or writes a file, and has no door to act through', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const recorded = await recordSession(await realpath(dir), model);
      const projectBefore = await entries(recorded.project);
      const homeBefore = await entries(recorded.home);
      const served = await startReplayServe({ cwd: recorded.project, env: { HN_HOME: recorded.home } });
      try {
        const cookie = await login(served);
        const origin = `http://127.0.0.1:${served.port}`;
        for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
          for (const path of ['/replay', `/replay/api/session/${recorded.sessionId}`, '/replay/api/sessions', '/prompt', '/approve', '/session', '/events']) {
            const reply = await call(served.port, method, path, { cookie, origin, 'x-hn-csrf': 'anything', 'content-type': 'application/json' }, '{"text":"run rm -rf","decision":"once"}');
            assert.ok([401, 403, 405, 415, 404].includes(reply.status) && reply.status !== 200, `${method} ${path} answered ${reply.status}`);
          }
        }
        // The live session's own doors do not exist here.
        for (const path of ['/prompt', '/approve', '/session', '/events', '/app.js']) assert.equal((await call(served.port, 'GET', path, { cookie })).status, 404, path);
        // A WebSocket upgrade is refused whatever it claims.
        const refused = await new Promise<string>((resolve) => {
          const socket = connect(served.port, '127.0.0.1', () => socket.write(`GET /replay HTTP/1.1\r\nHost: 127.0.0.1:${served.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\nCookie: ${cookie}\r\n\r\n`));
          let text = '';
          socket.on('data', (chunk) => (text += chunk.toString()));
          socket.on('close', () => resolve(text));
        });
        assert.match(refused, /^HTTP\/1\.1 403/);
      } finally {
        await served.close();
      }
      assert.deepEqual(await entries(recorded.project), projectBefore, 'the replay screen changed the project');
      assert.deepEqual(await entries(recorded.home), homeBefore, 'the replay screen started a session or wrote into the home folder');
    });
  });

  it('is part of the live hn serve too, behind the same login, and it cannot be used to prompt or approve', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const recorded = await recordSession(await realpath(dir), model);
      const live = await startFakeOpenAI(() => ({ text: 'hi' }));
      const served = await startServe({ keys: KeyStore.capture({}), cwd: recorded.project, defaults: { model: 'fake', baseUrl: live.url, window: 64_000 }, env: { HN_HOME: recorded.home }, sessionExtras: { verify: 'off' } });
      try {
        assert.equal((await call(served.port, 'GET', '/replay/api/sessions')).status, 401);
        const cookie = await login(served);
        const list = JSON.parse((await call(served.port, 'GET', '/replay/api/sessions', { cookie })).body) as { sessions: { id: string }[] };
        assert.ok(list.sessions.some((entry) => entry.id === recorded.sessionId));
        const replay = JSON.parse((await call(served.port, 'GET', `/replay/api/session/${recorded.sessionId}`, { cookie })).body) as Replay;
        assert.equal(replay.trust, 'verified');
        const session = JSON.parse((await call(served.port, 'GET', '/session', { cookie })).body) as { csrf: string };
        const origin = `http://127.0.0.1:${served.port}`;
        const post = await call(served.port, 'POST', '/replay/api/sessions', { cookie, origin, 'x-hn-csrf': session.csrf, 'content-type': 'application/json' }, '{}');
        assert.equal(post.status, 405);
        assert.equal((await call(served.port, 'GET', '/', { cookie })).status, 200, 'the live page still works');
      } finally {
        await served.close();
        await live.close();
      }
    });
  });

  it('is started by the real command, hn serve --replay: it prints a token and an address, needs no key, runs no session, and shows the project\'s sessions', { timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const recorded = await recordSession(await realpath(dir), model);
      const homeBefore = await entries(recorded.home);
      // The launcher only adds --disable-proto=throw and waits for the real process, so killing the launcher would leave the server running
      // (and the test runner waiting on its pipes). Start the real entry point with the same flags.
      const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
      const env: NodeJS.ProcessEnv = { ...process.env, HN_HOME: recorded.home };
      for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'ELECTRON_RUN_AS_NODE']) delete env[name];
      const child = spawn(process.execPath, ['--disable-proto=throw', '--no-warnings', main, 'serve', '--replay'], { cwd: recorded.project, env, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      let err = '';
      child.stdout.on('data', (chunk: Buffer) => (out += chunk.toString()));
      child.stderr.on('data', (chunk: Buffer) => (err += chunk.toString()));
      try {
        const started = Date.now();
        while (!/Ctrl\+C to stop/.test(out) && Date.now() - started < 60_000 && child.exitCode === null) await new Promise((resolve) => setTimeout(resolve, 100));
        assert.match(out, /hn is showing the sessions recorded for this folder at http:\/\/127\.0\.0\.1:(\d+)\/replay/, `no address was printed. stdout: ${out} stderr: ${err}`);
        const port = Number(/127\.0\.0\.1:(\d+)\/replay/.exec(out)?.[1]);
        const token = /\n([0-9a-f]{64})\n/.exec(out)?.[1] as string;
        assert.ok(token !== undefined, 'no token was printed');
        const reply = await call(port, 'POST', '/login', { origin: `http://127.0.0.1:${port}`, 'content-type': 'application/x-www-form-urlencoded' }, `token=${token}`);
        const cookie = /hn_session=[0-9a-f]{64}/.exec(String(reply.headers['set-cookie']))?.[0] as string;
        const replay = JSON.parse((await call(port, 'GET', `/replay/api/session/${recorded.sessionId}`, { cookie })).body) as Replay;
        assert.equal(replay.trust, 'verified');
        assert.ok(replay.steps.length > 20);
      } finally {
        child.kill();
        await new Promise((resolve) => (child.exitCode === null ? child.once('exit', resolve) : resolve(undefined)));
      }
      assert.deepEqual(await entries(recorded.home), homeBefore, 'running the command started a session or wrote into the home folder');
    });
  });
});
