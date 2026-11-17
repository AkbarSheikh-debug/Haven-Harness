import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import { connect } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { EgressProxy, NonceSinks, browserArgs, findBrowser, hostAddresses } from '@hn/operations';
import { EgressPolicy } from '@hn/security';
import { createBrowserTool } from '@hn/tools';

/** A page server on loopback that records every path it was asked for and echoes the headers it got. */
async function pageServer(html: (port: number) => string): Promise<{ server: Server; port: number; paths: string[]; headers: Record<string, unknown>[] }> {
  const paths: string[] = [];
  const headers: Record<string, unknown>[] = [];
  const server = createServer((req, res) => {
    paths.push(req.url ?? '');
    headers.push(req.headers);
    if (req.url === '/') res.writeHead(200, { 'content-type': 'text/html' }).end(html(port));
    else res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
  });
  await new Promise<void>((resolve) => server.listen({ port: 0, host: '127.0.0.1' }, resolve));
  const port = (server.address() as { port: number }).port;
  return { server, port, paths, headers };
}

function tunnel(proxyPort: number, target: string): Promise<string> {
  return new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port: proxyPort }, () => socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    socket.once('data', (data) => {
      resolve(data.toString().split('\r\n')[0] ?? '');
      socket.destroy();
    });
    socket.on('error', () => resolve('error'));
    // A proxy that forwards to an address that never answers must fail the test, not hang it.
    socket.on('close', () => resolve('closed'));
    socket.setTimeout(5_000, () => {
      resolve('no answer');
      socket.destroy();
    });
  });
}

function viaProxy(proxyPort: number, url: string, extra: Record<string, string> = {}): Promise<number> {
  return new Promise((resolve) => {
    const req = request({ host: '127.0.0.1', port: proxyPort, path: url, headers: { host: new URL(url).host, ...extra } }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', () => resolve(0));
    req.setTimeout(5_000, () => {
      resolve(-1);
      req.destroy();
    });
    req.end();
  });
}

describe('the browser egress proxy', () => {
  let page: Awaited<ReturnType<typeof pageServer>>;
  let proxy: EgressProxy;
  before(async () => {
    page = await pageServer(() => 'page');
    const names: Record<string, string[]> = { 'site.hn-test.example': ['127.0.0.1'], 'inside.hn-test.example': ['10.0.0.5'], 'rebind.hn-test.example': ['93.184.216.34', '127.0.0.1'], 'held.hn-test.example': ['93.184.216.34'] };
    proxy = await EgressProxy.start({
      resolve: async (host) => names[host] ?? [],
      allowHttp: true,
      allowedPorts: [80, 443, page.port],
      exempt: { address: '127.0.0.1', port: page.port },
      allowHost: (host) => host !== 'held.hn-test.example',
    });
  });
  after(async () => {
    await proxy.close();
    page.server.close();
  });

  it('refuses tunnels to loopback, to a name that resolves to a private address, and to a name with one private address among public ones', async () => {
    assert.match(await tunnel(proxy.port, '127.0.0.1:443'), /403/);
    assert.match(await tunnel(proxy.port, '[::1]:443'), /403/);
    assert.match(await tunnel(proxy.port, 'inside.hn-test.example:443'), /403/);
    assert.match(await tunnel(proxy.port, 'rebind.hn-test.example:443'), /403/);
    assert.match(await tunnel(proxy.port, '169.254.169.254:443'), /403/);
    assert.match(await tunnel(proxy.port, 'held.hn-test.example:443'), /403/, 'a host not approved under taint');
    assert.match(await tunnel(proxy.port, 'example.org:22'), /403/, 'a port that is not allowed');
    const reasons = proxy.decisions.filter((decision) => !decision.allowed).map((decision) => decision.reason ?? '').join('\n');
    assert.match(reasons, /metadata/);
    assert.match(reasons, /not approved/);
  });

  it('forwards plain http only to an allowed address, with the proxy headers stripped', async () => {
    assert.equal(await viaProxy(proxy.port, 'http://169.254.169.254/latest/meta-data/'), 403);
    assert.equal(await viaProxy(proxy.port, 'http://inside.hn-test.example/'), 403);
    assert.equal(await viaProxy(proxy.port, `http://site.hn-test.example:${page.port}/hello`, { 'proxy-authorization': 'Basic c2VjcmV0' }), 200);
    assert.equal(page.paths.at(-1), '/hello');
    assert.equal(page.headers.at(-1)?.['proxy-authorization'], undefined);
  });

  it('starts the browser with every request through the proxy, loopback included, and no name resolution of its own', () => {
    const args = browserArgs(4321, 'C:\\tmp\\profile');
    for (const flag of ['--headless=new', '--proxy-server=http://127.0.0.1:4321', '--proxy-bypass-list=<-loopback>', '--disable-quic', '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-extensions', '--user-data-dir=C:\\tmp\\profile']) {
      assert.ok(args.includes(flag), flag);
    }
    assert.ok(!args.some((arg) => arg.startsWith('--remote-debugging-address')), 'the DevTools port must stay on loopback');
  });
});

describe('the browser tool with a real headless browser', { skip: findBrowser() === null ? 'no Chrome or Edge on this machine' : false }, () => {
  let sinks: NonceSinks;
  let page: Awaited<ReturnType<typeof pageServer>>;
  before(async () => {
    sinks = await NonceSinks.open();
    page = await pageServer((port) => {
      const images = hostAddresses()
        .map((address) => `<img src="http://${address.includes(':') ? `[${address}]` : address}:${sinks.tcpPort}/leak.png">`)
        .join('\n');
      return `<!doctype html><title>Test page</title><body><p>HELLO FROM THE PAGE</p>
${images}
<img src="http://rebind.hn-test.example:${sinks.tcpPort}/rebind.png">
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
<img src="http://other.hn-test.example:${port}/other.png">
<img src="http://site.hn-test.example:${port}/fine.png">
<script>fetch('http://10.1.2.3:${sinks.tcpPort}/x').catch(() => {}); new Image().src = 'http://127.0.0.1:${sinks.tcpPort}/script.png';</script>
<a href="https://example.org/next">next page</a></body>`;
    });
  });
  after(async () => {
    await sinks.close();
    page.server.close();
  });

  const toolFor = (tainted: boolean) =>
    createBrowserTool({
      policy: new EgressPolicy({}),
      tainted: () => tainted,
      proxy: {
        resolve: async (host) => ({ 'site.hn-test.example': ['127.0.0.1'], 'other.hn-test.example': ['127.0.0.1'], 'rebind.hn-test.example': ['93.184.216.34', '127.0.0.1'] })[host] ?? [],
        allowHttp: true,
        allowedPorts: [80, 443, page.port, sinks.tcpPort],
        exempt: { address: '127.0.0.1', port: page.port },
      },
    });

  it('reads a page while nothing the page asks for reaches this machine, a private network or the metadata address', { timeout: 90_000 }, async () => {
    const browser = toolFor(false);
    const context = { workdir: '.', ops: {} as never, signal: new AbortController().signal, callId: 'b' };
    try {
      const opened = await browser.tool.execute({ action: 'open', url: `http://site.hn-test.example:${page.port}/` }, context);
      assert.equal(opened.origin, 'web');
      assert.match(opened.content, /<untrusted source="web"/);
      assert.match(opened.content, /HELLO FROM THE PAGE/);
      assert.match(opened.content, /the egress proxy refused \d+ request/);
      assert.match(opened.content, /metadata/);
      await new Promise((resolve) => setTimeout(resolve, 800));
      assert.deepEqual(sinks.hits, [], `a request from the page reached a listener on this machine: ${JSON.stringify(sinks.hits)}
${opened.content}`);
      assert.ok(page.paths.includes('/fine.png'), 'an allowed request was not made, so the test proves nothing');
      const links = await browser.tool.execute({ action: 'links' }, context);
      assert.match(links.content, /next page {2}https:\/\/example\.org\/next/);
    } finally {
      await browser.close();
    }
  });

  it('under the Rule of Two reaches only the host a person approved, so a page cannot send data to another one', { timeout: 90_000 }, async () => {
    const browser = toolFor(true);
    const context = { workdir: '.', ops: {} as never, signal: new AbortController().signal, callId: 'b' };
    const before = page.paths.length;
    try {
      const opened = await browser.tool.execute({ action: 'open', url: `http://site.hn-test.example:${page.port}/` }, context);
      assert.match(opened.content, /HELLO FROM THE PAGE/);
      const asked = page.paths.slice(before);
      assert.ok(asked.includes('/fine.png'));
      assert.ok(!asked.includes('/other.png'), 'the page reached a host nobody approved');
      assert.match(opened.content, /other\.hn-test\.example[^\n]*not approved/);
    } finally {
      await browser.close();
    }
  });
});

describe('addresses of this machine', () => {
  it('are refused even when they are public (a global IPv6 address, a VPN address), for the browser and web_fetch alike', async () => {
    const { networkInterfaces } = await import('node:os');
    const { blockedAddress } = await import('@hn/security');
    const mine = Object.values(networkInterfaces()).flatMap((list) => (list ?? []).map((entry) => entry.address.replace(/%.*$/, '')));
    assert.ok(mine.length > 0);
    for (const address of mine) assert.notEqual(blockedAddress(address), null, `${address} belongs to this machine and was allowed`);
    assert.equal(blockedAddress('93.184.216.34'), null, 'an ordinary public address is still allowed');
  });
});
