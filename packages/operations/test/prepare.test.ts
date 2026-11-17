import assert from 'node:assert/strict';
import { mkdir, readdir, realpath, writeFile } from 'node:fs/promises';
import type { Server } from 'node:http';
import { connect } from 'node:net';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { copyManifests, detectManager, dockerDesktopProblem, preparePlan, scriptPackages } from '@hn/operations';
import { createRegistryProxy } from '../src/registry-proxy.mjs';
import { withTempDir } from '@hn/testkit';

const PIN = `node@sha256:${'a'.repeat(64)}`;

/** Sends one raw request line, so nothing on the client side normalises the path or the target. */
function raw(port: number, requestLine: string, headers: Record<string, string> = {}): Promise<number> {
  return new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port }, () => {
      const extra = Object.entries({ host: 'proxy:8080', ...headers }).map(([name, value]) => `${name}: ${value}\r\n`).join('');
      socket.write(`${requestLine} HTTP/1.1\r\n${extra}connection: close\r\n\r\n`);
    });
    let text = '';
    socket.on('data', (chunk) => (text += chunk.toString()));
    socket.on('close', () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0)));
    socket.on('error', () => resolve(0));
  });
}

describe('the prepare package proxy', () => {
  let server: Server;
  let port = 0;
  const upstream: { url: string; headers: Record<string, string> }[] = [];

  before(async () => {
    server = createRegistryProxy({
      publicBase: 'http://proxy:8080',
      fetch: async (url, init) => {
        upstream.push({ url, headers: init.headers });
        const body = JSON.stringify({ name: 'left-pad', versions: { '1.3.0': { dist: { tarball: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz' } } } });
        return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
      },
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as { port: number }).port;
  });
  after(() => {
    server.close();
  });

  it('attack: prepare_cannot_publish_or_reach_engine_api (no publish, no login, no engine API, no other host, no traversal)', async () => {
    const refused: [string, number, Record<string, string>?][] = [
      ['PUT /npm/left-pad', 405],
      ['POST /npm/-/v1/login', 405],
      ['DELETE /npm/left-pad/-rev/1', 405],
      ['GET /npm/-/whoami', 403],
      ['GET /npm/-/npm/v1/security/audits', 403],
      ['GET /npm/-/user/org.couchdb.user:me', 400], // refused earlier still: no package path has a colon
      ['GET http://host.docker.internal:2375/containers/json', 403],
      ['GET http://172.17.0.1:2375/version', 403],
      ['GET https://github.com/owner/repo', 403],
      ['CONNECT 172.17.0.1:2375', 405],
      ['CONNECT github.com:443', 405],
      ['GET /version', 404, { host: '172.17.0.1:2375' }],
      ['GET /v1.43/containers/json', 404],
      ['GET /github/owner/repo/archive/main.tar.gz', 404],
      ['GET /npm/../../v1.43/containers/json', 400],
      ['GET /npm/%2e%2e/%2e%2e/v1.43/containers/json', 400],
      ['GET /npm/left-pad%5c..%5c..%5cx', 400],
    ];
    for (const [line, status, headers] of refused) assert.equal(await raw(port, line, headers), status, line);
    assert.deepEqual(upstream, [], 'a refused request reached a registry, or somewhere else');
  });

  it('reads a package from the fixed registry only, drops every credential, and points downloads back at itself', async () => {
    const status = await raw(port, 'GET /npm/left-pad', { authorization: 'Bearer npm_SECRET', cookie: 'session=1', 'npm-otp': '123456', 'x-forwarded-for': '1.2.3.4' });
    assert.equal(status, 200);
    assert.equal(upstream.length, 1);
    assert.equal(upstream[0]?.url, 'https://registry.npmjs.org/left-pad');
    const sent = Object.keys(upstream[0]?.headers ?? {}).map((name) => name.toLowerCase());
    for (const name of ['authorization', 'cookie', 'npm-otp', 'x-forwarded-for', 'host']) assert.ok(!sent.includes(name), `${name} was forwarded`);
    const reply = await fetch(`http://127.0.0.1:${port}/npm/left-pad`);
    const text = await reply.text();
    assert.match(text, /http:\/\/proxy:8080\/npm\/left-pad\/-\/left-pad-1\.3\.0\.tgz/);
    assert.doesNotMatch(text, /registry\.npmjs\.org/);
    for (const call of upstream) assert.match(call.url, /^https:\/\/(registry\.npmjs\.org|pypi\.org\/simple|files\.pythonhosted\.org)\//);
  });
});

describe('the prepare plan', () => {
  it('installs on an internal network with scripts off, never mounts the engine socket, and runs approved scripts with no network', () => {
    const steps = preparePlan({ id: 'abc123', manager: 'npm', workDir: '/tmp/work', proxyImage: PIN, installImage: PIN, runScripts: false });
    const all = steps.map((step) => step.args.join(' ')).join('\n');
    assert.deepEqual(steps[0]?.args, ['network', 'create', '--internal', 'hn-prep-abc123']);
    const install = steps.find((step) => step.args.includes('ci'));
    assert.ok(install !== undefined);
    assert.ok(install.args.includes('--ignore-scripts'));
    assert.equal(install.args[install.args.indexOf('--network') + 1], 'hn-prep-abc123');
    assert.ok(install.args.includes('--registry=http://hn-prep-proxy-abc123:8080/npm/'));
    for (const flag of ['--read-only', 'no-new-privileges']) assert.ok(install.args.includes(flag), flag);
    assert.doesNotMatch(all, /docker\.sock|--privileged|--network host|-v \/:/);
    assert.equal(steps.filter((step) => step.args.includes('bridge')).length, 1, 'only the proxy is on a routed network');
    assert.ok(!steps.some((step) => step.args.includes('rebuild')), 'scripts ran without a person');
    const withScripts = preparePlan({ id: 'abc123', manager: 'npm', workDir: '/tmp/work', proxyImage: PIN, installImage: PIN, runScripts: true });
    const scripts = withScripts.find((step) => step.args.includes('rebuild'));
    assert.equal(scripts?.args[scripts.args.indexOf('--network') + 1], 'none');
    const pip = preparePlan({ id: 'abc123', manager: 'pip', workDir: '/tmp/work', proxyImage: PIN, installImage: PIN, runScripts: true });
    assert.ok(pip.some((step) => step.args.includes('--only-binary=:all:')), 'pip may build from source, which runs setup code');
    assert.ok(!pip.some((step) => step.args.includes('rebuild')));
    assert.throws(() => preparePlan({ id: 'abc123', manager: 'npm', workDir: '/w', proxyImage: 'node:22', installImage: PIN, runScripts: false }), /pinned by digest/);
  });

  it('copies only the manifests and lockfile, never .npmrc or the source, and lists packages with install scripts', async () => {
    await withTempDir(async (dir) => {
      const root = join(await realpath(dir), 'project');
      await mkdir(join(root, 'src'), { recursive: true });
      await writeFile(join(root, 'package.json'), '{"name":"p"}');
      await writeFile(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/esbuild': { hasInstallScript: true }, 'node_modules/left-pad': {} } }));
      await writeFile(join(root, '.npmrc'), '//registry.npmjs.org/:_authToken=npm_SECRET\n');
      await writeFile(join(root, 'src', 'index.js'), 'x');
      assert.equal(await detectManager(root), 'npm');
      const out = join(root, '..', 'work');
      assert.deepEqual(await copyManifests(root, 'npm', out), ['package.json', 'package-lock.json']);
      assert.deepEqual((await readdir(out)).sort(), ['package-lock.json', 'package.json']);
      assert.deepEqual(await scriptPackages(root, 'npm'), ['esbuild']);
    });
  });

  it('hn doctor refuses a Docker Desktop older than 4.44.3 (CVE-2025-9074)', () => {
    assert.match(dockerDesktopProblem('Docker Desktop 4.44.2 (201000)') ?? '', /CVE-2025-9074/);
    assert.match(dockerDesktopProblem('Docker Desktop 4.9.0 (1)') ?? '', /older/);
    assert.equal(dockerDesktopProblem('Docker Desktop 4.44.3 (202357)'), null);
    assert.equal(dockerDesktopProblem('Docker Desktop 4.52.0 (1)'), null);
    assert.equal(dockerDesktopProblem('Docker Engine - Community'), null);
  });
});
