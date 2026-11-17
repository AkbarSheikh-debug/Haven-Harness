import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, it } from 'node:test';
import { git } from '@hn/operations';
import { baseTree, startTeam, type Team } from './fixture.ts';

const MCP_SECRET = 'mcp-secret-value-77';
const GIT_SECRET = 'ghp-broker-token-55';

interface FakeMcp {
  readonly url: string;
  readonly calls: string[];
  readonly headers: IncomingHttpHeaders[];
  close(): Promise<void>;
}

/** A streamable-HTTP MCP server that wants a bearer token and records what it was asked. */
async function fakeMcp(): Promise<FakeMcp> {
  const calls: string[] = [];
  const headers: IncomingHttpHeaders[] = [];
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      headers.push(request.headers);
      if (request.headers['authorization'] !== `Bearer ${MCP_SECRET}`) return void response.writeHead(401).end();
      const message = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { id?: number; method: string; params?: { name?: string; arguments?: unknown } };
      calls.push(message.method === 'tools/call' ? `call ${String(message.params?.name)}` : message.method);
      if (message.id === undefined) return void response.writeHead(202).end();
      const result =
        message.method === 'initialize'
          ? { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'docs', version: '1' } }
          : message.method === 'tools/list'
            ? { tools: [{ name: 'search', description: 'Search the docs', inputSchema: { type: 'object' } }, { name: 'delete_all', description: 'Delete every page', inputSchema: { type: 'object' } }] }
            : { content: [{ type: 'text', text: `found: ${JSON.stringify(message.params?.arguments)}` }] };
      // Answered as an event stream, as many servers do.
      response.writeHead(200, { 'content-type': 'text/event-stream', 'mcp-session-id': 'sess-1' });
      response.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: message.id, result })}\n\n`);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, calls, headers, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

const tree = baseTree({
  org: { version: 1, name: 'org', models: { allow: ['team-*'] }, mcp: { allow: ['docs'] }, tools: { deny: ['mcp__docs__delete_all'] }, git: { repos: ['acme/app'], protect: ['refs/heads/main'] }, approvers: { roles: ['lead'], separate: true } },
});

interface Setup {
  readonly team: Team;
  readonly mcp: FakeMcp;
  readonly token: string;
  readonly remoteDir: string;
}

async function withTools(run: (setup: Setup) => Promise<void>, claims: Record<string, unknown> = { email: 'ana@example.com', department: 'eng', groups: [] }): Promise<void> {
  const mcp = await fakeMcp();
  // The remote is a bare repository on disk, named by a file URL, so the push really happens.
  const remoteDir = await mkdtemp(join(tmpdir(), 'hn-remote-'));
  await git(['init', '--bare', '--quiet'], { cwd: remoteDir });
  const team = await startTeam({
    tree,
    env: { DOCS_TOKEN: `Bearer ${MCP_SECRET}`, EVIL_TOKEN: 'x', GH_TOKEN: GIT_SECRET },
    tools: {
      mcp: [{ name: 'docs', url: mcp.url, headers: { Authorization: 'DOCS_TOKEN' } }, { name: 'evil', url: mcp.url, headers: { Authorization: 'EVIL_TOKEN' } }],
      git: [{ repo: 'acme/app', remote: pathToFileURL(remoteDir).href, tokenEnv: 'GH_TOKEN' }, { repo: 'acme/other', remote: pathToFileURL(remoteDir).href }],
    },
  });
  try {
    const ana = await team.login(claims);
    await run({ team, mcp, token: await ana.session('t-1'), remoteDir });
  } finally {
    await team.close();
    await mcp.close();
    await rm(remoteDir, { recursive: true, force: true });
  }
}

async function callTool(team: Team, token: string, name: string, args: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await team.raw('/v1/tools/call', { token, session: 't-1', body: { name, args } });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe('server-side tools on the broker', () => {
  it('lists only the tools this person may use, and calls MCP with a credential the client never sees', async () => {
    await withTools(async ({ team, mcp, token }) => {
      const listed = (await (await team.raw('/v1/tools', { token, session: 't-1' })).json()) as { tools: { name: string }[] };
      assert.deepEqual(listed.tools.map((tool) => tool.name), ['mcp__docs__search', 'git_push']);
      const found = await callTool(team, token, 'mcp__docs__search', { q: 'deploy' });
      assert.deepEqual(found, { status: 200, body: { ok: true, text: 'found: {"q":"deploy"}' } });
      assert.ok(mcp.headers.length > 0 && mcp.headers.every((headers) => headers['authorization'] === `Bearer ${MCP_SECRET}`), 'the broker sent its credential');
      assert.ok(!JSON.stringify(listed).includes(MCP_SECRET) && !JSON.stringify(found).includes(MCP_SECRET));
    });
  });

  it('refuses a denied tool and a server the policy does not allow, and never calls them', async () => {
    await withTools(async ({ team, mcp, token }) => {
      assert.equal((await callTool(team, token, 'mcp__docs__delete_all', {})).status, 403);
      assert.equal((await callTool(team, token, 'mcp__evil__search', {})).status, 403);
      assert.equal((await callTool(team, token, 'mcp__nobody__x', {})).status, 403);
      assert.ok(!mcp.calls.includes('call delete_all'));
      assert.ok(team.audit.some((row) => row.type === 'broker/tool-refused' && row.data['tool'] === 'mcp__docs__delete_all'));
    });
  });

  it('pushes a bundle to an allowed repository and branch, and refuses protected branches, other repositories and bad names', async () => {
    await withTools(async ({ team, token, remoteDir }) => {
      const work = join(team.dir, 'work');
      await mkdir(work, { recursive: true });
      await git(['init', '--quiet'], { cwd: work });
      await writeFile(join(work, 'a.txt'), 'hello\n');
      await git(['add', 'a.txt'], { cwd: work });
      await git(['commit', '--quiet', '-m', 'first'], { cwd: work });
      const sha = (await git(['rev-parse', 'HEAD'], { cwd: work })).stdout.trim();
      await git(['bundle', 'create', '--quiet', join(team.dir, 'b.bundle'), 'HEAD'], { cwd: work });
      const bundle = (await readFile(join(team.dir, 'b.bundle'))).toString('base64');

      const pushed = await callTool(team, token, 'git_push', { repo: 'acme/app', branch: 'feature/x', bundle });
      assert.equal(pushed.body['ok'], true, String(pushed.body['text']));
      assert.equal((await git(['rev-parse', 'refs/heads/feature/x'], { cwd: remoteDir })).stdout.trim(), sha, 'the commit reached the remote');
      assert.ok(!JSON.stringify(pushed).includes(GIT_SECRET));

      assert.match(String((await callTool(team, token, 'git_push', { repo: 'acme/app', branch: 'main', bundle })).body['text']), /This needs an approval\. Request [0-9a-f]{12} is waiting/);
      assert.equal((await git(['rev-parse', '--verify', '--quiet', 'refs/heads/main'], { cwd: remoteDir, check: false })).code, 1, 'main was not pushed');
      assert.match(String((await callTool(team, token, 'git_push', { repo: 'acme/other', branch: 'x', bundle })).body['text']), /not allowed/);
      for (const branch of ['../main', '-f', 'a..b', 'x.lock', '']) assert.equal((await callTool(team, token, 'git_push', { repo: 'acme/app', branch, bundle })).body['ok'], false, branch);
      assert.ok(team.audit.some((row) => row.type === 'broker/git-push' && row.data['commit'] === sha && row.data['ok'] === true));
    });
  });
});

async function commitAndBundle(team: Team, text: string): Promise<{ sha: string; bundle: string }> {
  const work = join(team.dir, 'work');
  await mkdir(work, { recursive: true });
  await git(['init', '--quiet'], { cwd: work });
  await writeFile(join(work, 'a.txt'), text);
  await git(['add', 'a.txt'], { cwd: work });
  await git(['commit', '--quiet', '-m', text], { cwd: work });
  const sha = (await git(['rev-parse', 'HEAD'], { cwd: work })).stdout.trim();
  await git(['bundle', 'create', '--quiet', join(team.dir, 'b.bundle'), 'HEAD'], { cwd: work });
  return { sha, bundle: (await readFile(join(team.dir, 'b.bundle'))).toString('base64') };
}

describe('approvals on the broker', () => {
  it('a requester cannot clear their own request, a non-approver cannot clear it, and an approval is used once for one commit', async () => {
    await withTools(async ({ team, token, remoteDir }) => {
      const first = await commitAndBundle(team, 'one');
      const asked = String((await callTool(team, token, 'git_push', { repo: 'acme/app', branch: 'main', bundle: first.bundle })).body['text']);
      const id = /Request ([0-9a-f]{12})/.exec(asked)?.[1] as string;
      assert.ok(id !== undefined, asked);
      const decide = async (session: string, who: string, decision: string): Promise<number> => (await team.raw('/v1/approvals/decide', { token: who, session, body: { id, decision } })).status;

      assert.equal(await decide('t-1', token, 'approve'), 403, 'ana is a lead, but asked, and separate is on');
      const bo = await team.login({ email: 'bo@example.com', department: 'eng', groups: [] });
      const boToken = await bo.session('t-bo');
      assert.equal(await decide('t-bo', boToken, 'approve'), 403, 'bo is not an approver');
      const listedForBo = (await (await team.raw('/v1/approvals', { token: boToken, session: 't-bo' })).json()) as { requests: unknown[] };
      assert.deepEqual(listedForBo.requests, [], 'bo is not shown requests he cannot decide');
      const cy = await team.login({ email: 'cy@example.com', department: 'eng', groups: ['lead'] });
      const cyToken = await cy.session('t-cy');
      const listed = (await (await team.raw('/v1/approvals', { token: cyToken, session: 't-cy' })).json()) as { requests: { id: string; action: string }[] };
      assert.equal(listed.requests[0]?.id, id);
      assert.match(listed.requests[0]?.action ?? '', new RegExp(first.sha));
      assert.equal(await decide('t-cy', cyToken, 'approve'), 200);
      assert.equal(await decide('t-cy', cyToken, 'approve'), 409, 'decided once');

      const pushed = await callTool(team, token, 'git_push', { repo: 'acme/app', branch: 'main', bundle: first.bundle });
      assert.equal(pushed.body['ok'], true, String(pushed.body['text']));
      assert.equal((await git(['rev-parse', 'refs/heads/main'], { cwd: remoteDir })).stdout.trim(), first.sha);
      assert.match(String((await callTool(team, token, 'git_push', { repo: 'acme/app', branch: 'main', bundle: first.bundle })).body['text']), /needs an approval/, 'the approval was used up');
      const second = await commitAndBundle(team, 'two');
      assert.match(String((await callTool(team, token, 'git_push', { repo: 'acme/app', branch: 'main', bundle: second.bundle })).body['text']), /needs an approval/, 'another commit needs its own approval');
      assert.ok(team.audit.some((row) => row.type === 'broker/approval-decided' && row.data['approver'] === 'cy@example.com' && row.data['requester'] === 'ana@example.com'));
      assert.ok(team.audit.some((row) => row.type === 'broker/approval-refused' && row.data['approver'] === 'ana@example.com'));
    }, { email: 'ana@example.com', department: 'eng', groups: ['lead'] });
  });
});
