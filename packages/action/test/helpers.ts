import { createServer, type IncomingMessage, type Server } from 'node:http';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { GitHubApi } from '../src/github.ts';
import { git } from '../src/proc.ts';

/** Runs git in a fixture with an identity, and fails loudly with git's own words. */
export async function g(cwd: string, ...args: string[]): Promise<string> {
  const ran = await git(['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'init.defaultBranch=main', ...args], { cwd });
  if (ran.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${ran.stderr}`);
  return ran.stdout.toString('utf8');
}

/** A working repository with a bare "origin" to push to, both under `top`. */
export async function repoWith(top: string, files: Record<string, string>): Promise<{ work: string; origin: string }> {
  const work = join(top, 'work');
  const origin = join(top, 'origin.git');
  await mkdir(work, { recursive: true });
  await mkdir(origin, { recursive: true });
  await g(origin, 'init', '--bare', '-q');
  await g(work, 'init', '-q');
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(work, path)), { recursive: true });
    await writeFile(join(work, path), text);
  }
  await g(work, 'add', '-A');
  await g(work, 'commit', '-q', '-m', 'start');
  await g(work, 'branch', '-M', 'main');
  await g(work, 'remote', 'add', 'origin', origin);
  await g(work, 'push', '-q', 'origin', 'main');
  return { work, origin };
}

/** What GitHub would be told, with roles set per login. */
export class FakeGitHub implements GitHubApi {
  readonly roles = new Map<string, string>();
  readonly pulls: { repo: string; title: string; head: string; base: string; body: string }[] = [];
  readonly comments: { repo: string; issue: number; body: string }[] = [];
  asked = 0;
  failRole = false;
  async roleOf(_repo: string, login: string): Promise<string> {
    this.asked += 1;
    if (this.failRole) throw new Error('GitHub is down.');
    return this.roles.get(login) ?? 'none';
  }
  async createPullRequest(repo: string, input: { title: string; head: string; base: string; body: string }): Promise<{ number: number; url: string }> {
    this.pulls.push({ repo, ...input });
    return { number: this.pulls.length, url: `https://github.example/${repo}/pull/${this.pulls.length}` };
  }
  async comment(repo: string, issue: number, body: string): Promise<void> {
    this.comments.push({ repo, issue, body });
  }
}

export interface Seen {
  readonly method: string;
  readonly url: string;
  readonly auth: string | undefined;
  readonly body: string;
}

const readBody = (request: IncomingMessage): Promise<string> =>
  new Promise((resolve) => {
    let text = '';
    request.on('data', (chunk: Buffer) => (text += chunk.toString()));
    request.on('end', () => resolve(text));
  });

/** A tiny server that speaks enough of GitHub's REST API for RestGitHub, and records every request. */
export async function startFakeApi(handler: (seen: Seen) => { status: number; body?: unknown; headers?: Record<string, string> }): Promise<{ url: string; seen: Seen[]; close(): Promise<void> }> {
  const seen: Seen[] = [];
  const server: Server = createServer(async (request, response) => {
    const entry: Seen = { method: request.method ?? '', url: request.url ?? '', auth: request.headers.authorization, body: await readBody(request) };
    seen.push(entry);
    const answer = handler(entry);
    response.writeHead(answer.status, { 'content-type': 'application/json', ...(answer.headers ?? {}) });
    response.end(answer.body === undefined ? '' : JSON.stringify(answer.body));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  return { url: `http://127.0.0.1:${port}`, seen, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

/** An `issues` / `labeled` event as GitHub writes it, with anything overridden. */
export function labeledEvent(overrides: { issue?: Record<string, unknown>; sender?: Record<string, unknown>; label?: string; action?: string; repository?: Record<string, unknown> } = {}): Record<string, unknown> {
  return {
    action: overrides.action ?? 'labeled',
    label: { name: overrides.label ?? 'hn' },
    issue: { number: 7, state: 'open', title: 'Greeting is wrong', body: 'Say hello, not hullo.', user: { login: 'reporter' }, ...(overrides.issue ?? {}) },
    repository: { full_name: 'acme/widgets', default_branch: 'main', ...(overrides.repository ?? {}) },
    sender: { login: 'maintainer', type: 'User', ...(overrides.sender ?? {}) },
  };
}
