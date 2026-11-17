import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { git } from '@hn/operations';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import { Harness, createTeamTools, loadTeamLogin, runApprovalsCommand, runLoginCommand } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';
import { UPSTREAM_KEY, baseTree, startTeam, type Team } from '../../broker/test/fixture.ts';

/** Team mode end to end: `hn login` through the broker, then a real session that holds no model key. */

async function login(team: Team, home: string, claims: Record<string, unknown>): Promise<string> {
  team.idp.user = { sub: `sub-${String(claims['email'])}`, ...claims };
  let shown = '';
  const code = await runLoginCommand({
    positionals: ['login', team.broker.url],
    home,
    out: (text) => {
      shown += text;
      const match = /enter the code ([A-F0-9]+)/.exec(text);
      if (match !== null) team.idp.decide(match[1] as string, true);
    },
    wait: async () => undefined,
  });
  assert.equal(code, 0);
  return shown;
}

const harnessFor = (root: string, home: string, team: Awaited<ReturnType<typeof loadTeamLogin>>) =>
  new Harness({ workdir: root, model: 'team-large', team, window: 64_000, verify: 'off', keys: KeyStore.capture({}), env: { HN_HOME: home } } as never);

describe('team mode on the laptop', () => {
  it('logs in, then runs a session through the broker with no key on the laptop', { timeout: 60_000 }, async () => {
    const team = await startTeam();
    try {
      await withTempDir(async (dir) => {
        const root = await realpath(dir);
        const home = join(root, '.home');
        const shown = await login(team, home, { email: 'ana@example.com', department: 'eng', groups: ['dev'] });
        assert.match(shown, /Logged in as ana@example\.com \(eng\)/);
        const saved = await readFile(join(home, 'team.json'), 'utf8');
        assert.ok(!saved.includes(UPSTREAM_KEY), 'the login holds no model key');
        const harness = harnessFor(root, home, await loadTeamLogin(home));
        try {
          const result = await harness.run('say hello');
          assert.equal(result.end, 'done');
          assert.match(result.text, /hello from upstream/);
          assert.equal(team.upstream.headers[0]?.['authorization'], `Bearer ${UPSTREAM_KEY}`);
          assert.ok(team.audit.some((row) => row.type === 'broker/model' && row.data['user'] === 'ana@example.com'));
        } finally {
          await harness.close();
        }
        // The serial of the tree in use is remembered, so an older one is refused next time.
        assert.equal((await loadTeamLogin(home)).seen?.serial, 1);
      });
    } finally {
      await team.close();
    }
  });

  it('refuses a policy signed by a key other than the one pinned at login', { timeout: 60_000 }, async () => {
    const team = await startTeam();
    try {
      await withTempDir(async (dir) => {
        const root = await realpath(dir);
        const home = join(root, '.home');
        await login(team, home, { email: 'ana@example.com', department: 'eng', groups: [] });
        const login_ = await loadTeamLogin(home);
        const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
        await writeFile(join(home, 'team.json'), JSON.stringify({ ...login_, policyKeys: { 'org-1': other } }));
        const harness = harnessFor(root, home, await loadTeamLogin(home));
        try {
          await assert.rejects(harness.run('hi'), /changed or signed by someone else/);
        } finally {
          await harness.close().catch(() => undefined);
        }
      });
    } finally {
      await team.close();
    }
  });

  it('offers the broker tools this person may use, and git_push sends the project HEAD for the broker to push', { timeout: 60_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const remote = join(root, 'remote.git');
      const project = join(root, 'project');
      await mkdir(remote);
      await mkdir(project);
      await git(['init', '--bare', '--quiet'], { cwd: remote });
      await git(['init', '--quiet'], { cwd: project });
      await writeFile(join(project, 'a.txt'), 'one\n');
      await git(['add', 'a.txt'], { cwd: project });
      await git(['commit', '--quiet', '-m', 'one'], { cwd: project });
      const tree = baseTree({ org: { version: 1, name: 'org', models: { allow: ['team-*'] }, git: { repos: ['acme/app'], protect: ['refs/heads/main'] }, approvers: { roles: ['lead'], separate: true } } });
      const team = await startTeam({ tree, tools: { git: [{ repo: 'acme/app', remote: pathToFileURL(remote).href }] } });
      try {
        const home = join(root, '.home');
        await login(team, home, { email: 'ana@example.com', department: 'eng', groups: [] });
        const notes: string[] = [];
        const tools = await createTeamTools(await loadTeamLogin(home), 'tt-1', project, notes);
        assert.deepEqual(tools.map((tool) => [tool.name, tool.effect, tool.deferred]), [['git_push', 'external', true], ['team_memory_search', 'observe', true], ['team_memory_save', 'external', true]]);
        assert.equal(tools[2]?.requiresHuman?.({}), true, 'a team memory write always needs a person');
        const push = tools[0]!;
        const context = {} as never;
        const done = await push.execute({ repo: 'acme/app', branch: 'feature' }, context);
        assert.equal(done.isError, undefined, done.content);
        assert.equal((await git(['rev-parse', 'refs/heads/feature'], { cwd: remote })).stdout.trim(), (await git(['rev-parse', 'HEAD'], { cwd: project })).stdout.trim());
        const refused = await push.execute({ repo: 'acme/app', branch: 'main' }, context);
        assert.equal(refused.isError, true);
        assert.match(refused.content, /needs an approval/);
        // A lead, logged in on another machine, sees the request and approves it; the same push then goes through.
        const leadHome = join(root, '.lead');
        await login(team, leadHome, { email: 'cy@example.com', department: 'eng', groups: ['lead'] });
        let listed = '';
        assert.equal(await runApprovalsCommand({ positionals: ['approvals'], home: leadHome, out: (text) => (listed += text) }), 0);
        const id = /^([0-9a-f]{12})  ana@example\.com  git_push acme\/app refs\/heads\/main /m.exec(listed)?.[1];
        assert.ok(id !== undefined, listed);
        let decided = '';
        await runApprovalsCommand({ positionals: ['approvals', 'approve', id], home: leadHome, out: (text) => (decided += text) });
        assert.match(decided, /is approved/);
        const pushed = await push.execute({ repo: 'acme/app', branch: 'main' }, context);
        assert.equal(pushed.isError, undefined, pushed.content);
      } finally {
        await team.close();
      }
    });
  });

  it('a person whose OU denies bash never receives a bash call, whatever the model wants', { timeout: 60_000 }, async () => {
    const team = await startTeam({ decide: (request) => (request.messages.some((message) => message.role === 'tool') ? { text: 'done' } : { calls: [{ id: 'b1', name: 'bash', args: { command: 'echo pwned > pwned.txt' } }] }) });
    try {
      await withTempDir(async (dir) => {
        const root = await realpath(dir);
        const home = join(root, '.home');
        await login(team, home, { email: 'cy@example.com', department: 'hr', groups: [] });
        const harness = harnessFor(root, home, await loadTeamLogin(home));
        try {
          const result = await harness.run('run it');
          assert.match(result.text, /Removed 1 call\(s\) to tools you may not use: bash/);
          assert.equal(team.upstream.requests[0]?.tools?.some((item) => item.function?.name === 'bash'), false, 'bash was not offered upstream');
          await assert.rejects(readFile(join(root, 'pwned.txt')));
        } finally {
          await harness.close();
        }
      });
    } finally {
      await team.close();
    }
  });
});
