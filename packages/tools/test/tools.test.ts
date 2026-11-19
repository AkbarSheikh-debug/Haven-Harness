import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, realpath, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { ToolDispatcher, ToolOutcome } from '@hn/loop';
import { localOperations } from '@hn/operations';
import { Gate, Jail, type Approver } from '@hn/security';
import { MAX_INLINE_CHARS, createDispatcher, createShellTools, decodeText, encodeText, type ToolDefinition } from '@hn/tools';
import { withTempDir } from '@hn/testkit';

interface Kit {
  tools: ToolDispatcher;
  call(name: string, args?: unknown): Promise<ToolOutcome>;
  dir: string;
}

let counter = 0;

async function kit(directory: string, mode = 'accept-edits', approver: Approver = async () => 'once', extraTools?: ToolDefinition[]): Promise<Kit> {
  const dir = await realpath(directory);
  const ops = localOperations(join(dir, '..', `spill-${(counter += 1)}`));
  const gate = new Gate({
    mode,
    workdir: dir,
    audit: () => undefined,
    jail: new Jail({ root: dir, realpath: ops.read.realpath }),
    approver,
  });
  const tools = createDispatcher({ gate, ops, workdir: dir, ...(extraTools === undefined ? {} : { extraTools }) });
  return {
    tools,
    dir,
    call: (name, args = {}) => {
      const request = { id: `c${(counter += 1)}`, name, args };
      const check = tools.check(request);
      if (check.kind !== 'ok') return Promise.resolve({ content: check.message, isError: true, origin: 'harness' });
      return tools.run({ ...request, name: check.name, args: check.args }, new AbortController().signal);
    },
  };
}

describe('read_file', () => {
  it('numbers lines and pages long files', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.txt'), Array.from({ length: 5 }, (_, i) => `line ${i + 1}`).join('\n'));
      const { call } = await kit(dir);
      assert.equal((await call('read_file', { path: 'a.txt', offset: 4 })).content, '4\tline 4\n5\tline 5');
      assert.match((await call('read_file', { path: 'a.txt', limit: 2 })).content, /Use offset 3 to continue/);
    });
  });

  it('never returns nothing', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'empty'), '');
      assert.equal((await (await kit(dir)).call('read_file', { path: 'empty' })).content, '(empty file)');
    });
  });

  it('refuses binary, and reads UTF-16', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'bin'), Buffer.from([1, 0, 2, 0]));
      await writeFile(join(dir, 'u16'), encodeText('hello', 'utf16le'));
      const { call } = await kit(dir);
      assert.match((await call('read_file', { path: 'bin' })).content, /FS_BINARY/);
      assert.equal((await call('read_file', { path: 'u16' })).content, '1\thello');
    });
  });

  it('turns a missing file into a message', async () => {
    await withTempDir(async (dir) => {
      const result = await (await kit(dir)).call('read_file', { path: 'nope' });
      assert.equal(result.isError, true);
    });
  });
});

describe('edit_file', () => {
  it('needs the file read first, and notices a change since', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.ts'), 'one');
      const { call } = await kit(dir);
      assert.match((await call('edit_file', { path: 'a.ts', old_string: 'one', new_string: 'two' })).content, /FS_NOT_OBSERVED/);
      await call('read_file', { path: 'a.ts' });
      await writeFile(join(dir, 'a.ts'), 'changed by someone else');
      assert.match((await call('edit_file', { path: 'a.ts', old_string: 'one', new_string: 'two' })).content, /FS_STALE_VERSION/);
    });
  });

  it('says what to do when the text is missing or not unique', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.ts'), 'x x');
      const { call } = await kit(dir);
      await call('read_file', { path: 'a.ts' });
      assert.match((await call('edit_file', { path: 'a.ts', old_string: 'y', new_string: 'z' })).content, /EDIT_NOT_FOUND.*copy the text exactly/);
      assert.match((await call('edit_file', { path: 'a.ts', old_string: 'x', new_string: 'z' })).content, /EDIT_NOT_UNIQUE.*2 times/);
      await call('edit_file', { path: 'a.ts', old_string: 'x', new_string: 'z', replace_all: true });
      assert.equal(await readFile(join(dir, 'a.ts'), 'utf8'), 'z z');
    });
  });

  it('keeps editing after its own edit without a new read', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.ts'), 'one two');
      const { call } = await kit(dir);
      await call('read_file', { path: 'a.ts' });
      await call('edit_file', { path: 'a.ts', old_string: 'one', new_string: '1' });
      await call('edit_file', { path: 'a.ts', old_string: 'two', new_string: '2' });
      assert.equal(await readFile(join(dir, 'a.ts'), 'utf8'), '1 2');
    });
  });

  it('preserves CRLF and a BOM', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.txt'), encodeText('a\r\nb\r\nc\r\n', 'utf8-bom'));
      const { call } = await kit(dir);
      await call('read_file', { path: 'a.txt' });
      const result = await call('edit_file', { path: 'a.txt', old_string: 'a\nb', new_string: 'x\ny' });
      assert.equal(result.isError, false, result.content);
      assert.deepEqual(await readFile(join(dir, 'a.txt')), encodeText('x\r\ny\r\nc\r\n', 'utf8-bom'));
    });
  });

  it('edits UTF-16 in place', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.txt'), encodeText('hello', 'utf16be'));
      const { call } = await kit(dir);
      await call('read_file', { path: 'a.txt' });
      await call('edit_file', { path: 'a.txt', old_string: 'hello', new_string: 'bye' });
      assert.equal(decodeText(await readFile(join(dir, 'a.txt')))?.text, 'bye');
    });
  });

  it('serializes parallel writes to one file, so neither is lost', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.ts'), 'one two');
      const { call } = await kit(dir);
      await call('read_file', { path: 'a.ts' });
      await Promise.all([
        call('edit_file', { path: 'a.ts', old_string: 'one', new_string: '1' }),
        call('edit_file', { path: 'a.ts', old_string: 'two', new_string: '2' }),
      ]);
      assert.equal(await readFile(join(dir, 'a.ts'), 'utf8'), '1 2');
    });
  });
});

describe('write_file', () => {
  it('creates new files and folders, but will not blindly replace', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir);
      await call('write_file', { path: 'new/deep/a.ts', content: 'x' });
      assert.equal(await readFile(join(dir, 'new/deep/a.ts'), 'utf8'), 'x');
      await writeFile(join(dir, 'old.ts'), 'precious');
      assert.match((await call('write_file', { path: 'old.ts', content: 'y' })).content, /FS_NOT_OBSERVED/);
      assert.equal(await readFile(join(dir, 'old.ts'), 'utf8'), 'precious');
    });
  });

  it('refuses to write the redaction sentinel back over a real secret', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'c.env'), 'TOKEN=real-value\nNAME=a\n');
      const { call } = await kit(dir);
      await call('read_file', { path: 'c.env' });
      assert.match((await call('write_file', { path: 'c.env', content: 'TOKEN=[REDACTED]\nNAME=a\n' })).content, /REDACTED_WRITE/);
      assert.match(
        (await call('edit_file', { path: 'c.env', old_string: 'TOKEN=real-value', new_string: 'TOKEN=[REDACTED]' })).content,
        /REDACTED_WRITE/,
      );
      assert.equal(await readFile(join(dir, 'c.env'), 'utf8'), 'TOKEN=real-value\nNAME=a\n');
    });
  });
});

describe('bash', () => {
  it('returns output and exit codes, and never nothing', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir, 'safe');
      assert.equal((await call('bash', { command: 'echo hi' })).content, 'hi');
      assert.equal((await call('bash', { command: 'true' })).content, '(no output)');
      const failed = await call('bash', { command: 'echo oops >&2; exit 3' });
      assert.equal(failed.isError, true);
      assert.match(failed.content, /oops[\s\S]*Exit code 3/);
    });
  });

  it('stops a command that outlives its timeout, and its children', async () => {
    await withTempDir(async (dir) => {
      const started = Date.now();
      const result = await (await kit(dir, 'safe')).call('bash', {
        command: '(sleep 2; touch survived) & sleep 30',
        timeout_ms: 300,
      });
      assert.equal(result.isError, true);
      assert.match(result.content, /stopped after 300 ms/);
      assert.ok(Date.now() - started < 10_000);
      await new Promise((resolve) => setTimeout(resolve, 2_500));
      assert.equal((await readdir(dir)).includes('survived'), false, 'the background child must die too');
    });
  });

  it('shows the head and tail of huge output and keeps the rest in a file', async () => {
    await withTempDir(async (dir) => {
      const result = await (await kit(dir, 'safe')).call('bash', { command: `printf 'START'; head -c 200000 /dev/zero | tr '\\0' 'x'; printf 'END'` });
      assert.match(result.content, /^START/);
      assert.match(result.content, /bytes omitted/);
      assert.match(result.content, /full stdout: /);
      assert.ok(result.content.length < 70_000);
    });
  });

  it('never sees a key that was taken from the environment', async () => {
    await withTempDir(async (dir) => {
      delete process.env['ANTHROPIC_API_KEY'];
      const result = await (await kit(dir, 'safe')).call('bash', { command: 'echo "[${ANTHROPIC_API_KEY}]"' });
      assert.equal(result.content, '[]');
    });
  });
});

describe('grep and list_files', () => {
  it('search and respect .gitignore', async () => {
    await withTempDir(async (dir) => {
      await mkdir(join(dir, '.git'));
      await writeFile(join(dir, '.gitignore'), 'ignored.ts\n');
      await writeFile(join(dir, 'a.ts'), 'needle\n');
      await writeFile(join(dir, 'ignored.ts'), 'needle\n');
      const { call } = await kit(dir);
      const grep = (await call('grep', { pattern: 'needle' })).content;
      assert.match(grep, /a\.ts:1:needle/);
      assert.doesNotMatch(grep, /ignored/);
      const list = (await call('list_files')).content;
      assert.match(list, /a\.ts/);
      assert.doesNotMatch(list, /ignored\.ts/);
    });
  });

  it('say so when nothing matches', async () => {
    await withTempDir(async (dir) => {
      assert.equal((await (await kit(dir)).call('grep', { pattern: 'nothing' })).content, 'No matches.');
    });
  });

  it('say plainly that a path is missing, rather than blaming ripgrep (found live)', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir);
      for (const result of [await call('list_files', { path: 'test' }), await call('grep', { pattern: 'x', path: 'test' })]) {
        assert.equal(result.isError, true);
        assert.match(result.content, /There is no such file or folder in the project\./);
        assert.doesNotMatch(result.content, /ENOENT|rg\.exe|ripgrep/);
      }
    });
  });

  it('search one file when the path is a file (found live: a file path crashed the spawn)', async () => {
    await withTempDir(async (dir) => {
      await mkdir(join(dir, 'src'));
      await writeFile(join(dir, 'src', 'api.js'), 'export function createUser() {}\n');
      await writeFile(join(dir, 'src', 'other.js'), 'createUser();\n');
      const { call } = await kit(dir);
      const result = await call('grep', { pattern: 'createUser', path: 'src/api.js' });
      assert.equal(result.isError, false, result.content);
      assert.match(result.content, /api\.js:1:export function createUser/);
      assert.doesNotMatch(result.content, /other\.js/);
      assert.match((await call('list_files', { path: 'src/api.js' })).content, /api\.js/);
    });
  });

  it('take an absolute path to the project folder or inside it, as a task names it (found on Linux in a benchmark: list_files /app failed)', async () => {
    await withTempDir(async (dir) => {
      await mkdir(join(dir, 'src'));
      await writeFile(join(dir, 'top.txt'), 'needle at the top\n');
      await writeFile(join(dir, 'src', 'api.js'), 'needle in src\n');
      const { call } = await kit(dir);
      for (const root of [dir, `${dir}/`, `${dir}${process.platform === 'win32' ? '\\' : '/'}.`]) {
        const list = await call('list_files', { path: root });
        assert.equal(list.isError, false, `${root}: ${list.content}`);
        assert.match(list.content, /top\.txt/);
        assert.match(list.content, /api\.js/);
        const found = await call('grep', { pattern: 'needle', path: root });
        assert.equal(found.isError, false, `${root}: ${found.content}`);
        assert.match(found.content, /top\.txt:1:needle at the top/);
      }
      const inside = join(dir, 'src');
      assert.match((await call('list_files', { path: inside })).content, /api\.js/);
      assert.doesNotMatch((await call('list_files', { path: inside })).content, /top\.txt/, 'a folder inside lists only itself');
      assert.match((await call('grep', { pattern: 'needle', path: join(inside, 'api.js') })).content, /api\.js:1:needle in src/);
      assert.match((await call('grep', { pattern: 'needle', path: 'src' })).content, /api\.js:1:needle in src/, 'a relative path still works');
    });
  });

  it('attack: the search tools refuse a path outside the project themselves, without relying on the gate', async () => {
    await withTempDir(async (dir) => {
      const project = join(dir, 'project');
      const sibling = join(dir, 'sibling');
      await mkdir(project);
      await mkdir(sibling);
      await writeFile(join(sibling, 'entry-7f3a.txt'), 'LEAKED-CONTENT-7f3a\n');
      const ops = localOperations(join(dir, 'spill'));
      const [, grep, list] = createShellTools() as [ToolDefinition, ToolDefinition, ToolDefinition];
      // The tools are called directly, so the gate and the jail never see these paths: whether they stay inside is
      // decided by the tools alone.
      const outside = [sibling, join(project, '..', 'sibling'), `${project}-other`, '../sibling', join(sibling, 'entry-7f3a.txt')];
      if (process.platform === 'win32') outside.push(`${project.startsWith('D:') ? 'C:' : 'D:'}\\somewhere`);
      for (const path of outside) {
        await assert.rejects(list.execute({ path }, { workdir: project, ops } as never), /outside the project/, `list_files ${path}`);
        await assert.rejects(grep.execute({ pattern: 'LEAKED', path }, { workdir: project, ops } as never), /outside the project/, `grep ${path}`);
      }
      // And a path that is inside still works through the same call.
      const fine = await list.execute({ path: project }, { workdir: project, ops } as never);
      assert.equal(fine.isError ?? false, false);
    });
  });

  it('attack: an absolute path outside the project is still refused, and lists nothing of it', async () => {
    await withTempDir(async (dir) => {
      const project = join(dir, 'project');
      const sibling = join(dir, 'sibling');
      await mkdir(project);
      await mkdir(sibling);
      await writeFile(join(sibling, 'entry-7f3a.txt'), 'LEAKED-CONTENT-7f3a\n');
      const { call } = await kit(project);
      // A refusal names the path that was asked for, so what must be absent is what lives there: the entries of a
      // folder, and the contents of a file.
      for (const path of [sibling, join(project, '..', 'sibling'), join(sibling, 'entry-7f3a.txt')]) {
        for (const result of [await call('list_files', { path }), await call('grep', { pattern: 'LEAKED', path })]) {
          assert.equal(result.isError, true, `${path} was not refused: ${result.content}`);
          assert.doesNotMatch(result.content, /LEAKED-CONTENT-7f3a/);
        }
        assert.doesNotMatch((await call('list_files', { path: path === join(sibling, 'entry-7f3a.txt') ? sibling : path })).content, /entry-7f3a\.txt\s*$/m, 'no entry of the outside folder is listed');
      }
      assert.equal((await call('list_files', { path: `${project}-other` })).isError, true, 'a folder that only shares the prefix is outside too');
    });
  });

  it('attack: naming a secret file as the search path reveals nothing of it', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, '.env'), 'API_KEY=sk-live-0123456789abcdef0123456789abcdef\n');
      const { call } = await kit(dir);
      for (const result of [await call('grep', { pattern: 'API_KEY', path: '.env' }), await call('list_files', { path: '.env' })]) {
        assert.doesNotMatch(result.content, /sk-live|API_KEY=/);
      }
    });
  });

  it('refuse a glob that would become a flag', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.ts'), 'x\n');
      assert.match((await (await kit(dir)).call('grep', { pattern: 'x', glob: '--pre=evil' })).content, /cannot start with a dash/);
    });
  });
});

describe('attack: reading a secret', () => {
  const SECRET = 'sk-canary-do-not-leak';

  for (const name of ['.env', '.env.local', '.ENV', 'nested/.env', 'server.pem', '.git-credentials']) {
    it(`no tool returns the contents of ${name}`, async () => {
      await withTempDir(async (dir) => {
        await mkdir(join(dir, 'nested'), { recursive: true });
        await writeFile(join(dir, name), `TOKEN=${SECRET}\n`);
        await writeFile(join(dir, 'ok.ts'), 'fine\n');
        const { call } = await kit(dir, 'safe');
        const results = await Promise.all([
          call('read_file', { path: name }),
          call('grep', { pattern: 'TOKEN' }),
          call('grep', { pattern: 'TOKEN', path: 'nested' }),
          call('grep', { pattern: 'TOKEN', glob: '*' }),
          call('grep', { pattern: 'TOKEN', glob: '.env*' }),
          call('list_files'),
          call('bash', { command: `cat ${name}` }),
          call('edit_file', { path: name, old_string: 'x', new_string: 'y' }),
          call('write_file', { path: name, content: 'y' }),
        ]);
        for (const result of results) assert.equal(result.content.includes(SECRET), false, result.content);
        assert.equal((await readFile(join(dir, name), 'utf8')).includes(SECRET), true, 'and it was not overwritten');
      });
    });
  }

  it('does not follow a link to a secret', async (t) => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, '.env'), `TOKEN=${SECRET}\n`);
      try {
        await symlink(join(dir, '.env'), join(dir, 'notes.txt'));
      } catch {
        t.skip('this machine cannot create symlinks');
        return;
      }
      const result = await (await kit(dir, 'safe')).call('read_file', { path: 'notes.txt' });
      assert.equal(result.content.includes(SECRET), false);
    });
  });

  it('does not leave the project', async () => {
    await withTempDir(async (dir) => {
      await mkdir(join(dir, 'project'));
      await writeFile(join(dir, 'outside.txt'), SECRET);
      const { call } = await kit(join(dir, 'project'));
      for (const path of ['../outside.txt', join(dir, 'outside.txt')]) {
        assert.equal((await call('read_file', { path })).content.includes(SECRET), false);
        assert.match((await call('write_file', { path, content: 'x' })).content, /Blocked/);
      }
      assert.match((await call('grep', { pattern: 'x', path: '..' })).content, /Blocked/);
    });
  });
});

describe('attack: a search backend that leaks', () => {
  it('still filters secrets out of grep and list_files results', async () => {
    await withTempDir(async (directory) => {
      const dir = await realpath(directory);
      const real = localOperations(join(dir, '..', 'spill-leak'));
      const ops = {
        ...real,
        search: {
          grep: async () => ['./.env:1:TOKEN=sk-leak', './src/a.ts:3:fine'],
          listFiles: async () => ['.env.local', 'src/a.ts'],
        },
      };
      const gate = new Gate({
        mode: 'safe',
        workdir: dir,
        audit: () => undefined,
        jail: new Jail({ root: dir, realpath: real.read.realpath }),
      });
      const tools = createDispatcher({ gate, ops, workdir: dir });
      const run = (name: string, args: unknown) => tools.run({ id: `leak-${name}`, name, args }, new AbortController().signal);
      const grep = (await run('grep', { pattern: 'TOKEN' })).content;
      const list = (await run('list_files', {})).content;
      assert.equal(grep.includes('sk-leak'), false, 'the second layer must hold when the first fails');
      assert.match(grep, /src\/a\.ts/);
      assert.equal(list.includes('.env.local'), false);
      assert.match(list, /src\/a\.ts/);
    });
  });
});

describe('the dispatcher', () => {
  const extra: ToolDefinition = {
    name: 'deploy_site',
    description: 'Deploy the website',
    deferred: true,
    parameters: { type: 'object', properties: { env: { type: 'string' } }, required: ['env'], additionalProperties: false },
    effect: 'execution',
    concurrencySafe: false,
    paths: () => [],
    summary: (args) => `deploy ${String(args['env'])}`,
    execute: async () => ({ content: 'deployed' }),
  };

  it('keeps deferred tools out of the fixed list', async () => {
    await withTempDir(async (dir) => {
      const { tools } = await kit(dir, 'safe', undefined, [extra]);
      assert.deepEqual(
        tools.specs.map((spec) => spec.name),
        ['bash', 'edit_file', 'grep', 'list_files', 'read_file', 'write_file', 'tool_search', 'call_tool'],
      );
    });
  });

  it('lists the harness deferred tools for the reminder row, never one from an MCP server, and leaves tool_search as it was (found live)', async () => {
    await withTempDir(async (dir) => {
      const outside: ToolDefinition = { ...extra, name: 'mcp__evil__run', origin: 'mcp' };
      const dir2 = await realpath(dir);
      const ops = localOperations(join(dir2, '..', `spill-${(counter += 1)}`));
      const gate = new Gate({ mode: 'safe', workdir: dir2, audit: () => undefined, jail: new Jail({ root: dir2, realpath: ops.read.realpath }), approver: async () => 'once' });
      const dispatcher = createDispatcher({ gate, ops, workdir: dir2, extraTools: [extra, outside] });
      assert.deepEqual(dispatcher.deferredNames, ['deploy_site', 'read_image']);
      const plain = createDispatcher({ gate, ops, workdir: dir2 });
      assert.equal(JSON.stringify(dispatcher.specs), JSON.stringify(plain.specs), 'the cached prefix does not depend on the deferred set');
    });
  });

  it('never changes the tools bytes with the mode', async () => {
    await withTempDir(async (dir) => {
      const specs = async (mode: string) => JSON.stringify((await kit(dir, mode)).tools.specs);
      assert.equal(await specs('read-only'), await specs('safe'));
    });
  });

  it('attack: call_tool_unwrapped_before_gate. finds a deferred tool and runs it through the gate', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir, 'read-only', undefined, [extra]);
      assert.match((await call('tool_search', { query: 'deploy' })).content, /deploy_site/);
      const result = await call('call_tool', { name: 'deploy_site', args: { env: 'prod' } });
      assert.equal(result.isError, true, 'call_tool must not bypass read-only');
      assert.match(result.content, /read-only mode/);
    });
  });

  it('validates what call_tool wraps, and denies nesting', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir, 'safe', undefined, [extra]);
      assert.match((await call('call_tool', { name: 'deploy_site', args: {} })).content, /Missing required argument "env"/);
      assert.match((await call('call_tool', { name: 'call_tool', args: { name: 'bash', args: {} } })).content, /cannot call itself/);
    });
  });

  it('checks every call against the schema before it runs', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir);
      assert.match((await call('read_file', {})).content, /Missing required argument "path"/);
      assert.match((await call('read_file', { path: 1 })).content, /must be of type string/);
      assert.match((await call('read_file', { path: 'a', evil: 1 })).content, /Unknown argument "evil"/);
      assert.match((await call('read_file', { INVALID_JSON: '{"pa' })).content, /not valid JSON/);
      assert.match((await call('read_file', 'nope')).content, /must be a JSON object/);
    });
  });

  it('repairs an obvious name and rejects an unknown one', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a'), 'x');
      const { call } = await kit(dir);
      assert.equal((await call('Read-File', { path: 'a' })).content, '1\tx');
      assert.match((await call('nope')).content, /There is no tool called "nope"/);
    });
  });

  it('refuses a plugin that tries to replace a built-in', async () => {
    await withTempDir(async (dir) => {
      await assert.rejects(kit(dir, 'safe', undefined, [{ ...extra, name: 'bash' }]), /cannot be replaced/);
    });
  });

  it('runs nothing the gate stops', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir, 'read-only');
      const result = await call('bash', { command: 'touch pwned' });
      assert.equal(result.isError, true);
      assert.deepEqual((await readdir(dir)).includes('pwned'), false);
    });
  });

  it('spills an oversized result to a file', async () => {
    await withTempDir(async (dir) => {
      const big: ToolDefinition = { ...extra, name: 'big', deferred: false, effect: 'observe', execute: async () => ({ content: 'x'.repeat(MAX_INLINE_CHARS + 1) }) };
      const result = await (await kit(dir, 'safe', undefined, [big])).call('big', { env: 'a' });
      assert.match(result.content, /characters omitted\. Full output: /);
      assert.ok(result.content.length < 2_000);
    });
  });
});

describe('syntax warnings after an edit', () => {
  it('warns when an edit breaks a file that parsed, and still makes the edit', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'a.ts'), 'export const a = 1;\nexport const b = 2;\n');
      const { call } = await kit(dir);
      await call('read_file', { path: 'a.ts' });
      const result = await call('edit_file', { path: 'a.ts', old_string: 'export const b = 2;', new_string: 'export const b = ;' });
      assert.equal(result.isError, false);
      assert.match(result.content, /^Edited a\.ts\./);
      assert.match(result.content, /a\.ts no longer parses cleanly/);
      assert.match(result.content, /line 2/);
      assert.equal(await readFile(join(dir, 'a.ts'), 'utf8'), 'export const a = 1;\nexport const b = ;\n', 'the edit must still be made');
    });
  });

  it('says nothing for a valid edit, a fix, an edit to a broken file that is no worse, or a file it cannot check', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'ok.ts'), 'export const a = 1;\n');
      await writeFile(join(dir, 'broken.ts'), 'export const a = ;\nexport const b = 1;\n');
      await writeFile(join(dir, 'notes.txt'), 'plain {{{ text');
      const { call } = await kit(dir);
      for (const path of ['ok.ts', 'broken.ts', 'notes.txt']) await call('read_file', { path });
      assert.doesNotMatch((await call('edit_file', { path: 'ok.ts', old_string: 'a = 1', new_string: 'a = 2' })).content, /parses cleanly/);
      assert.doesNotMatch((await call('edit_file', { path: 'broken.ts', old_string: 'b = 1', new_string: 'b = 2' })).content, /parses cleanly/, 'the file was already broken and no worse');
      assert.doesNotMatch((await call('edit_file', { path: 'broken.ts', old_string: 'a = ;', new_string: 'a = 3;' })).content, /parses cleanly/, 'this fixed it');
      assert.doesNotMatch((await call('edit_file', { path: 'notes.txt', old_string: '{{{', new_string: '}}}' })).content, /parses cleanly/);
    });
  });

  it('warns about a new file that does not parse, and about a replaced one that stops parsing', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir);
      assert.match((await call('write_file', { path: 'new.py', content: 'def f(x)\n    return x\n' })).content, /new\.py no longer parses cleanly/);
      assert.doesNotMatch((await call('write_file', { path: 'good.py', content: 'def f(x):\n    return x\n' })).content, /parses cleanly/);
      await call('read_file', { path: 'good.py' });
      assert.match((await call('write_file', { path: 'good.py', content: 'def f(x)\n    return x\n' })).content, /good\.py no longer parses cleanly/);
    });
  });
});

describe('redaction of tool output', () => {
  const KEY = 'sk-ant-api03-Zq8vN2mXk4Lp7TrW9yBc3Dh6Fj1Gs5Aa';
  const leaky = (content: string): ToolDefinition => ({
    name: 'leaky',
    description: 'returns whatever it was built with',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    effect: 'observe',
    concurrencySafe: true,
    paths: () => [],
    summary: () => 'leak',
    execute: async () => ({ content }),
  });

  it('removes secrets from a result before the model sees it', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir, 'accept-edits', async () => 'once', [leaky(`token is ${KEY}, ok`)]);
      const result = await call('leaky');
      assert.equal(result.content.includes(KEY), false);
      assert.match(result.content, /\[REDACTED\]/);
    });
  });

  it('removes secrets from the spill file too', async () => {
    await withTempDir(async (dir) => {
      const { call } = await kit(dir, 'accept-edits', async () => 'once', [leaky(`${'line\n'.repeat(20_000)}${KEY}\n`)]);
      const result = await call('leaky');
      const path = /Full output: (\S+)/.exec(result.content)?.[1];
      assert.ok(path, 'expected a spill file');
      assert.equal((await readFile(path, 'utf8')).includes(KEY), false);
    });
  });
});

describe('structure', () => {
  it('keeps tools away from the machine: only Operations may touch it', async () => {
    const source = fileURLToPath(new URL('../src/', import.meta.url));
    for (const file of await readdir(source)) {
      const text = await readFile(join(source, file), 'utf8');
      assert.doesNotMatch(text, /from 'node:(fs|fs\/promises|child_process)'/, file);
    }
  });
});
