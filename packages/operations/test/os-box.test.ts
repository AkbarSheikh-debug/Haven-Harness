import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  LinuxBox,
  NonceSinks,
  SeatbeltBox,
  ancestorsOf,
  bwrapRun,
  confinePrefix,
  describeOsTier,
  detectLinuxSupport,
  findHelper,
  linuxFactsProblems,
  linuxFactsScript,
  osTierOf,
  seatbeltProfile,
  survivorShellScript,
  verifyOsBoxTier,
  type BoxLayers,
  type LinuxSupport,
  type OsVerifiable,
  type PosixRunRequest,
} from '@hn/operations';
import type { ExecResult } from '@hn/operations';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const signal = new AbortController().signal;
/** On a CI runner or in the test container a box that cannot start is a failure, never a quiet skip. */
const required = process.env['HN_REQUIRE_BOX'] === '1';
const paths = { copy: '/b/box/work', home: '/b/box/home', tmp: '/b/box/tmp', cwd: '/b/box/work' };

describe('the box command lines, on any platform', () => {
  it('puts Landlock and seccomp in front of the command, reads and writes named, and nothing writable besides the copy, home and temp', () => {
    const args = bwrapRun(paths, '/bin/bash', ['-c', 'make test'], { HN_PARENT_SESSION: 's' }, { reads: ['/opt/node/bin/node'], confine: { helper: '/opt/hn/hn-sandbox', landlock: true, seccomp: true } });
    const split = args.indexOf('--', args.indexOf('--chdir'));
    const inner = args.slice(split + 1);
    assert.deepEqual(inner.slice(0, 4), ['/opt/hn/hn-sandbox', 'confine', '--landlock', '--seccomp']);
    assert.deepEqual(inner.slice(-3), ['/bin/bash', '-c', 'make test']);
    const writes = inner.flatMap((arg, i) => (arg === '--write' ? [inner[i + 1]] : []));
    assert.deepEqual(writes, [paths.copy, paths.home, paths.tmp]);
    const reads = inner.flatMap((arg, i) => (arg === '--read' ? [inner[i + 1]] : []));
    assert.ok(reads.includes('/usr') && reads.includes('/opt/node/bin/node') && reads.includes('/proc'));
    assert.ok(!reads.some((read) => read === '/' || read === '/home' || read === '/root'));
    // The helper is bound read-only into the box, so the box can run it; it is never writable.
    const bound = args.flatMap((arg, i) => (arg === '--ro-bind' ? [args[i + 1]] : []));
    assert.deepEqual(bound, ['/opt/hn/hn-sandbox']);
    assert.deepEqual(args.flatMap((arg, i) => (arg === '--bind' ? [args[i + 1]] : [])), [paths.copy, paths.home, paths.tmp]);
    assert.ok(args.join(' ').includes('--cap-drop ALL'));
  });

  it('asks for only the layers the kernel has, and for none when it has none', () => {
    const helper = '/opt/hn/hn-sandbox';
    assert.deepEqual(confinePrefix(paths, {}), []);
    assert.deepEqual(confinePrefix(paths, { confine: { helper, landlock: false, seccomp: false } }), []);
    const seccompOnly = confinePrefix(paths, { confine: { helper, landlock: false, seccomp: true } });
    assert.deepEqual(seccompOnly, [helper, 'confine', '--seccomp', '--']);
    const landlockOnly = confinePrefix(paths, { confine: { helper, landlock: true, seccomp: false } });
    assert.ok(landlockOnly.includes('--landlock') && !landlockOnly.includes('--seccomp'));
  });

  it('never gives the box the root, the home folders, sockets or a relative path, and refuses a path that climbs', () => {
    for (const bad of ['/', '/home', '/root', '/run', '/var/run', '/Users', '/proc', 'relative/bin', '/opt/../root']) {
      assert.throws(() => bwrapRun(paths, '/bin/sh', [], {}, { reads: [bad] }), /absolute|cannot be given|\.\./, bad);
      assert.throws(() => seatbeltProfile(paths, { reads: [bad] }), /absolute|cannot be given|\.\./, bad);
    }
    assert.throws(() => bwrapRun(paths, 'sh', [], {}), /absolute/);
  });

  it('lists the folders on the way to an allowed path, as names only, and no other folder of the host', () => {
    assert.deepEqual(ancestorsOf('/Users/runner/work/box/tmp'), ['/', '/Users', '/Users/runner', '/Users/runner/work', '/Users/runner/work/box']);
    const profile = seatbeltProfile({ copy: '/Users/r/b/work', home: '/Users/r/b/home', tmp: '/Users/r/b/tmp', cwd: '/Users/r/b/work' }, { reads: ['/Users/r/hostedtoolcache/node/bin/node'] });
    assert.match(profile, /\(allow file-read-metadata [^\n]*\(literal "\/Users\/r"\)/);
    assert.match(profile, /\(literal "\/Users\/r\/hostedtoolcache\/node\/bin"\)/);
    assert.match(profile, /\(allow file-read\* [^\n]*\(subpath "\/Users\/r\/hostedtoolcache\/node\/bin\/node"\)/);
    // Nothing under /Users is readable except what was named; the writable set is exactly the three folders.
    const writeRule = profile.split('\n').find((line) => line.startsWith('(allow file-write*')) ?? '';
    assert.equal((writeRule.match(/subpath/g) ?? []).length, 3);
    assert.doesNotMatch(profile, /\(subpath "\/Users"\)|\(subpath "\/"\)|allow network/);
  });

  it('quotes the beat file in the survivor script, so a name with a quote cannot add a command', () => {
    const script = survivorShellScript("/tmp/it's here/beat; rm -rf x");
    assert.ok(script.includes(`'/tmp/it'\\''s here/beat; rm -rf x'`));
  });
});

const layers = (applied: string[]): BoxLayers => ({ applied, missing: [] });
const HOST = { net: 'net:[1]', pid: 'pid:[2]', ipc: 'ipc:[3]', uts: 'uts:[4]', user: 'user:[5]', mnt: 'mnt:[6]', cgroup: 'cgroup:[7]' };
const factsFor = (overrides: Record<string, string> = {}): string => {
  const base: Record<string, string> = { 'ns-net': 'net:[11]', 'ns-pid': 'pid:[12]', 'ns-ipc': 'ipc:[13]', 'ns-uts': 'uts:[14]', 'ns-user': 'user:[15]', 'ns-mnt': 'mnt:[16]', 'ns-cgroup': 'cgroup:[17]', capeff: '0000000000000000', nonewprivs: '1', seccomp: '2', 'run-writable': 'no', 'ptrace-errno': '1', ...overrides };
  return ['facts-ran', ...Object.entries(base).map(([key, value]) => `${key}=${value}`)].join('\n');
};

describe('what the box says about itself is judged against what the host knows', () => {
  it('accepts a box in its own namespaces with no capability, Landlock in force and ptrace denied, and says which layers held', () => {
    const judged = linuxFactsProblems(factsFor(), HOST, layers(['namespaces', 'landlock', 'seccomp']));
    assert.deepEqual(judged.problems, []);
    assert.deepEqual(judged.verified, ['namespaces', 'landlock', 'seccomp']);
  });

  it('rejects each namespace left shared with the host, one by one', () => {
    for (const name of ['net', 'pid', 'ipc', 'uts', 'user', 'mnt', 'cgroup']) {
      const judged = linuxFactsProblems(factsFor({ [`ns-${name}`]: HOST[name as keyof typeof HOST] }), HOST, layers(['namespaces']));
      assert.match(judged.problems.join(), new RegExp(`${name} namespace`), name);
      assert.ok(!judged.verified.includes('namespaces'));
    }
  });

  it('rejects a capability, a missing no_new_privs, a filesystem rule that is not in force, and a filter that does not deny', () => {
    const all = layers(['namespaces', 'landlock', 'seccomp']);
    assert.match(linuxFactsProblems(factsFor({ capeff: '0000000000200000' }), HOST, all).problems.join(), /capabilities/);
    assert.match(linuxFactsProblems(factsFor({ nonewprivs: '0' }), HOST, all).problems.join(), /no_new_privs/);
    const open = linuxFactsProblems(factsFor({ 'run-writable': 'yes' }), HOST, all);
    assert.match(open.problems.join(), /Landlock was applied, but/);
    assert.ok(!open.verified.includes('landlock'));
    const noMode = linuxFactsProblems(factsFor({ seccomp: '0' }), HOST, all);
    assert.match(noMode.problems.join(), /seccomp mode 0/);
    const leaky = linuxFactsProblems(factsFor({ 'ptrace-errno': '5' }), HOST, all);
    assert.match(leaky.problems.join(), /ptrace was not denied/);
    assert.ok(!leaky.verified.includes('seccomp'));
  });

  it('does not claim a layer the box did not apply, and fails a box that never ran the script', () => {
    const judged = linuxFactsProblems(factsFor({ 'run-writable': 'yes', seccomp: '0' }), HOST, layers(['namespaces']));
    assert.deepEqual(judged.problems, []);
    assert.deepEqual(judged.verified, ['namespaces']);
    assert.match(linuxFactsProblems('', HOST, layers(['namespaces'])).problems.join(), /did not run the facts script/);
    assert.match(linuxFactsProblems('facts-ran\ncapeff=0000000000000000', HOST, layers(['namespaces'])).problems.join(), /could not say which net namespace/);
  });

  it('writes the facts script for the architecture it runs on, and says "untested" where it has no call number', () => {
    assert.match(linuxFactsScript('x64'), /syscall\(101,/);
    assert.match(linuxFactsScript('arm64'), /syscall\(117,/);
    assert.match(linuxFactsScript('riscv64'), /ptrace-errno=untested/);
  });
});

/** Runs the canary straight on this machine, with no box, claiming every layer. */
function unconfined(box: { work: string; tmp: string }, kind: 'linux' | 'macos'): OsVerifiable {
  return {
    kind,
    work: box.work,
    tmp: box.tmp,
    layers: layers(kind === 'linux' ? ['namespaces', 'landlock', 'seccomp'] : ['seatbelt']),
    run: (program, args, request: PosixRunRequest) =>
      new Promise<ExecResult>((resolve) => {
        const child = spawn(program, [...args], { cwd: request.cwd, stdio: ['pipe', 'pipe', 'pipe'] });
        const out: Buffer[] = [];
        child.stdout.on('data', (chunk: Buffer) => out.push(chunk));
        child.stdin.on('error', () => undefined);
        child.stdin.end(request.input ?? '');
        child.on('close', (code) => resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.alloc(0), timedOut: false, cancelled: false, clipped: false }));
      }),
  };
}

/** Says it ran the canary, prints a clean result, and runs nothing at all. */
function runsNothing(box: { work: string; tmp: string }, kind: 'linux' | 'macos'): OsVerifiable {
  return { kind, work: box.work, tmp: box.tmp, layers: layers(kind === 'linux' ? ['namespaces', 'landlock', 'seccomp'] : ['seatbelt']), run: async () => ({ code: 0, stdout: Buffer.from('attempts=9\nfacts-ran\n'), stderr: Buffer.alloc(0), timedOut: false, cancelled: false, clipped: false }) };
}

const onPosix = process.platform === 'linux' || process.platform === 'darwin';
const hostKind = process.platform === 'darwin' ? 'macos' : 'linux';

describe('the stand-ins fail the outside-in check on any Linux or macOS host', { skip: onPosix ? false : 'Linux and macOS only' }, () => {
  let base: string;
  let outside: string;
  let sinks: NonceSinks;
  let folders: { work: string; tmp: string };

  before(async () => {
    base = await realpath(await mkdtemp(join(tmpdir(), 'hn-standin-')));
    outside = join(base, 'outside');
    folders = { work: join(base, 'box', 'work'), tmp: join(base, 'box', 'tmp') };
    for (const dir of [outside, folders.work, folders.tmp]) await mkdir(dir, { recursive: true });
    sinks = await NonceSinks.open();
  });

  after(async () => {
    await sinks?.close();
    await rm(base, { recursive: true, force: true });
  });

  it('a "sandbox" that is not one: connections arrive, the outside file is written, the background process lives on, the namespaces are the host\'s', async () => {
    const report = await verifyOsBoxTier(unconfined(folders, hostKind), sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.ok(report.hits.length > 0, 'no connection reached the host listener');
    assert.ok(report.evidence.some((line) => /outside its own folder/.test(line)), report.evidence.join(' / '));
    assert.ok(report.evidence.some((line) => /kept running/.test(line)), report.evidence.join(' / '));
    assert.deepEqual(report.verifiedLayers, []);
    assert.equal(osTierOf(report), 2);
    if (hostKind === 'linux') assert.match(report.evidence.join('\n'), /namespace, so it is not unshared/);
  });

  it('a "sandbox" that runs nothing: it prints a clean result, but no proof file was written', async () => {
    const report = await verifyOsBoxTier(runsNothing(folders, hostKind), sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.match(report.evidence.join('\n'), /canary did not run in the box/);
    assert.match(report.evidence.join('\n'), /No background process ran/);
    assert.deepEqual(report.verifiedLayers, []);
  });

  it('a runner that says nothing at all fails too: no attempts, no facts, no proof', async () => {
    const silent: OsVerifiable = { ...runsNothing(folders, hostKind), run: async () => ({ code: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), timedOut: false, cancelled: false, clipped: false }) };
    const report = await verifyOsBoxTier(silent, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.match(report.evidence.join('\n'), /made no network attempts/);
  });
});

let support: LinuxSupport | null = null;
let helper: string | null = null;
if (process.platform === 'linux') {
  helper = await findHelper({ env: {}, repoRoot });
  support = await detectLinuxSupport(helper === null ? {} : { helper });
}
const linuxUsable = support !== null && support.namespaces && helper !== null;
const linuxWhyNot = support?.namespaceProblem ?? (helper === null ? 'hn-sandbox is not built (pnpm build:sandbox)' : 'unknown');

describe('the Linux box, for real', { skip: process.platform !== 'linux' ? 'Linux only' : linuxUsable || required ? false : `not available: ${linuxWhyNot}` }, () => {
  if (!linuxUsable) {
    // Where the box is required (CI, the test container) a box that cannot start is a failure that says why.
    it('can start a bubblewrap box here', () => assert.fail(linuxWhyNot));
    return;
  }
  const ok = support as LinuxSupport;
  const helperPath = helper as string;

  let base: string;
  let outside: string;
  let sinks: NonceSinks;
  let boxes = 0;

  const open = async (options: { support?: LinuxSupport; layers?: { landlock?: boolean; seccomp?: boolean }; rewriteArgs?: (args: string[]) => string[]; withHelper?: boolean } = {}): Promise<LinuxBox> => {
    boxes += 1;
    return LinuxBox.open({
      boxDir: join(base, `session-${boxes}`),
      support: options.support ?? ok,
      ...(options.withHelper === false ? {} : { helper: helperPath }),
      reads: [process.execPath],
      ...(options.layers === undefined ? {} : { layers: options.layers }),
      ...(options.rewriteArgs === undefined ? {} : { rewriteArgs: options.rewriteArgs }),
    });
  };

  before(async () => {
    base = await realpath(await mkdtemp(join(tmpdir(), 'hn-linux-box-')));
    outside = join(base, 'outside');
    await mkdir(outside, { recursive: true });
    sinks = await NonceSinks.open();
  });

  after(async () => {
    await sinks?.close();
    await rm(base, { recursive: true, force: true });
  });

  const full = (): string[] => ['namespaces', ...(ok.landlockAbi >= 1 ? ['landlock'] : []), ...(ok.seccomp ? ['seccomp'] : [])];

  it('passes the outside-in check with every layer this kernel has: nothing reached this machine, nothing outside was touched, nothing outlived it', async () => {
    const box = await open();
    const report = await verifyOsBoxTier(box, sinks, { outside, interpreter: process.execPath });
    assert.deepEqual(report.evidence, [], report.evidence.join('\n'));
    assert.equal(report.real, true);
    assert.ok(report.attempts >= 2, `only ${report.attempts} addresses were tried`);
    assert.deepEqual(report.hits, []);
    assert.deepEqual([...report.verifiedLayers], full());
    assert.equal(osTierOf(report), 3);
  });

  it('exit gate: every namespace unshared, a Landlock filesystem rule and a seccomp filter, all three verified', { skip: ok.landlockAbi >= 1 && ok.seccomp ? false : `this kernel lacks ${ok.landlockAbi < 1 ? 'Landlock' : 'seccomp filters'}, so the gate cannot be met on it` }, async () => {
    const box = await open();
    assert.deepEqual([...box.layers.applied], ['namespaces', 'landlock', 'seccomp']);
    const report = await verifyOsBoxTier(box, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, true, report.evidence.join('\n'));
    assert.deepEqual([...report.verifiedLayers], ['namespaces', 'landlock', 'seccomp']);
    assert.match(describeOsTier(report), /layers verified: namespaces, landlock, seccomp/);
  });

  it('a kernel without Landlock or seccomp gives a lower, honestly named tier, not a failed run and not a claimed layer', async () => {
    const lacking: LinuxSupport = { ...ok, landlockAbi: 0, seccomp: false, confineProblem: null };
    const box = await open({ support: lacking });
    assert.deepEqual([...box.layers.applied], ['namespaces']);
    assert.deepEqual(box.layers.missing.map((entry) => entry.layer), ['landlock', 'seccomp']);
    const report = await verifyOsBoxTier(box, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, true, report.evidence.join('\n'));
    assert.deepEqual([...report.verifiedLayers], ['namespaces']);
    assert.match(describeOsTier(report), /not applied: landlock \(.*\); seccomp/);
    // The same with no helper at all: bubblewrap alone.
    const bare = await open({ withHelper: false });
    assert.deepEqual([...bare.layers.applied], ['namespaces']);
    assert.equal((await verifyOsBoxTier(bare, sinks, { outside, interpreter: process.execPath })).real, true);
  });

  it('fails a box that is built to leak: bubblewrap with the network shared lets a connection reach this machine', async () => {
    const leaky = await open({ rewriteArgs: (args) => [args[0] as string, '--share-net', ...args.slice(1)] });
    const report = await verifyOsBoxTier(leaky, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.ok(report.hits.length > 0, 'a box that shares the network reached nothing, so the listeners prove nothing');
    assert.match(report.evidence.join('\n'), /namespace, so it is not unshared|connection from the box reached/);
    assert.deepEqual(report.verifiedLayers, []);
  });

  it('fails a box that shares the host\'s process namespace, though nothing else is wrong', async () => {
    const shared = await open({ rewriteArgs: (args) => args.flatMap((arg) => (arg === '--unshare-all' ? ['--unshare-user-try', '--unshare-ipc', '--unshare-uts', '--unshare-net', '--unshare-cgroup-try'] : [arg])) });
    const report = await verifyOsBoxTier(shared, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.match(report.evidence.join('\n'), /pid namespace/);
  });

  it('fails a box whose Landlock was claimed and not applied: /run is writable, so the filesystem rule is not in force', async () => {
    const bare = await open({ withHelper: false });
    const lie: OsVerifiable = { kind: 'linux', work: bare.work, tmp: bare.tmp, layers: layers(['namespaces', 'landlock']), run: (program, args, request) => bare.run(program, args, request) };
    const report = await verifyOsBoxTier(lie, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.match(report.evidence.join('\n'), /Landlock was applied, but/);
  });

  it('runs bash in the copy, writes land in the copy and nowhere else, exit codes pass through, and no key of this process reaches it', async () => {
    const box = await open();
    process.env['ANTHROPIC_API_KEY'] = 'sk-ant-should-never-reach-the-box';
    try {
      const ran = await box.exec('echo "from the box" > made.txt; cat made.txt; echo "key=[$ANTHROPIC_API_KEY]"; pwd; id -u >/dev/null; echo "shell=$0"', { cwd: box.work, timeoutMs: 60_000, signal });
      assert.equal(ran.code, 0, ran.stderr.toString());
      const text = ran.stdout.toString();
      assert.match(text, /from the box/);
      assert.match(text, /key=\[\]/);
      assert.ok(text.includes(box.work), text);
      assert.equal((await readFile(join(box.work, 'made.txt'), 'utf8')).trim(), 'from the box');
      assert.equal((await box.exec('exit 7', { cwd: box.work, timeoutMs: 60_000, signal })).code, 7);
      assert.equal(box.shell, 'bash');
    } finally {
      delete process.env['ANTHROPIC_API_KEY'];
    }
  });

  it('cannot read a file of the user outside the box, nor write beside it, nor see the host\'s home', async () => {
    const box = await open();
    const secret = join(outside, 'secret.txt');
    await writeFile(secret, 'host secret');
    const read = await box.exec(`cat '${secret}'`, { cwd: box.work, timeoutMs: 60_000, signal });
    assert.notEqual(read.code, 0);
    assert.doesNotMatch(read.stdout.toString(), /host secret/);
    const wrote = await box.exec(`echo x > '${join(outside, 'planted.txt')}'`, { cwd: box.work, timeoutMs: 60_000, signal });
    assert.notEqual(wrote.code, 0);
    await assert.rejects(readFile(join(outside, 'planted.txt')), /ENOENT/);
    const homes = await box.exec('ls /home /root 2>&1; ls /run | wc -l', { cwd: box.work, timeoutMs: 60_000, signal });
    assert.doesNotMatch(homes.stdout.toString(), /\b[a-z]+@|authorized_keys/);
  });

  it('has no network at all: a connection to a listener of this machine fails', async () => {
    const box = await open();
    const probe = await box.run(process.execPath, ['-e', `require('net').connect({host:'127.0.0.1',port:${sinks.tcpPort}}).on('connect',()=>{console.log('CONNECTED');process.exit(0)}).on('error',(e)=>{console.log('refused '+e.code);process.exit(0)})`], { cwd: box.work, timeoutMs: 60_000, signal });
    assert.match(probe.stdout.toString(), /refused/);
    assert.doesNotMatch(probe.stdout.toString(), /CONNECTED/);
  });

  it('stops everything in the box when a command times out, including what it started', async () => {
    const box = await open();
    const started = Date.now();
    const result = await box.exec('sleep 60 & sleep 60', { cwd: box.work, timeoutMs: 2_000, signal });
    assert.equal(result.timedOut, true);
    assert.ok(Date.now() - started < 15_000, 'the timeout did not stop the box');
  });

  it('ends a background process with the command that started it', async () => {
    const box = await open();
    const beat = join(box.tmp, 'beat');
    await box.exec(`( while true; do printf b >> '${beat}'; sleep 0.1; done ) >/dev/null 2>&1 & sleep 0.5`, { cwd: box.work, timeoutMs: 60_000, signal });
    const first = (await readFile(beat)).length;
    await new Promise((resolve) => setTimeout(resolve, 600));
    assert.equal((await readFile(beat)).length, first, 'the background process kept writing after the command ended');
  });

  it('runs jobs in the box and stops them on a signal', async () => {
    const box = await open();
    const job = box.startProcess('echo started; sleep 60', { cwd: box.work, input: false });
    await new Promise((resolve) => setTimeout(resolve, 800));
    assert.match(job.stdout.bytes.toString(), /started/);
    job.signal('terminate');
    const ended = await Promise.race([job.exited, new Promise<null>((resolve) => setTimeout(() => resolve(null), 10_000))]);
    assert.notEqual(ended, null, 'the job did not stop');
  });

  it('still does ordinary build work with every layer on: files, processes, pipes, a Node script, a compile-like loop', async () => {
    const box = await open();
    await writeFile(join(box.work, 'build.mjs'), "import { writeFileSync, readdirSync } from 'node:fs'; writeFileSync('out.txt', String(readdirSync('.').length)); console.log('built');");
    const result = await box.exec(`mkdir -p src/a && for i in 1 2 3; do echo $i > src/a/f$i; done && cat src/a/f* | sort -r | head -1 && '${process.execPath}' build.mjs && cat out.txt && tar -cf - src | tar -tf - | wc -l`, { cwd: box.work, timeoutMs: 120_000, signal });
    assert.equal(result.code, 0, result.stderr.toString());
    assert.match(result.stdout.toString(), /built/);
  });

  it('Landlock stops a write that a wrong mount would have allowed', { skip: ok.landlockAbi >= 1 ? false : 'this kernel has no Landlock' }, async () => {
    // A mount mistake: the outside folder is bound writable into the box. Without Landlock the write lands; with it, the kernel refuses.
    const wrongMount = (args: string[]): string[] => {
      const at = args.indexOf('--chdir');
      return [...args.slice(0, at), '--bind', outside, outside, ...args.slice(at)];
    };
    const target = join(outside, 'through-the-wrong-mount.txt');
    const withoutLandlock = await open({ layers: { landlock: false, seccomp: false }, rewriteArgs: wrongMount });
    await withoutLandlock.exec(`echo x > '${target}'`, { cwd: withoutLandlock.work, timeoutMs: 60_000, signal });
    assert.equal((await readFile(target, 'utf8')).trim(), 'x', 'the control: with the mount wrong and no Landlock, the write must land, or this test proves nothing');
    await rm(target);
    const withLandlock = await open({ layers: { landlock: true, seccomp: false }, rewriteArgs: wrongMount });
    const refused = await withLandlock.exec(`echo x > '${target}'`, { cwd: withLandlock.work, timeoutMs: 60_000, signal });
    assert.notEqual(refused.code, 0);
    await assert.rejects(readFile(target), /ENOENT/, 'Landlock did not stop the write');
  });

  it('seccomp makes ptrace, mount and bpf fail inside the box, and an ordinary command still runs', { skip: ok.seccomp ? false : 'this kernel has no seccomp filters' }, async () => {
    const box = await open();
    const arch = process.arch === 'arm64' ? { ptrace: 117, bpf: 280, mount: 40 } : { ptrace: 101, bpf: 321, mount: 165 };
    const probe = (number: number): string => `perl -e '$r = syscall(${number}, -1, 0, 0, 0); print $!+0'`;
    const result = await box.exec(`echo "ptrace=$(${probe(arch.ptrace)}) bpf=$(${probe(arch.bpf)}) mount=$(${probe(arch.mount)})"`, { cwd: box.work, timeoutMs: 60_000, signal });
    assert.match(result.stdout.toString(), /ptrace=1 bpf=1 mount=1/, result.stderr.toString());
    // The control: the same calls under bubblewrap alone do not all answer EPERM for ptrace.
    const lower = await open({ layers: { landlock: false, seccomp: false } });
    const open2 = await lower.exec(`echo "ptrace=$(${probe(arch.ptrace)})"`, { cwd: lower.work, timeoutMs: 60_000, signal });
    assert.doesNotMatch(open2.stdout.toString(), /ptrace=1\b/, 'without the filter ptrace answered EPERM already, so the check proves nothing');
  });
});

describe('the macOS box, for real', { skip: process.platform === 'darwin' ? false : 'macOS only' }, () => {
  let base: string;
  let outside: string;
  let sinks: NonceSinks;
  let boxes = 0;

  const open = (extraProfile?: string): Promise<SeatbeltBox> => {
    boxes += 1;
    return SeatbeltBox.open({ boxDir: join(base, `session-${boxes}`), reads: [process.execPath], ...(extraProfile === undefined ? {} : { extraProfile }) });
  };

  before(async () => {
    base = await realpath(await mkdtemp(join(tmpdir(), 'hn-mac-box-')));
    outside = join(base, 'outside');
    await mkdir(outside, { recursive: true });
    sinks = await NonceSinks.open();
  });

  after(async () => {
    await sinks?.close();
    await rm(base, { recursive: true, force: true });
  });

  it('passes the outside-in check: nothing reached this machine, nothing outside was touched, nothing outlived it', async () => {
    const box = await open();
    const report = await verifyOsBoxTier(box, sinks, { outside, interpreter: process.execPath });
    assert.deepEqual(report.evidence, [], report.evidence.join('\n'));
    assert.equal(report.real, true);
    assert.ok(report.attempts >= 2);
    assert.deepEqual([...report.verifiedLayers], ['seatbelt']);
    assert.match(describeOsTier(report), /process-tree/);
  });

  it('fails a box built to leak: the same profile with the network allowed lets a connection reach this machine', async () => {
    const leaky = await open('(allow network*)');
    const report = await verifyOsBoxTier(leaky, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.ok(report.hits.length > 0, 'a profile that allows the network reached nothing, so the listeners prove nothing');
  });

  it('runs bash in the copy, passes exit codes through, gives it no key of this process, and cannot read or write outside', async () => {
    const box = await open();
    process.env['ANTHROPIC_API_KEY'] = 'sk-ant-should-never-reach-the-box';
    try {
      const ran = await box.exec('echo "from the box" > made.txt; cat made.txt; echo "key=[$ANTHROPIC_API_KEY]"', { cwd: box.work, timeoutMs: 60_000, signal });
      assert.equal(ran.code, 0, ran.stderr.toString());
      assert.match(ran.stdout.toString(), /from the box/);
      assert.match(ran.stdout.toString(), /key=\[\]/);
      assert.equal((await box.exec('exit 7', { cwd: box.work, timeoutMs: 60_000, signal })).code, 7);
      const secret = join(outside, 'secret.txt');
      await writeFile(secret, 'host secret');
      const read = await box.exec(`cat '${secret}'`, { cwd: box.work, timeoutMs: 60_000, signal });
      assert.notEqual(read.code, 0);
      assert.doesNotMatch(read.stdout.toString(), /host secret/);
      const wrote = await box.exec(`echo x > '${join(outside, 'planted.txt')}'`, { cwd: box.work, timeoutMs: 60_000, signal });
      assert.notEqual(wrote.code, 0);
    } finally {
      delete process.env['ANTHROPIC_API_KEY'];
    }
  });

  it('stops everything in the box when a command times out', async () => {
    const box = await open();
    const started = Date.now();
    const result = await box.exec('sleep 60 & sleep 60', { cwd: box.work, timeoutMs: 2_000, signal });
    assert.equal(result.timedOut, true);
    assert.ok(Date.now() - started < 15_000);
  });
});
