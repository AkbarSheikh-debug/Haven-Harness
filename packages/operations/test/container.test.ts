import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { withTempDir } from '@hn/testkit';
import {
  ContainerBox,
  ContainerError,
  assertPinned,
  boxUser,
  containerRunArgs,
  dockerIsUp,
  findDocker,
  verifyRuntime,
  type BoxOptions,
} from '@hn/operations';

const DIGEST = `alpine@sha256:${'a'.repeat(64)}`;
const base: BoxOptions = { image: DIGEST, sessionId: 'abc123', workDir: '/tmp/copy', docker: 'docker' };

describe('the box user', () => {
  it('is this account on a Linux host, never root, and nobody elsewhere', () => {
    assert.equal(boxUser('linux', 1001, 121), '1001:121');
    assert.equal(boxUser('linux', 0, 0), '65534:65534', 'root on the host never makes a root box');
    assert.equal(boxUser('darwin', 501, 20), '65534:65534');
    assert.equal(boxUser('win32', undefined, undefined), '65534:65534');
  });
  it('is the user the run arguments ask for, and its home belongs to it', () => {
    const args = containerRunArgs({ ...base, user: '1001:121' });
    assert.equal(args[args.indexOf('--user') + 1], '1001:121');
    assert.ok(args.includes('/home/hn:rw,nosuid,size=128m,uid=1001,gid=121'));
  });
});

describe('the container run arguments', () => {
  const args = containerRunArgs(base);
  const has = (...flags: string[]): boolean => flags.every((flag, i) => args.includes(flag) && (i === 0 || args.indexOf(flag) > args.indexOf(flags[i - 1] as string) - 1));
  const after = (flag: string): string | undefined => args[args.indexOf(flag) + 1];

  it('asks for every confinement the box needs', () => {
    assert.equal(after('--network'), 'none');
    assert.ok(args.includes('--read-only'));
    assert.equal(after('--user'), boxUser());
    assert.equal(after('--cap-drop'), 'ALL');
    assert.equal(after('--security-opt'), 'no-new-privileges');
    assert.equal(after('--pids-limit'), '256');
    assert.equal(after('--memory'), '1g');
    assert.equal(after('--memory-swap'), '1g', 'swap must not widen the memory limit');
    assert.equal(after('--cpus'), '2');
    assert.ok(args.includes('--init'));
    assert.ok(args.includes('--pull=never'), 'the image is already pinned and present; never fetch a different one');
    assert.ok(has('--entrypoint'));
  });

  it('mounts only the project copy, and no socket, home or privilege', () => {
    assert.equal(args.filter((arg) => arg === '--mount' || arg === '-v' || arg === '--volume').length, 1);
    assert.equal(after('--mount'), 'type=bind,source=/tmp/copy,target=/work');
    for (const forbidden of ['--privileged', '--cap-add', '--device', '--pid', '--ipc', '--userns', '--network=host', 'host', '--env-file']) {
      assert.ok(!args.includes(forbidden), forbidden);
    }
    assert.ok(!args.join(' ').includes('docker.sock'));
  });

  it('puts the image last before the command, and scrubs the environment down to HOME', () => {
    assert.equal(args.filter((arg) => arg === '--env').length, 1);
    assert.equal(after('--env'), 'HOME=/home/hn');
    assert.equal(args[args.indexOf(DIGEST) + 1], '-c');
  });

  it('applies limits the caller sets, and no others', () => {
    const custom = containerRunArgs({ ...base, limits: { memory: '256m', pids: 64 } });
    assert.equal(custom[custom.indexOf('--memory') + 1], '256m');
    assert.equal(custom[custom.indexOf('--pids-limit') + 1], '64');
    assert.equal(custom[custom.indexOf('--cpus') + 1], '2');
  });

  it('refuses an image that is not pinned by digest', () => {
    for (const image of ['alpine', 'alpine:3.20', 'alpine:latest', 'alpine@sha256:abc', `alpine@sha256:${'g'.repeat(64)}`, `${DIGEST}x`, '']) {
      assert.throws(() => assertPinned(image), (error: ContainerError) => error.code === 'IMAGE_NOT_PINNED', image);
      assert.throws(() => containerRunArgs({ ...base, image }), ContainerError);
    }
    assert.doesNotThrow(() => assertPinned(`registry.example/team/app@sha256:${'0'.repeat(64)}`));
  });

  it('refuses a session id that is not safe in a container name', () => {
    for (const sessionId of ['', 'a b', 'a;b', '../x', 'x'.repeat(65), '-x --privileged']) {
      assert.throws(() => containerRunArgs({ ...base, sessionId }), (error: ContainerError) => error.code === 'BAD_SESSION_ID', sessionId);
    }
  });
});

/** A `docker inspect` result for a box that is exactly as asked. */
function goodInspect(): Record<string, unknown> {
  return {
    Config: { User: '65534:65534' },
    HostConfig: {
      NetworkMode: 'none',
      ReadonlyRootfs: true,
      CapDrop: ['ALL'],
      CapAdd: null,
      Privileged: false,
      SecurityOpt: ['no-new-privileges'],
      PidsLimit: 256,
      Memory: 1073741824,
      NanoCpus: 2000000000,
      PidMode: '',
      IpcMode: 'private',
      UsernsMode: '',
      Devices: [],
    },
    Mounts: [{ Source: '/tmp/copy', Destination: '/work' }],
  };
}

function broken(change: (inspect: { Config: Record<string, unknown>; HostConfig: Record<string, unknown>; Mounts: unknown[] }) => void): readonly string[] {
  const inspect = goodInspect() as { Config: Record<string, unknown>; HostConfig: Record<string, unknown>; Mounts: unknown[] };
  change(inspect);
  return verifyRuntime([inspect]).failures;
}

describe('reading the runtime back (verifyRuntime)', () => {
  it('accepts a box that is exactly as asked', () => {
    const report = verifyRuntime([goodInspect()]);
    assert.deepEqual(report.failures, []);
    assert.equal(report.ok, true);
  });

  const cases: [string, (i: { Config: Record<string, unknown>; HostConfig: Record<string, unknown>; Mounts: unknown[] }) => void, RegExp][] = [
    ['a network', (i) => (i.HostConfig['NetworkMode'] = 'bridge'), /network is "bridge"/],
    ['the host network', (i) => (i.HostConfig['NetworkMode'] = 'host'), /network is "host"/],
    ['a writable root', (i) => (i.HostConfig['ReadonlyRootfs'] = false), /writable/],
    ['root by default', (i) => (i.Config['User'] = ''), /root/],
    ['root by name', (i) => (i.Config['User'] = 'root'), /root/],
    ['root by number', (i) => (i.Config['User'] = '0:0'), /not an unprivileged/],
    ['capabilities kept', (i) => (i.HostConfig['CapDrop'] = null), /not dropped/],
    ['capabilities added', (i) => (i.HostConfig['CapAdd'] = ['SYS_ADMIN']), /added: SYS_ADMIN/],
    ['privileged', (i) => (i.HostConfig['Privileged'] = true), /privileged/],
    ['new privileges allowed', (i) => (i.HostConfig['SecurityOpt'] = []), /no-new-privileges/],
    ['no process limit', (i) => (i.HostConfig['PidsLimit'] = 0), /process limit/],
    ['no memory limit', (i) => (i.HostConfig['Memory'] = 0), /memory limit/],
    ['no CPU limit', (i) => (i.HostConfig['NanoCpus'] = 0), /CPU limit/],
    ['the host PID namespace', (i) => (i.HostConfig['PidMode'] = 'host'), /process namespace/],
    ['the host IPC namespace', (i) => (i.HostConfig['IpcMode'] = 'host'), /IPC/],
    ['the host user namespace', (i) => (i.HostConfig['UsernsMode'] = 'host'), /user namespace/],
    ['a host device', (i) => (i.HostConfig['Devices'] = [{ PathOnHost: '/dev/sda' }]), /devices/],
    ['no mount at all', (i) => (i.Mounts = []), /exactly one mount/],
    ['an extra mount', (i) => i.Mounts.push({ Source: '/data', Destination: '/data' }), /exactly one mount|other than \/work/],
    ['the Docker socket', (i) => (i.Mounts = [{ Source: '/var/run/docker.sock', Destination: '/var/run/docker.sock' }]), /socket|other than \/work/],
    ['the home folder', (i) => (i.Mounts = [{ Source: '/home/user', Destination: '/work' }]), /sensitive/],
    ['ssh keys', (i) => (i.Mounts = [{ Source: '/home/user/.ssh', Destination: '/work' }]), /sensitive/],
  ];
  for (const [name, change, message] of cases) {
    it(`fails a box with ${name}`, () => {
      const failures = broken(change);
      assert.ok(failures.length > 0, 'a bad box was accepted');
      assert.ok(failures.some((line) => message.test(line)), failures.join(' | '));
    });
  }

  it('fails when Docker reports nothing, or something unreadable, instead of assuming it is fine', () => {
    for (const value of [undefined, null, [], {}, 'text', [{}]]) assert.equal(verifyRuntime(value).ok, false);
  });
});

describe('a real box', async () => {
  const docker = await findDocker();
  const up = docker !== null && (await dockerIsUp(docker));
  const options = { skip: up ? false : 'Docker is not running, so there is no container tier to test' };
  let image = '';
  let box: ContainerBox | undefined;
  let copy = '';
  let cleanup: (() => Promise<void>) | undefined;

  before(async () => {
    if (!up || docker === null) return;
    try {
      image = execFileSync(docker, ['image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}'], { encoding: 'utf8' }).trim();
    } catch {
      execFileSync(docker, ['pull', '-q', 'alpine:3.20'], { stdio: 'ignore' });
      image = execFileSync(docker, ['image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}'], { encoding: 'utf8' }).trim();
    }
    image = image.replace(/^docker\.io\/library\//, '');
    assert.match(image, /@sha256:[0-9a-f]{64}$/);
    const holder = await import('node:fs/promises').then((fs) => fs.mkdtemp(join(process.env['TEMP'] ?? '/tmp', 'hn-box-')));
    copy = join(await realpath(holder), 'copy');
    await mkdir(copy);
    cleanup = async () => {
      await import('node:fs/promises').then((fs) => fs.rm(holder, { recursive: true, force: true }));
    };
    box = await ContainerBox.start({ image, sessionId: `test${process.pid}`, workDir: copy, docker });
  });

  after(async () => {
    await box?.stop();
    await cleanup?.();
  });

  const run = (command: string, timeoutMs = 20_000) => (box as ContainerBox).exec(command, { cwd: '/work', timeoutMs, signal: new AbortController().signal });
  const text = (buffer: Buffer): string => buffer.toString('utf8').trim();

  it('reports a verified runtime, read back from Docker', options, async () => {
    const report = await (box as ContainerBox).inspect();
    assert.deepEqual(report.failures, []);
    assert.equal(report.facts.networkMode, 'none');
    assert.equal((box as ContainerBox).report.ok, true);
  });

  it('runs as nobody, with no capabilities and no new privileges', options, async () => {
    assert.equal(text((await run('id -u')).stdout), boxUser().split(':')[0]);
    assert.notEqual(text((await run('id -u')).stdout), '0');
    const status = text((await run('cat /proc/self/status')).stdout);
    assert.match(status, /CapEff:\s+0000000000000000/);
    assert.match(status, /NoNewPrivs:\s+1/);
  });

  it('writes the project copy and scratch space, and nothing else', options, async () => {
    assert.equal((await run('echo from-box > /work/out.txt')).code, 0);
    assert.equal((await readFile(join(copy, 'out.txt'), 'utf8')).trim(), 'from-box');
    assert.equal((await run('touch /tmp/x && touch /home/hn/y')).code, 0);
    assert.notEqual((await run('touch /etc/hn-test')).code, 0, 'the root filesystem is writable');
    assert.notEqual((await run('touch /usr/hn-test')).code, 0);
  });

  it('has no network at all', options, async () => {
    const result = await run('wget -T 3 -q -O- http://1.1.1.1/ 2>&1; echo exit=$?');
    assert.doesNotMatch(text(result.stdout), /exit=0/);
    assert.equal(text((await run('ls /sys/class/net')).stdout), 'lo');
  });

  it('has no Docker socket and no host files', options, async () => {
    assert.notEqual((await run('ls /var/run/docker.sock')).code, 0);
    assert.notEqual((await run('ls /mnt/c /host_mnt')).code, 0);
    assert.equal(text((await run('env | grep -c -i -E "key|token|secret" || true')).stdout), '0');
  });

  it('stops everything a timed-out command left running', options, async () => {
    const result = await run('sleep 1000', 700);
    assert.equal(result.timedOut, true);
    await new Promise((resolve) => setTimeout(resolve, 800));
    assert.equal(text((await run('ps | grep -c "[s]leep 1000" || true')).stdout), '0');
  });

  it('honours a cancel', options, async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 300);
    const result = await (box as ContainerBox).exec('sleep 1000', { cwd: '/work', timeoutMs: 20_000, signal: controller.signal });
    assert.equal(result.cancelled, true);
  });

  it('is gone after stop', options, async () => {
    await withTempDir(async (dir) => {
      const second = await ContainerBox.start({ image, sessionId: `gone${process.pid}`, workDir: await realpath(dir), docker: docker as string });
      await second.stop();
      assert.equal((await second.inspect()).ok, false, 'the box still exists');
    });
  });
});
