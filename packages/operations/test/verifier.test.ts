import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { connect } from 'node:net';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  ContainerBox,
  NonceSinks,
  canaryScript,
  dockerIsUp,
  findDocker,
  hostAddresses,
  tierOf,
  verifyRuntime,
  verifyTier,
  type ExecResult,
  type RuntimeReport,
  type Verifiable,
} from '@hn/operations';

const goodRuntime: RuntimeReport = verifyRuntime([
  {
    Config: { User: '65534:65534' },
    HostConfig: {
      NetworkMode: 'none',
      ReadonlyRootfs: true,
      CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges'],
      PidsLimit: 256,
      Memory: 1,
      NanoCpus: 1,
      PidMode: '',
      IpcMode: 'private',
      UsernsMode: '',
      Devices: [],
    },
    Mounts: [{ Source: '/tmp/copy', Destination: '/work' }],
  },
]);

const result = (stdout: string): ExecResult => ({ code: 0, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0), timedOut: false, cancelled: false, clipped: false });

/** A box that says whatever the test wants, so the verdict logic can be checked without Docker. */
function stand(runtime: RuntimeReport, output: string, act?: () => Promise<void> | void): Verifiable {
  return {
    inspect: async () => runtime,
    exec: async () => {
      await act?.();
      return result(output);
    },
  };
}

describe('the host-side sinks', () => {
  it('record a TCP connection over IPv4 and over IPv6', async () => {
    const sinks = await NonceSinks.open();
    try {
      for (const host of ['127.0.0.1', '::1']) {
        await new Promise<void>((resolve) => {
          const socket = connect({ host, port: sinks.tcpPort }, () => socket.end());
          socket.on('close', () => resolve());
          socket.on('error', () => resolve());
        });
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.ok(sinks.hits.filter((hit) => hit.protocol === 'tcp').length >= 1, 'no TCP hit recorded');
    } finally {
      await sinks.close();
    }
  });

  it('record a UDP packet only when it carries the nonce', async () => {
    const sinks = await NonceSinks.open();
    try {
      const client = createSocket('udp4');
      const send = (text: string) => new Promise<void>((resolve) => client.send(text, sinks.udpPort, '127.0.0.1', () => resolve()));
      await send('stray noise');
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(sinks.hits.length, 0, 'noise without the nonce counted as an escape');
      await send(`hello ${sinks.nonce}`);
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(sinks.hits.filter((hit) => hit.protocol === 'udp').length, 1);
      client.close();
    } finally {
      await sinks.close();
    }
  });
});

describe('the canary and the address list', () => {
  it('carries the nonce and both ports, and tries the metadata address, the Docker API and a socket', () => {
    const script = canaryScript({ nonce: 'abc123', tcpPort: 4001, udpPort: 4002 }, ['10.0.0.5']);
    for (const piece of ['abc123', '4001', '4002', '10.0.0.5', '169.254.169.254', ':2375', 'docker.sock', 'nc -u']) assert.ok(script.includes(piece), piece);
  });

  it('refuses to put anything but an address into the script', () => {
    const script = canaryScript({ nonce: 'n', tcpPort: 1, udpPort: 2 }, ['10.0.0.5', '1.2.3.4; rm -rf /', '$(id)', '`id`', 'a b']);
    assert.ok(!script.includes('rm -rf'));
    assert.ok(!script.includes('$(id)'));
    assert.ok(!script.includes('`id`'));
  });

  it('lists loopback, Docker\'s usual gateways and this machine\'s own addresses', () => {
    const addresses = hostAddresses();
    for (const expected of ['127.0.0.1', '::1', '172.17.0.1', '192.168.65.254']) assert.ok(addresses.includes(expected), expected);
  });
});

describe('the verdict', () => {
  const quiet = 'attempts=12\nprobe-tools nc=yes wget=yes\n';

  it('is not real when the box had no tool to try a connection with, however quiet it was', async () => {
    const sinks = await NonceSinks.open();
    try {
      const noTools = await verifyTier(stand(goodRuntime, 'attempts=12\nprobe-tools nc=no wget=no\n'), sinks, { settleMs: 10 });
      assert.equal(noTools.real, false);
      assert.match(noTools.evidence.join('\n'), /no nc/);
      const silent = await verifyTier(stand(goodRuntime, 'attempts=12\n'), sinks, { settleMs: 10 });
      assert.equal(silent.real, false, 'a canary that does not say which tools it had proves nothing');
    } finally {
      await sinks.close();
    }
  });

  it('is real only when the config is right, nothing arrived, and the box claims no success', async () => {
    const sinks = await NonceSinks.open();
    try {
      const report = await verifyTier(stand(goodRuntime, quiet), sinks, { settleMs: 10 });
      assert.equal(report.real, true);
      assert.deepEqual(report.evidence, []);
      assert.equal(report.attempts, 12);
      assert.equal(tierOf(report), 4);
      assert.ok(report.unchecked.length > 0, 'the limits must be stated, not hidden');
    } finally {
      await sinks.close();
    }
  });

  it('is not real when Docker reports the wrong configuration, however quiet the box is', async () => {
    const sinks = await NonceSinks.open();
    try {
      const bad = verifyRuntime([{ Config: { User: '' }, HostConfig: { NetworkMode: 'bridge' }, Mounts: [] }]);
      const report = await verifyTier(stand(bad, quiet), sinks, { settleMs: 10 });
      assert.equal(report.real, false);
      assert.equal(tierOf(report), 2);
      assert.ok(report.evidence.some((line) => /network is "bridge"/.test(line)));
    } finally {
      await sinks.close();
    }
  });

  it('is not real when something reached the host, even if the box says it was blocked', async () => {
    const sinks = await NonceSinks.open();
    try {
      const reach = () =>
        new Promise<void>((resolve) => {
          const socket = connect({ host: '127.0.0.1', port: sinks.tcpPort }, () => socket.end());
          socket.on('close', () => resolve());
          socket.on('error', () => resolve());
        });
      const report = await verifyTier(stand(goodRuntime, `${quiet}all blocked\n`, reach), sinks, { settleMs: 150 });
      assert.equal(report.real, false);
      assert.ok(report.hits.length >= 1);
      assert.ok(report.evidence.some((line) => /connection from the box reached this machine/.test(line)));
    } finally {
      await sinks.close();
    }
  });

  it('is not real when the box claims any success, because the claim is evidence of its own', async () => {
    const sinks = await NonceSinks.open();
    try {
      for (const claim of ['tcp-ok 10.0.0.5', 'docker-api-ok 172.17.0.1', 'metadata-ok', 'dns-ok', 'docker-socket-present /var/run/docker.sock']) {
        const report = await verifyTier(stand(goodRuntime, `${claim}\n${quiet}`), sinks, { settleMs: 10 });
        assert.equal(report.real, false, claim);
        assert.ok(report.selfReported.length === 1, claim);
      }
    } finally {
      await sinks.close();
    }
  });

  it('is not real when the canary never ran, because nothing was tested', async () => {
    const sinks = await NonceSinks.open();
    try {
      const report = await verifyTier(stand(goodRuntime, ''), sinks, { settleMs: 10 });
      assert.equal(report.real, false);
      assert.ok(report.evidence.some((line) => /did not run/.test(line)));
    } finally {
      await sinks.close();
    }
  });

  it('counts only what arrived during this run', async () => {
    const sinks = await NonceSinks.open();
    try {
      sinks.hits.push({ protocol: 'tcp', remote: 'earlier' });
      const report = await verifyTier(stand(goodRuntime, quiet), sinks, { settleMs: 10 });
      assert.equal(report.real, true);
    } finally {
      await sinks.close();
    }
  });
});

describe('against real containers', async () => {
  const docker = await findDocker();
  const up = docker !== null && (await dockerIsUp(docker));
  const options = { skip: up ? false : 'Docker is not running, so there is no container tier to verify' };
  const run = (...args: string[]): string => execFileSync(docker as string, args, { encoding: 'utf8' }).trim();

  let image = '';
  let holder = '';
  let copy = '';
  let box: ContainerBox | undefined;
  let sinks: NonceSinks | undefined;
  const unconfined: string[] = [];

  before(async () => {
    if (!up) return;
    try {
      image = run('image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}');
    } catch {
      run('pull', '-q', 'alpine:3.20');
      image = run('image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}');
    }
    image = image.replace(/^docker\.io\/library\//, '');
    holder = mkdtempSync(join(process.env['TEMP'] ?? '/tmp', 'hn-verify-'));
    copy = join(realpathSync(holder), 'copy');
    execFileSync('mkdir', ['-p', copy]).toString();
    sinks = await NonceSinks.open();
    box = await ContainerBox.start({ image, sessionId: `verify${process.pid}`, workDir: copy, docker: docker as string });
  });

  after(async () => {
    await box?.stop();
    for (const id of unconfined) execFileSync(docker as string, ['rm', '-f', id], { stdio: 'ignore' });
    await sinks?.close();
    if (holder !== '') rmSync(holder, { recursive: true, force: true });
  });

  it('passes a verified box: right config, nothing reaches the host, nothing claimed', options, async () => {
    const report = await verifyTier(box as ContainerBox, sinks as NonceSinks);
    assert.deepEqual(report.evidence, []);
    assert.equal(report.real, true);
    assert.ok(report.attempts >= 6, `only ${report.attempts} addresses were tried`);
    assert.equal(report.hits.length, 0);
  });

  it('positive control: the same canary, in an unconfined container, DOES reach the sinks', options, async () => {
    // Without this, a quiet result above could mean the canary or the sinks cannot detect anything.
    const script = canaryScript(sinks as NonceSinks, ['host.docker.internal']);
    const before = (sinks as NonceSinks).hits.length;
    run('run', '--rm', '--pull=never', '--add-host', 'host.docker.internal:host-gateway', image, 'sh', '-c', script);
    await new Promise((resolve) => setTimeout(resolve, 500));
    const hits = (sinks as NonceSinks).hits.slice(before);
    assert.ok(hits.some((hit) => hit.protocol === 'tcp'), 'the TCP sink did not see an unconfined container, so the verifier cannot be trusted');
    assert.ok(hits.some((hit) => hit.protocol === 'udp'), 'the UDP sink did not see an unconfined container');
  });

  it('attack: hostile_image_cannot_fake_canary (fake nc and wget, unconfined network)', options, async () => {
    // The image replaces the canary's tools with ones that do nothing and claim nothing, so the canary stays silent.
    const id = run('run', '-d', '--pull=never', '--entrypoint', 'sh', image, '-c', 'printf "#!/bin/sh\\nexit 1\\n" > /usr/local/bin/nc; cp /usr/local/bin/nc /usr/local/bin/wget; chmod +x /usr/local/bin/nc /usr/local/bin/wget; while :; do sleep 3600; done');
    unconfined.push(id);
    await new Promise((resolve) => setTimeout(resolve, 500));
    const hostile: Verifiable = {
      inspect: async () => verifyRuntime(JSON.parse(run('inspect', id))),
      exec: async (command) => {
        const out = execFileSync(docker as string, ['exec', id, 'sh', '-c', command], { encoding: 'utf8' });
        return result(out);
      },
    };
    const report = await verifyTier(hostile, sinks as NonceSinks, { targets: ['host.docker.internal'], settleMs: 300 });
    assert.equal(report.hits.length, 0, 'the fakes did stay silent, as the attack intends');
    assert.equal(report.selfReported.length, 0);
    assert.equal(report.real, false, 'a quiet canary was believed over Docker\'s own report');
    assert.ok(report.evidence.some((line) => /network is "bridge"/.test(line)));
  });
});
