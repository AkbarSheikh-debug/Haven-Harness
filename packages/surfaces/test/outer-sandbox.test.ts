import assert from 'node:assert/strict';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { HnError } from '@hn/core';
import { KeyStore } from '@hn/provider';
import { ModeRefusedError } from '@hn/security';
import { BENCH_ALLOW_FILE, assertBenchContainer, claimOuterSandbox, insideLinuxContainer, openSession, realProbe, type ContainerProbe } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

/** A host that leaves behind exactly these files, and whose init process has this cgroup. */
const host = (platform: NodeJS.Platform, files: readonly string[] = [], cgroup: string | null = null): ContainerProbe => ({
  platform,
  exists: async (path) => files.includes(path),
  read: async (path) => (path === '/proc/1/cgroup' ? cgroup : null),
});
const bash = { exec: async () => { throw new Error('the container claim must never run a canary through the shell'); } } as never;
const HOME = '/home/x/.hn';
const ALLOW = join(HOME, BENCH_ALLOW_FILE);
const code = (error: unknown): string | undefined => (error instanceof HnError ? error.code : undefined);

describe('is this process inside a Linux container', () => {
  it('says yes only on Linux, from what a container runtime leaves behind', async () => {
    assert.equal(await insideLinuxContainer(host('linux', ['/.dockerenv'])), true);
    assert.equal(await insideLinuxContainer(host('linux', ['/run/.containerenv'])), true, 'podman');
    for (const cgroup of ['12:cpu:/docker/4f3a', '0::/system.slice/containerd.service', '1:name=systemd:/kubepods/burstable/pod1', '0::/libpod-9a8b']) assert.equal(await insideLinuxContainer(host('linux', [], cgroup)), true, cgroup);
  });

  it('says no for a workstation, a bare Linux machine, and a Windows or macOS host with every marker present', async () => {
    assert.equal(await insideLinuxContainer(host('linux')), false, 'nothing left behind and no cgroup');
    for (const cgroup of ['0::/init.scope', '0::/', '12:cpu:/user.slice/user-1000.slice', '0::/system.slice/ssh.service', '0::/dockerish', '']) assert.equal(await insideLinuxContainer(host('linux', [], cgroup)), false, JSON.stringify(cgroup));
    for (const platform of ['win32', 'darwin', 'freebsd'] as const) assert.equal(await insideLinuxContainer(host(platform, ['/.dockerenv', '/run/.containerenv'], '0::/docker/abc')), false, `${platform} even with every marker`);
  });
});

describe('--benchmark-container', () => {
  const inContainer = host('linux', ['/.dockerenv', ALLOW]);

  it('is accepted only when the operator allowed it, declared it, and the process really is in a container', async () => {
    assert.deepEqual(await assertBenchContainer(HOME, { HN_BENCH_CONTAINER: '1' }, inContainer), { tier: 3, asserted: true });
  });

  it('attack: benchmark_container_needs_operator_allow_entry. is refused without the allow entry in the person\'s home, however everything else looks', async () => {
    await assert.rejects(assertBenchContainer(HOME, { HN_BENCH_CONTAINER: '1' }, host('linux', ['/.dockerenv'])), (error: unknown) => code(error) === 'BENCH_CONTAINER_NOT_ALLOWED' && /A project cannot grant this itself/.test((error as Error).message));
  });

  it('is refused unless HN_BENCH_CONTAINER is exactly 1', async () => {
    for (const value of [undefined, '', '0', 'true', 'yes', '1 ', ' 1', 'on']) {
      await assert.rejects(assertBenchContainer(HOME, value === undefined ? {} : { HN_BENCH_CONTAINER: value }, inContainer), (error: unknown) => code(error) === 'BENCH_CONTAINER_NOT_DECLARED', JSON.stringify(value));
    }
  });

  it('attack: benchmark_container_refused_on_workstation. is refused on a workstation even with the allow entry and the variable both in place', async () => {
    const env = { HN_BENCH_CONTAINER: '1' };
    for (const probe of [host('win32', [ALLOW, '/.dockerenv']), host('darwin', [ALLOW]), host('linux', [ALLOW], '0::/init.scope'), host('linux', [ALLOW])]) {
      await assert.rejects(assertBenchContainer(HOME, env, probe), (error: unknown) => code(error) === 'BENCH_CONTAINER_NOT_A_CONTAINER' && /A workstation has no such boundary/.test((error as Error).message), probe.platform);
    }
  });
});

describe('claiming an outer sandbox', () => {
  const base = { boxed: false, home: HOME, env: { HN_BENCH_CONTAINER: '1' }, bash, probe: host('linux', ['/.dockerenv', ALLOW]) };
  const claim = (options: Partial<Parameters<typeof claimOuterSandbox>[0]['options']>, extra: Partial<Parameters<typeof claimOuterSandbox>[0]> = {}) => claimOuterSandbox({ ...base, ...extra, options: { mode: 'dont-ask', allow: ['bash'], workdir: '/work', ...options } });

  it('is nothing when no claim was made, whatever else is true of the host', async () => {
    assert.equal(await claim({}), null);
  });

  it('refuses both claims at once, and a claim inside a verified box', async () => {
    await assert.rejects(claim({ externalSandbox: true, benchmarkContainer: true }), /--external-sandbox or --benchmark-container, not both/);
    await assert.rejects(claim({ externalSandbox: true }, { boxed: true }), /Use --sandbox container or --external-sandbox, not both\./, 'the existing message is unchanged');
    await assert.rejects(claim({ benchmarkContainer: true }, { boxed: true }), /Use --sandbox container or --benchmark-container, not both\./);
  });

  it('attack: benchmark_container_never_yolo. caps the container claim at dont-ask with an explicit allow list: every other mode, and no list, is refused', async () => {
    for (const mode of ['yolo', 'safe', 'accept-edits', 'smart', 'read-only', 'plan']) {
      await assert.rejects(claim({ benchmarkContainer: true, mode }), (error: unknown) => error instanceof ModeRefusedError && /never yolo/.test(error.message), mode);
    }
    await assert.rejects(claimOuterSandbox({ ...base, options: { mode: 'dont-ask', workdir: '/work', benchmarkContainer: true } }), ModeRefusedError, 'no --allow list at all');
    assert.deepEqual(await claim({ benchmarkContainer: true }), { tier: 3, asserted: true });
  });

  it('never runs the external sandbox canary for the container claim, and still runs it (and refuses) for the external one', async () => {
    // `bash` throws if it is ever used: the container claim passed above without touching it.
    await assert.rejects(claim({ externalSandbox: true }), /user-level allow entry|CI|canary|could not be checked|looks like a workstation/);
  });
});

const thisHostIsAContainer = await insideLinuxContainer(realProbe);

describe('through a real session on this machine', () => {
  it('refuses the container claim here even with the allow entry and the variable, unless this really is a container', { skip: thisHostIsAContainer ? 'this host is a Linux container' : false, timeout: 120_000 }, async () => {
    await withTempDir(async (dir) => {
      const root = await realpath(dir);
      const home = join(root, '.home');
      await mkdir(home, { recursive: true });
      await writeFile(join(home, BENCH_ALLOW_FILE), '');
      await assert.rejects(
        openSession({ workdir: root, mode: 'dont-ask', allow: ['bash'], benchmarkContainer: true, model: 'fake', baseUrl: 'http://127.0.0.1:1/v1', window: 64_000, env: { HN_HOME: home, HN_BENCH_CONTAINER: '1' }, verify: 'off' }, KeyStore.capture({})),
        (error: unknown) => code(error) === 'BENCH_CONTAINER_NOT_A_CONTAINER',
      );
    });
  });
});
