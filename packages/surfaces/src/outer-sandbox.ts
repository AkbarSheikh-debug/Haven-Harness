import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import type { BashOperations } from '@hn/operations';
import { ModeRefusedError } from '@hn/security';
import { assertExternalSandbox, type ExternalSandbox } from './sandbox.ts';

/**
 * An operator's claim that something outside hn is the boundary (Phase 10, decision 5). There are two, and neither
 * is ever enough for yolo: both cap the session at `dont-ask` with an explicit `--allow` list, both log that the
 * tier was claimed, not verified, and both need an allow entry in the person's own home that a project cannot write.
 *
 *  - `--external-sandbox` (sandbox.ts): hn runs OUTSIDE the claimed sandbox, and its canary proves the sandbox cannot
 *    reach the machine hn runs on. Run from inside the sandbox it refuses itself, correctly: hn's own listeners are
 *    one network away from the shell (checked in a Linux container on 2026-11-19: six connections reached them).
 *  - `--benchmark-container` (here): hn runs INSIDE a benchmark container, such as Harbor's, and that container is the
 *    only boundary. hn cannot verify it from inside, so this is a narrower claim that says so: it needs its own
 *    allow entry, `HN_BENCH_CONTAINER=1` set by whoever runs the benchmark, and a process that really is inside a
 *    Linux container (checked from what a container leaves behind, never taken from a flag). A workstation, a
 *    Windows or macOS host and a Linux machine that is not a container are all refused.
 */

export const BENCH_ALLOW_FILE = 'benchmark-container-allowed';

/** What the container check looks at, so tests can show a workstation being refused without being on one. */
export interface ContainerProbe {
  readonly platform: NodeJS.Platform;
  readonly exists: (path: string) => Promise<boolean>;
  readonly read: (path: string) => Promise<string | null>;
}

export const realProbe: ContainerProbe = {
  platform: process.platform,
  exists: (path) => stat(path).then(() => true, () => false),
  read: (path) => readFile(path, 'utf8').then((text) => text, () => null),
};

/** True only on Linux, and only when the marker files or the init process's cgroup say a container runtime started this. */
export async function insideLinuxContainer(probe: ContainerProbe = realProbe): Promise<boolean> {
  if (probe.platform !== 'linux') return false;
  if ((await probe.exists('/.dockerenv')) || (await probe.exists('/run/.containerenv'))) return true;
  const cgroup = await probe.read('/proc/1/cgroup');
  return cgroup !== null && /\b(docker|containerd|kubepods|libpod|podman)\b/.test(cgroup);
}

export async function assertBenchContainer(home: string, env: NodeJS.ProcessEnv, probe: ContainerProbe = realProbe): Promise<ExternalSandbox> {
  if (!(await probe.exists(join(home, BENCH_ALLOW_FILE)))) throw new HnError('BENCH_CONTAINER_NOT_ALLOWED', `--benchmark-container needs a user-level allow entry: create ${join(home, BENCH_ALLOW_FILE)}. A project cannot grant this itself.`);
  if (env['HN_BENCH_CONTAINER'] !== '1') throw new HnError('BENCH_CONTAINER_NOT_DECLARED', '--benchmark-container also needs HN_BENCH_CONTAINER=1 in the environment, set by whoever runs the benchmark.');
  if (!(await insideLinuxContainer(probe))) throw new HnError('BENCH_CONTAINER_NOT_A_CONTAINER', 'This process is not inside a Linux container, so a claimed benchmark container is refused. A workstation has no such boundary.');
  return { tier: 3, asserted: true };
}

export interface OuterClaimInput {
  readonly options: { readonly externalSandbox?: boolean; readonly benchmarkContainer?: boolean; readonly mode: string; readonly allow?: readonly string[]; readonly workdir: string };
  /** The session already runs in a verified box of its own. */
  readonly boxed: boolean;
  readonly home: string;
  readonly env: NodeJS.ProcessEnv;
  readonly bash: BashOperations;
  readonly probe?: ContainerProbe;
}

/** The claimed outer sandbox, or null when none was claimed. Either claim is capped at dont-ask with an explicit allow list. */
export async function claimOuterSandbox(input: OuterClaimInput): Promise<ExternalSandbox | null> {
  const { options } = input;
  const external = options.externalSandbox === true;
  const bench = options.benchmarkContainer === true;
  if (!external && !bench) return null;
  if (external && bench) throw new HnError('SANDBOX_CONFLICT', 'Use --external-sandbox or --benchmark-container, not both.');
  if (input.boxed) throw new HnError('SANDBOX_CONFLICT', `Use --sandbox container or ${external ? '--external-sandbox' : '--benchmark-container'}, not both.`);
  if (options.mode !== 'dont-ask' || options.allow === undefined) {
    throw new ModeRefusedError(options.mode, 'a claimed outer sandbox caps the session at dont-ask with an explicit --allow list, never yolo.');
  }
  return bench ? assertBenchContainer(input.home, input.env, input.probe) : assertExternalSandbox(input.home, input.env, input.bash, options.workdir);
}
