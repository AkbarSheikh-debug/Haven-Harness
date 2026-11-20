import { access, mkdir, mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolvePaths } from '@hn/config';
import {
  CheckpointStore,
  ContainerBox,
  NonceSinks,
  SANDBOX_EXEC,
  createSafeFiles,
  detectLinuxSupport,
  dockerIsUp,
  engineVersion,
  dockerDesktopProblem,
  dockerPlatformName,
  findBash,
  findDocker,
  probeKeychain,
  ripgrepPath,
  strayBoxes,
  verifyTier,
} from '@hn/operations';
import { verifyInstalledTree } from '@hn/release';
import { TrustStore, loadBashParser, loadLocalPolicy, unusableGrammars, verifyAudit } from '@hn/security';
import { loadMcpConfig } from './mcp-config.ts';
import { readReleaseInfo, resolveHelper } from './helper.ts';

/**
 * `hn doctor`: what is true about this machine's security posture, said plainly. A check says ok, warn or fail, and a
 * fail means something that is supposed to protect you is missing or broken, so the exit code is not zero.
 */

export type Status = 'ok' | 'warn' | 'fail';

export interface Check {
  readonly name: string;
  readonly status: Status;
  readonly detail: string;
}

export interface DoctorOptions {
  readonly repoRoot: string;
  readonly env?: NodeJS.ProcessEnv;
  /** A digest-pinned image. When given, a real box is started and verified from outside, which takes several seconds. */
  readonly image?: string;
}

/** CVE-2025-9074 let a container reach the Docker Engine API. It is fixed in Docker Desktop 4.44.3, which ships engine 28.3.3. */
const MIN_ENGINE = [28, 3, 3] as const;

const atLeast = (version: string, minimum: readonly number[]): boolean => {
  const parts = version.split('.').map((part) => Number.parseInt(part, 10));
  for (let i = 0; i < minimum.length; i += 1) {
    const have = parts[i] ?? 0;
    if (Number.isNaN(have)) return false;
    if (have !== minimum[i]) return have > (minimum[i] as number);
  }
  return true;
};

const message = (error: unknown): string => (error instanceof Error ? error.message : String(error));

export async function runDoctor(options: DoctorOptions): Promise<Check[]> {
  const env = options.env ?? process.env;
  const paths = resolvePaths(env);
  const checks: Check[] = [];
  const add = (name: string, status: Status, detail: string): void => void checks.push({ name, status, detail });

  const [major = 0, minor = 0] = process.versions.node.split('.').map(Number);
  add('node', major > 24 || (major === 24 && minor >= 14) ? 'ok' : 'fail', `Node ${process.versions.node}${major > 24 || (major === 24 && minor >= 14) ? '' : ' is older than 24.14, which hn needs'}`);

  const probe: Record<string, unknown> = {};
  let protoOff = false;
  try {
    protoOff = probe['__proto__'] === undefined;
  } catch {
    protoOff = true;
  }
  add('__proto__ disabled', protoOff ? 'ok' : 'fail', protoOff ? 'started with --disable-proto=throw' : 'not disabled. Start hn through its launcher, which sets --disable-proto=throw');

  // The helper is what makes file access safe against a link swapped in mid-operation.
  const installed = await readReleaseInfo(env);
  if (installed !== null) {
    const tree = await verifyInstalledTree(installed.root);
    add('release integrity', tree.ok ? 'ok' : 'fail', tree.ok ? `${tree.checked} files match the manifest signed for ${tree.version}` : `${tree.problems.join('; ')}. Reinstall hn`);
  }
  const helper = await resolveHelper({ env, repoRoot: options.repoRoot, home: paths.home, download: false }).catch((error: unknown) => {
    add('hn-sandbox helper', 'fail', message(error));
    return null;
  });
  if (helper === null) {
    if (installed === null) add('hn-sandbox helper', 'fail', 'not found, so file access is refused. Build it with: pnpm build:sandbox');
    else if (!checks.some((check) => check.name === 'hn-sandbox helper')) add('hn-sandbox helper', 'warn', `not installed yet. hn fetches ${installed.version} for ${process.platform}-${process.arch} and checks its signature the first time a session needs it, or run: hn setup`);
  } else {
    const scratch = await mkdtemp(join(tmpdir(), 'hn-doctor-'));
    try {
      const files = createSafeFiles(helper);
      await mkdir(join(scratch, 'root'));
      await files.write(join(scratch, 'root'), join(scratch, 'root', 'probe.txt'), Buffer.from('ok'));
      const back = (await files.read(join(scratch, 'root'), join(scratch, 'root', 'probe.txt'), 100)).toString();
      const escaped = await files.read(join(scratch, 'root'), join(scratch, 'outside.txt'), 100).then(() => true, () => false);
      add('hn-sandbox helper', back === 'ok' && !escaped ? 'ok' : 'fail', back === 'ok' && !escaped ? `${helper}; reads and writes work and a path outside the root is refused` : 'the helper did not behave: it read outside its root or lost data');
    } catch (error) {
      add('hn-sandbox helper', 'fail', `found at ${helper}, but its self-test failed: ${message(error)}`);
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
    const keychain = await probeKeychain(helper);
    add('OS keychain', keychain === 'supported' ? 'ok' : 'warn', keychain === 'supported' ? 'available' : keychain === 'unsupported' ? 'not available on this platform yet, so keys live in a file only you can read. A process running as you could read that file' : 'the helper could not reach the keychain');
  }

  try {
    await loadBashParser();
    add('bash parser', 'ok', 'loaded, and its grammar matches its pinned hash');
  } catch (error) {
    add('bash parser', 'fail', `${message(error)} Without it every shell command is treated as execution, with only string rules to go on`);
  }
  const grammars = await unusableGrammars();
  add('syntax grammars', grammars.length === 0 ? 'ok' : 'warn', grammars.length === 0 ? 'all match their pinned hashes' : `not used: ${grammars.map((entry) => `${entry.language} (${entry.reason})`).join(', ')}`);

  try {
    const bash = findBash(env);
    add('shell', 'ok', bash);
  } catch (error) {
    add('shell', 'fail', message(error));
  }
  add('ripgrep', await access(ripgrepPath).then(() => true, () => false) ? 'ok' : 'fail', ripgrepPath);

  const docker = await findDocker(env);
  if (docker === null) {
    add('container sandbox', 'warn', 'Docker was not found, so there is no sandbox: yolo is refused, and an unattended run cannot use bash. Install Docker to enable it');
  } else if (!(await dockerIsUp(docker))) {
    add('container sandbox', 'warn', `Docker is installed (${docker}) but not running, so there is no sandbox until it is started`);
  } else {
    const version = await engineVersion(docker);
    const recent = version !== null && atLeast(version, MIN_ENGINE);
    add('docker engine', recent ? 'ok' : 'warn', version === null ? 'its version could not be read' : recent ? `engine ${version}` : `engine ${version} is older than ${MIN_ENGINE.join('.')}, which fixes CVE-2025-9074 (a container reaching the Docker Engine API). Update Docker Desktop to 4.44.3 or later`);
    // The fix is in a Docker Desktop release; a Desktop older than 4.44.3 lets a container reach the engine, so it fails.
    const platform = await dockerPlatformName(docker);
    const desktopProblem = platform === null ? null : dockerDesktopProblem(platform);
    if (platform !== null && /Docker Desktop/.test(platform)) add('docker desktop', desktopProblem === null ? 'ok' : 'fail', desktopProblem ?? platform);
    const strays = await strayBoxes(docker);
    add('stray boxes', strays.length === 0 ? 'ok' : 'warn', strays.length === 0 ? 'none running' : `still running from an earlier session: ${strays.join(', ')}. Remove with: docker rm -f ${strays.join(' ')}`);
    if (options.image !== undefined) {
      if (helper === null) add('container tier', 'fail', 'cannot verify a box without the hn-sandbox helper');
      else add(...(await verifyBox(docker, options.image)));
    } else {
      add('container tier', 'ok', 'Docker is ready. Run `hn doctor --image name@sha256:...` to verify a real box from outside');
    }
  }

  // The native box of this OS. It is a tier of its own, claimed only when the outside-in check passes at session start.
  if (process.platform === 'linux') {
    const support = await detectLinuxSupport({ ...(helper === null ? {} : { helper }), env });
    if (!support.namespaces) add('linux box', 'warn', `no native box here: ${support.namespaceProblem ?? 'bubblewrap cannot start'} Use --sandbox container instead`);
    else {
      const layers = ['namespaces: every one unshared', support.landlockAbi >= 1 ? `Landlock (ABI ${support.landlockAbi})` : 'Landlock: not in this kernel, so the box is a lower tier', support.seccomp ? 'seccomp' : 'seccomp: not in this kernel, so the box is a lower tier'];
      add('linux box', support.landlockAbi >= 1 && support.seccomp ? 'ok' : 'warn', `${support.bwrap}; ${layers.join('; ')}. Each layer is verified from outside when a session starts`);
    }
  } else if (process.platform === 'darwin') {
    const present = await access(SANDBOX_EXEC).then(() => true, () => false);
    add('macos box', present ? 'ok' : 'warn', present ? `${SANDBOX_EXEC} (Seatbelt; Apple lists it as deprecated). It is verified from outside when a session starts. A process that calls setsid can outlive its command: that limit is part of this box` : `${SANDBOX_EXEC} was not found, so there is no native box. Use --sandbox container instead`);
  }

  // The key everything signed or sealed depends on.
  const keyFile = await stat(paths.logKey).catch(() => null);
  if (keyFile === null) add('log key', 'ok', 'not created yet; it is made on first use');
  else if (process.platform !== 'win32' && (keyFile.mode & 0o077) !== 0) add('log key', 'fail', `${paths.logKey} can be read by other accounts (mode ${(keyFile.mode & 0o777).toString(8)}). Run: chmod 600 ${paths.logKey}`);
  else add('log key', 'ok', `${paths.logKey}${process.platform === 'win32' ? ' (permissions are not checked on Windows)' : ', readable only by you'}. A process running as you can still read it, so a forged log is only caught while the key is not stolen`);

  const key = keyFile === null ? null : await readFile(paths.logKey).catch(() => null);
  if (key !== null) {
    try {
      const trust = new TrustStore(join(paths.home, 'trust'), key, { keepText: true });
      const loaded = await trust.load();
      add('trust store', loaded.tampered ? 'fail' : 'ok', loaded.tampered ? `${join(paths.home, 'trust')} fails its integrity check, so nothing in it is trusted. Delete it and approve again` : 'its integrity check passes');
    } catch (error) {
      add('trust store', 'fail', message(error));
    }
    const auditDir = join(paths.home, 'audit');
    const names = (await readdir(auditDir).catch(() => [] as string[])).filter((name) => name.endsWith('.jsonl'));
    const bad: string[] = [];
    for (const name of names) {
      const result = verifyAudit(await readFile(join(auditDir, name), 'utf8'), key);
      if (!result.ok) bad.push(`${name} (${result.reason})`);
    }
    add('audit chains', bad.length === 0 ? 'ok' : 'fail', bad.length === 0 ? `${names.length} verified` : `${bad.length} failed verification: ${bad.slice(0, 3).join('; ')}`);
    if (helper !== null) {
      try {
        const store = new CheckpointStore({ dir: join(paths.home, 'checkpoints'), key, files: createSafeFiles(helper) });
        add('checkpoints', 'ok', `${(await store.list()).length} readable under this key`);
      } catch (error) {
        add('checkpoints', 'warn', message(error));
      }
    }
  }

  for (const [name, load] of [['mcp.json', () => loadMcpConfig(paths.home)], ['policy.json', () => loadLocalPolicy(paths.home)]] as const) {
    try {
      await load();
      add(name, 'ok', (await stat(join(paths.home, name)).catch(() => null)) === null ? 'not present, so nothing is configured' : 'valid');
    } catch (error) {
      add(name, 'fail', message(error));
    }
  }
  add('external sandbox', 'ok', (await stat(join(paths.home, 'external-sandbox-allowed')).catch(() => null)) === null ? 'no operator allow entry, so --external-sandbox is refused' : 'an operator allow entry exists, so --external-sandbox is possible on a CI host');
  add('benchmark container', 'ok', (await stat(join(paths.home, 'benchmark-container-allowed')).catch(() => null)) === null ? 'no operator allow entry, so --benchmark-container is refused' : 'an operator allow entry exists, so --benchmark-container works inside a Linux container that sets HN_BENCH_CONTAINER=1');
  return checks;
}

async function verifyBox(docker: string, image: string): Promise<[string, Status, string]> {
  const scratch = await mkdtemp(join(tmpdir(), 'hn-doctor-box-'));
  const sinks = await NonceSinks.open();
  let box: ContainerBox | undefined;
  try {
    box = await ContainerBox.start({ image, sessionId: `doctor${process.pid}`, workDir: scratch, docker });
    const report = await verifyTier(box, sinks);
    return ['container tier', report.real ? 'ok' : 'fail', report.real ? `a real box passed the outside-in check: tier 4. Not covered: ${report.unchecked.join('; ')}` : `the box did not pass: ${report.evidence.join('; ')}`];
  } catch (error) {
    return ['container tier', 'fail', message(error)];
  } finally {
    await box?.stop();
    await sinks.close();
    await rm(scratch, { recursive: true, force: true });
  }
}

const MARK: Record<Status, string> = { ok: 'ok  ', warn: 'warn', fail: 'FAIL' };

export function formatDoctor(checks: readonly Check[]): string {
  const width = Math.max(...checks.map((check) => check.name.length));
  const lines = checks.map((check) => `${MARK[check.status]}  ${check.name.padEnd(width)}  ${check.detail}`);
  const fails = checks.filter((check) => check.status === 'fail').length;
  const warns = checks.filter((check) => check.status === 'warn').length;
  return `${lines.join('\n')}\n\n${fails === 0 ? 'Nothing that protects you is broken.' : `${fails} check(s) failed: something that is supposed to protect you is missing or broken.`}${warns === 0 ? '' : ` ${warns} warning(s).`}\n`;
}

export const doctorExitCode = (checks: readonly Check[]): number => (checks.some((check) => check.status === 'fail') ? 1 : 0);
