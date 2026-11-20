import { createHash, randomBytes } from 'node:crypto';
import { readFile, rm, stat, writeFile } from 'node:fs/promises';
import { readlinkSync } from 'node:fs';
import { join } from 'node:path';
import { nativeCanary } from './native-verifier.ts';
import type { PosixRunRequest, BoxLayers } from './posix-box.ts';
import type { ExecResult } from './types.ts';
import { hostAddresses, type NonceSinks, type SinkHit } from './verifier.ts';

/**
 * The outside-in check for the Linux and macOS boxes. It is the check the Windows box passes, for the same reasons:
 * nothing the box prints clears it. What clears it, from outside:
 * - host listeners on every address that saw no connection or packet from the box;
 * - a nonce file outside the box that the box could not read, and a file outside it that it could not create;
 * - a proof file the box wrote inside itself, which only running the canary can produce, so a runner that skips it fails;
 * - a background process the canary started that stopped writing once the box ended;
 * - on Linux, the namespaces the process was really in (compared with this process's own, which the box cannot know),
 *   no capability, and for each layer the box says it applied (Landlock, seccomp) a probe that only that layer stops.
 * A layer is reported as verified only when its probe held; a layer the machine lacks is named as missing.
 */

/** What the verifier needs from a box. A real box satisfies it, and so does each stand-in the tests use. */
export interface OsVerifiable {
  readonly kind: 'linux' | 'macos';
  readonly work: string;
  readonly tmp: string;
  readonly layers: BoxLayers;
  run(program: string, args: readonly string[], request: PosixRunRequest): Promise<ExecResult>;
}

export interface OsVerifyOptions {
  /** A folder on this machine outside the box, owned by the host, for the nonce file and the escape check. */
  readonly outside: string;
  /** The canary's interpreter (Node). The box must be able to read and run it. */
  readonly interpreter: string;
  readonly targets?: readonly string[];
  readonly timeoutMs?: number;
  readonly settleMs?: number;
}

export interface OsTierReport {
  readonly kind: 'linux' | 'macos';
  /** True only when every check held. */
  readonly real: boolean;
  readonly evidence: readonly string[];
  readonly hits: readonly SinkHit[];
  readonly selfReported: readonly string[];
  readonly attempts: number;
  /** The layers the box says it applied, as built. */
  readonly layers: BoxLayers;
  /** The layers whose probe held here. Never more than `layers.applied`, and empty unless `real`. */
  readonly verifiedLayers: readonly string[];
  /** What this check does not cover, so the limit is stated and not hidden. */
  readonly unchecked: readonly string[];
}

const UNCHECKED_COMMON = ['timing channels', 'reading the system folders a box is given read-only (the system, certificates)'];
const UNCHECKED_LINUX = [...UNCHECKED_COMMON, 'kernel bugs: the box shares the host kernel, and Landlock and seccomp narrow that surface without removing it'];
const UNCHECKED_MACOS = [...UNCHECKED_COMMON, 'a process that calls setsid can outlive the command (Seatbelt has no process namespace)', 'sandbox-exec is deprecated by Apple'];

const NAMESPACES = ['net', 'pid', 'ipc', 'uts', 'user', 'mnt', 'cgroup'] as const;

/** `ptrace` is the call the probe makes, and its number depends on the architecture. */
const PTRACE_NUMBER: Readonly<Record<string, number>> = { x64: 101, arm64: 117 };

const shQuote = (text: string): string => `'${text.replaceAll("'", `'\\''`)}'`;

/** The facts script a Linux box runs about itself. Plain `sh`, no tool but the shell and, for the seccomp probe, perl. */
export function linuxFactsScript(arch: string = process.arch): string {
  const ptrace = PTRACE_NUMBER[arch];
  return [
    'echo facts-ran',
    `for n in ${NAMESPACES.join(' ')}; do echo "ns-$n=$(readlink /proc/self/ns/$n 2>/dev/null)"; done`,
    'while read -r key value; do case "$key" in CapEff:) echo "capeff=$value";; NoNewPrivs:) echo "nonewprivs=$value";; Seccomp:) echo "seccomp=$value";; esac; done < /proc/self/status',
    // /run is a tmpfs the mount table makes writable. Only Landlock can stop a write there.
    'if ( : > /run/hn-landlock-probe ) 2>/dev/null; then echo run-writable=yes; rm -f /run/hn-landlock-probe; else echo run-writable=no; fi',
    // ptrace with a request no kernel knows answers ESRCH or EIO when it is allowed to look, so EPERM can only be the filter.
    ptrace === undefined
      ? 'echo ptrace-errno=untested'
      : `if command -v perl >/dev/null 2>&1; then echo "ptrace-errno=$(perl -e '$r = syscall(${ptrace}, -1, 0, 0, 0); print $!+0')"; else echo ptrace-errno=untested; fi`,
  ].join('\n');
}

/** The survivor check as a shell script for its own run in the box: a background loop writing to `beatFile` for 20 seconds. */
export function survivorShellScript(beatFile: string): string {
  const file = shQuote(beatFile);
  return [
    // Output goes to /dev/null so the pipe the runner waits on is not held open by the background process.
    `( n=0; while [ $n -lt 200 ]; do printf b >> ${file}; sleep 0.1; n=$((n+1)); done ) >/dev/null 2>&1 &`,
    'i=0',
    `while [ ! -s ${file} ] && [ $i -lt 150 ]; do sleep 0.1; i=$((i+1)); done`,
  ].join('\n');
}

function parseFacts(output: string): Map<string, string> {
  const facts = new Map<string, string>();
  for (const line of output.split(/\r?\n/)) {
    const at = line.indexOf('=');
    if (at > 0) facts.set(line.slice(0, at), line.slice(at + 1).trim());
  }
  return facts;
}

/** The namespaces this process is in, read from outside the box. */
export function hostNamespaces(): Record<string, string> {
  const found: Record<string, string> = {};
  for (const name of NAMESPACES) {
    try {
      found[name] = readlinkSync(`/proc/self/ns/${name}`);
    } catch {
      // An older kernel without that namespace: nothing to compare.
    }
  }
  return found;
}

/** What the box's own facts say about it, judged against what the host knows. */
export function linuxFactsProblems(output: string, host: Readonly<Record<string, string>>, layers: BoxLayers): { problems: string[]; verified: string[] } {
  const facts = parseFacts(output);
  const problems: string[] = [];
  const verified: string[] = [];
  if (!output.includes('facts-ran')) return { problems: ['The box did not run the facts script, so its namespaces, capabilities and layers were not checked.'], verified };
  const shared = NAMESPACES.filter((name) => host[name] !== undefined && facts.get(`ns-${name}`) === host[name]);
  const unreadable = NAMESPACES.filter((name) => host[name] !== undefined && (facts.get(`ns-${name}`) ?? '') === '');
  for (const name of shared) problems.push(`The box is in this machine's ${name} namespace, so it is not unshared.`);
  for (const name of unreadable) problems.push(`The box could not say which ${name} namespace it is in, so it was not checked.`);
  if (shared.length === 0 && unreadable.length === 0) verified.push('namespaces');
  const capabilities = facts.get('capeff') ?? '';
  if (!/^0+$/.test(capabilities)) problems.push(`The box process holds capabilities (${capabilities === '' ? 'unreadable' : capabilities}); it must hold none.`);
  const applied = new Set(layers.applied);
  if (applied.has('landlock') || applied.has('seccomp')) {
    if (facts.get('nonewprivs') !== '1') problems.push('no_new_privs is not set, so the box could gain privileges through a setuid program.');
  }
  if (applied.has('landlock')) {
    if (facts.get('run-writable') === 'no') verified.push('landlock');
    else problems.push('Landlock was applied, but the box could write to a folder only its mount table opens (/run), so the filesystem rule is not in force.');
  }
  if (applied.has('seccomp')) {
    const mode = facts.get('seccomp');
    const errno = facts.get('ptrace-errno');
    if (mode !== '2') problems.push(`seccomp was applied, but the process is in seccomp mode ${mode ?? 'unknown'}, not a filter (2).`);
    else if (errno !== undefined && errno !== 'untested' && errno !== '1') problems.push(`seccomp is in filter mode, but ptrace was not denied (errno ${errno}), so the filter does not hold what it lists.`);
    else verified.push('seccomp');
  }
  return { problems, verified };
}

const sizeOf = (path: string): Promise<number> => stat(path).then((info) => info.size, () => 0);
const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);
/** Five seconds of heartbeats: far more than a box that ends at once allows. */
const SURVIVOR_BEATS = 50;

/** Runs the canary in the box and reads the verdict from the host. Run it again whenever the box is made again. */
export async function verifyOsBoxTier(box: OsVerifiable, sinks: NonceSinks, options: OsVerifyOptions): Promise<OsTierReport> {
  const before = sinks.hits.length;
  const salt = randomBytes(16).toString('hex');
  // One name per run, so a process a failed box left running cannot write into the next run's files.
  const run = randomBytes(6).toString('hex');
  const nonceFile = join(options.outside, `nonce-${run}.txt`);
  const escapeFile = join(options.outside, `escape-${run}.txt`);
  const proofFile = join(box.tmp, `proof-${run}`);
  const beatFile = join(box.tmp, `beat-${run}`);
  const timeoutMs = options.timeoutMs ?? 60_000;
  await writeFile(nonceFile, `secret ${sinks.nonce}`);
  const evidence: string[] = [];
  const verified: string[] = [];
  let canary: ExecResult | null = null;
  try {
    const script = nativeCanary({ nonce: sinks.nonce, salt, tcpPort: sinks.tcpPort, udpPort: sinks.udpPort, targets: options.targets ?? hostAddresses(), nonceFile, escapeFile, proofFile });
    canary = await box.run(options.interpreter, ['-'], { cwd: box.work, timeoutMs, signal: new AbortController().signal, input: script });

    if (box.kind === 'linux') {
      const facts = await box.run('/bin/sh', ['-c', linuxFactsScript()], { cwd: box.work, timeoutMs, signal: new AbortController().signal });
      const judged = linuxFactsProblems(facts.stdout.toString('utf8'), hostNamespaces(), box.layers);
      evidence.push(...judged.problems);
      verified.push(...judged.verified);
    }

    await box.run('/bin/sh', ['-c', survivorShellScript(beatFile)], { cwd: box.work, timeoutMs, signal: new AbortController().signal });
    await new Promise((resolve) => setTimeout(resolve, options.settleMs ?? 400));
    const first = await sizeOf(beatFile);
    await new Promise((resolve) => setTimeout(resolve, 800));
    const second = await sizeOf(beatFile);
    if (first === 0) evidence.push('No background process ran in the box, so whether one could outlive it was not tested.');
    // The script exits as soon as the background process has written once. Many writes mean it kept going after the
    // script was done, and what waited for it was not the box ending it.
    else if (second > first || first >= SURVIVOR_BEATS) evidence.push('A process the box started kept running after the box ended.');
    if (await exists(escapeFile)) evidence.push('The box created a file outside its own folder.');
    const proof = await readFile(proofFile, 'utf8').catch(() => '');
    const expected = createHash('sha256').update(`${sinks.nonce}:${salt}`).digest('hex');
    if (proof !== expected) evidence.push('The canary did not run in the box (its proof file is missing or wrong), so nothing was tested.');
  } finally {
    await rm(nonceFile, { force: true });
    await rm(escapeFile, { force: true });
    await rm(proofFile, { force: true });
    await rm(beatFile, { force: true }).catch(() => undefined);
  }

  const output = canary?.stdout.toString('utf8') ?? '';
  const hits = sinks.hits.slice(before);
  const selfReported = output.split(/\r?\n/).filter((line) => /-ok\b/.test(line));
  const attempts = Number(/attempts=(\d+)/.exec(output)?.[1] ?? 0);
  for (const hit of hits) evidence.push(`A ${hit.protocol.toUpperCase()} connection from the box reached this machine (from ${hit.remote}).`);
  for (const line of selfReported) evidence.push(`The box reported: ${line}`);
  if (attempts === 0) evidence.push(`The canary made no network attempts, so the network was not tested. It printed: ${JSON.stringify(output.slice(0, 300))} ${JSON.stringify(canary?.stderr.toString('utf8').slice(0, 300) ?? '')}`);
  const real = evidence.length === 0;
  // A layer counts only if the box said it applied it AND its probe held; on macOS the profile is the layer, and the
  // behaviour checks above are its probes.
  const claimed = new Set(box.layers.applied);
  const verifiedLayers = real ? [...(box.kind === 'macos' ? ['seatbelt'] : []), ...verified].filter((layer) => claimed.has(layer)) : [];
  return { kind: box.kind, real, evidence, hits, selfReported, attempts, layers: box.layers, verifiedLayers, unchecked: box.kind === 'linux' ? UNCHECKED_LINUX : UNCHECKED_MACOS };
}

/** The tier a verified native box earns: tier 3 (section 8.1). Anything unverified is no boundary. */
export const osTierOf = (report: OsTierReport): number => (report.real ? 3 : 2);

/** What a person is told about a box: its tier, and every layer it has or lacks. */
export function describeOsTier(report: OsTierReport): string {
  const have = report.verifiedLayers.length === 0 ? 'none verified' : report.verifiedLayers.join(', ');
  const lacks = report.layers.missing.map((entry) => `${entry.layer} (${entry.reason})`);
  return `${report.kind} box, tier ${osTierOf(report)}; layers verified: ${have}${lacks.length === 0 ? '' : `; not applied: ${lacks.join('; ')}`}`;
}
