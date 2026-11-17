import { randomBytes } from 'node:crypto';
import { createSocket, type Socket as UdpSocket } from 'node:dgram';
import { createServer, type Server } from 'node:net';
import { networkInterfaces } from 'node:os';
import type { RuntimeReport } from './container.ts';
import type { ExecOptions, ExecResult } from './types.ts';

/**
 * Tier detection is verified from outside, not claimed. A hostile image can replace `nc` and
 * `wget` with fakes that print "blocked", so the box's own output proves nothing. The verdict
 * comes from two host-side facts: the runtime configuration Docker reports, and listeners on
 * the host that record any connection or packet that arrives from the box.
 */

export interface SinkHit {
  readonly protocol: 'tcp' | 'udp';
  readonly remote: string;
}

/** Host listeners on every address, IPv4 and IPv6. A box with no network cannot reach them. */
export class NonceSinks {
  readonly nonce: string;
  readonly tcpPort: number;
  readonly udpPort: number;
  /** The same array the listeners push to, so a hit is visible the moment it arrives. */
  readonly hits: SinkHit[];
  readonly #tcp: Server;
  readonly #udp: UdpSocket;

  private constructor(nonce: string, hits: SinkHit[], tcp: Server, udp: UdpSocket, tcpPort: number, udpPort: number) {
    this.nonce = nonce;
    this.hits = hits;
    this.#tcp = tcp;
    this.#udp = udp;
    this.tcpPort = tcpPort;
    this.udpPort = udpPort;
  }

  static async open(): Promise<NonceSinks> {
    const nonce = randomBytes(8).toString('hex');
    const hits: SinkHit[] = [];
    // A dual-stack socket on `::` also accepts IPv4, so one listener per protocol covers both families.
    const tcp = createServer((socket) => {
      hits.push({ protocol: 'tcp', remote: socket.remoteAddress ?? 'unknown' });
      socket.on('error', () => undefined);
      socket.destroy();
    });
    await new Promise<void>((resolve, reject) => {
      tcp.once('error', reject);
      tcp.listen({ port: 0, host: '::', ipv6Only: false }, resolve);
    });
    const udp = createSocket({ type: 'udp6', ipv6Only: false });
    udp.on('message', (message, remote) => {
      // A UDP packet only counts when it carries the nonce, so stray network noise is not mistaken for an escape.
      if (message.toString('utf8').includes(nonce)) hits.push({ protocol: 'udp', remote: remote.address });
    });
    await new Promise<void>((resolve, reject) => {
      udp.once('error', reject);
      udp.bind({ port: 0, address: '::', exclusive: true }, resolve);
    });
    const tcpPort = (tcp.address() as { port: number }).port;
    const udpPort = (udp.address() as { port: number }).port;
    return new NonceSinks(nonce, hits, tcp, udp, tcpPort, udpPort);
  }

  async close(): Promise<void> {
    this.#udp.close();
    await new Promise<void>((resolve) => this.#tcp.close(() => resolve()));
  }
}

/** Every address a box might use to reach this machine. Docker's usual gateways are included because a name cannot be resolved without a network. */
export function hostAddresses(): string[] {
  const found = new Set<string>(['172.17.0.1', '192.168.65.254', '192.168.65.2', '10.0.2.2', '127.0.0.1', '::1']);
  for (const list of Object.values(networkInterfaces())) {
    for (const entry of list ?? []) {
      if (entry.family === 'IPv4' || (entry.family === 'IPv6' && !entry.address.startsWith('fe80'))) found.add(entry.address);
    }
  }
  return [...found];
}

/** The canary. It is supplied by the harness and piped in, never read from the image. */
export function canaryScript(sinks: Pick<NonceSinks, 'nonce' | 'tcpPort' | 'udpPort'>, targets: readonly string[]): string {
  const list = targets.filter((target) => /^[0-9a-fA-F:.]+$|^[A-Za-z0-9.-]+$/.test(target)).join(' ');
  return [
    'attempts=0',
    // Every probe runs at once, so a long address list does not take a second per address.
    `for ip in ${list}; do`,
    '  attempts=$((attempts+1))',
    `  ( echo ${sinks.nonce} | nc -w 1 $ip ${sinks.tcpPort} >/dev/null 2>&1 && echo "tcp-ok $ip" ) &`,
    `  ( echo ${sinks.nonce} | nc -u -w 1 $ip ${sinks.udpPort} >/dev/null 2>&1 ) &`,
    `  ( wget -T 1 -q -O- http://$ip:2375/version >/dev/null 2>&1 && echo "docker-api-ok $ip" ) &`,
    'done',
    '( wget -T 1 -q -O- http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1 && echo "metadata-ok" ) &',
    '( wget -T 1 -q -O- http://[fd00:ec2::254]/latest/meta-data/ >/dev/null 2>&1 && echo "metadata6-ok" ) &',
    `( getent hosts ${sinks.nonce}.canary.invalid >/dev/null 2>&1 && echo "dns-ok" ) &`,
    'wait',
    'for s in /var/run/docker.sock /run/docker.sock; do [ -S "$s" ] && echo "docker-socket-present $s"; done',
    'echo "attempts=$attempts"',
  ].join('\n');
}

/** What the verifier needs from a box. `ContainerBox` satisfies it, and so can a test double. */
export interface Verifiable {
  inspect(): Promise<RuntimeReport>;
  exec(command: string, options: ExecOptions): Promise<ExecResult>;
}

export interface TierReport {
  /** True only when Docker reports the right configuration AND nothing reached the host. */
  readonly real: boolean;
  /** What went wrong, in plain words. Empty when `real`. */
  readonly evidence: readonly string[];
  readonly hits: readonly SinkHit[];
  /** Lines the canary printed that claim a success, kept as extra evidence. The box's word is never what clears it. */
  readonly selfReported: readonly string[];
  readonly runtime: RuntimeReport;
  readonly attempts: number;
  /** What this check does not cover, so the limit is stated and not hidden. */
  readonly unchecked: readonly string[];
}

const UNCHECKED = ['DNS egress through a resolver (a host sink needs privileged port 53; the runtime check of network=none covers it)', 'timing channels'];

export interface VerifyOptions {
  readonly targets?: readonly string[];
  /** How long to wait for late packets after the canary finishes. */
  readonly settleMs?: number;
  readonly timeoutMs?: number;
}

/** Runs the canary in the box and reads the verdict from the host. Run it again after any rebuild or backend change. */
export async function verifyTier(box: Verifiable, sinks: NonceSinks, options: VerifyOptions = {}): Promise<TierReport> {
  const before = sinks.hits.length;
  const runtime = await box.inspect();
  const script = canaryScript(sinks, options.targets ?? hostAddresses());
  const encoded = Buffer.from(script, 'utf8').toString('base64');
  const run = await box.exec(`echo ${encoded} | base64 -d | sh`, {
    cwd: '/work',
    timeoutMs: options.timeoutMs ?? 60_000,
    signal: new AbortController().signal,
  });
  await new Promise((resolve) => setTimeout(resolve, options.settleMs ?? 400));

  const output = run.stdout.toString('utf8');
  const hits = sinks.hits.slice(before);
  const selfReported = output.split('\n').filter((line) => /-ok\b|-present\b/.test(line));
  const attempts = Number(/attempts=(\d+)/.exec(output)?.[1] ?? 0);

  const evidence = [...runtime.failures];
  for (const hit of hits) evidence.push(`A ${hit.protocol.toUpperCase()} connection from the box reached this machine (from ${hit.remote}).`);
  for (const line of selfReported) evidence.push(`The box reported: ${line}`);
  if (attempts === 0) evidence.push('The canary did not run, so nothing was tested.');

  return { real: evidence.length === 0, evidence, hits, selfReported, runtime, attempts, unchecked: UNCHECKED };
}

/** The tier a verified box earns. Anything unverified is treated as no boundary at all. */
export const tierOf = (report: TierReport): number => (report.real ? 4 : 2);
