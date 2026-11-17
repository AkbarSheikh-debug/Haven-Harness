import { createHash, randomBytes } from 'node:crypto';
import { readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { nativeReportProblems, powershellPath, type NativeReport, type RunOutcome, type RunRequest } from './native-box.ts';
import { hostAddresses, type NonceSinks, type SinkHit } from './verifier.ts';

/**
 * The outside-in check for the Windows native box. Nothing the box prints clears it. What clears it:
 * - the token and job the helper read back from Windows (AppContainer, no capabilities, low integrity, kill on close);
 * - host listeners on every address that saw no connection or packet from the box;
 * - a nonce file outside the box that the box could not read, and a file outside the box it could not create;
 * - a proof file the box wrote inside itself, which only running the canary can produce, so a runner that skips it fails;
 * - a background process the canary started that stopped writing once the box ended.
 */

export interface NativeVerifiable {
  run(program: string, args: readonly string[], request: RunRequest): Promise<RunOutcome>;
  /** Folders inside the box, granted to it. */
  readonly work: string;
  readonly tmp: string;
}

export interface NativeVerifyOptions {
  /** A folder on this machine outside the box, owned by the host, for the nonce file and the escape check. */
  readonly outside: string;
  /** The canary's interpreter (Node). */
  readonly interpreter: string;
  /** Windows PowerShell, for the survivor check. */
  readonly powershell?: string;
  readonly targets?: readonly string[];
  readonly timeoutMs?: number;
  readonly settleMs?: number;
}

export interface NativeTierReport {
  readonly real: boolean;
  readonly evidence: readonly string[];
  readonly hits: readonly SinkHit[];
  readonly selfReported: readonly string[];
  readonly report: NativeReport | null;
  readonly attempts: number;
  readonly unchecked: readonly string[];
}

const UNCHECKED = [
  'timing channels',
  'RPC and named pipes to Windows services that AppContainers may still reach (brokers); a box can ask a service, it cannot open a socket',
  'reading system folders that Windows opens to every app (Windows, Program Files)',
];

/** The canary: harness code, piped into Node in the box on standard input, never read from the box. */
export function nativeCanary(input: { nonce: string; salt: string; tcpPort: number; udpPort: number; targets: readonly string[]; nonceFile: string; escapeFile: string; proofFile: string }): string {
  const targets = input.targets.filter((target) => /^[0-9a-fA-F:.]+$/.test(target));
  return `'use strict';
const net = require('net'), dgram = require('dgram'), dns = require('dns'), fs = require('fs'), http = require('http'), crypto = require('crypto'), cp = require('child_process');
const nonce = ${JSON.stringify(input.nonce)};
let attempts = 0;
// Written straight to the handle: buffered pipe output can be lost when the process exits on Windows.
const say = (line) => fs.writeSync(1, line + '\\n');
const tries = [];
// No probe may hang the canary: each one settles within two seconds, and the whole run ends within twelve.
const bounded = (work) => Promise.race([new Promise(work), new Promise((done) => setTimeout(done, 2000))]);
setTimeout(() => { say('attempts=' + attempts); process.exit(0); }, 12000).unref();
for (const ip of ${JSON.stringify(targets)}) {
  attempts += 1;
  tries.push(bounded((done) => {
    const s = net.connect({ host: ip, port: ${input.tcpPort} });
    s.on('connect', () => { s.end(nonce); say('tcp-ok ' + ip); done(); });
    s.on('error', () => done());
    s.setTimeout(1200, () => { s.destroy(); done(); });
  }));
  tries.push(bounded((done) => {
    try {
      const u = dgram.createSocket(ip.includes(':') ? 'udp6' : 'udp4');
      u.on('error', () => { try { u.close(); } catch {} done(); });
      u.send(nonce, ${input.udpPort}, ip, () => { try { u.close(); } catch {} done(); });
    } catch { done(); }
  }));
}
tries.push(bounded((done) => dns.lookup(nonce + '.canary.invalid', (e) => { if (!e) say('dns-ok'); done(); })));
tries.push(bounded((done) => dns.lookup('example.com', (e) => { if (!e) say('dns-public-ok'); done(); })));
tries.push(bounded((done) => {
  const r = http.get({ host: '169.254.169.254', path: '/latest/meta-data/', timeout: 1200 }, () => { say('metadata-ok'); r.destroy(); done(); });
  r.on('error', () => done()); r.on('timeout', () => { r.destroy(); done(); });
}));
try { fs.readFileSync(${JSON.stringify(input.nonceFile)}); say('read-outside-ok'); } catch {}
try { fs.writeFileSync(${JSON.stringify(input.escapeFile)}, nonce); say('write-outside-ok'); } catch {}
fs.writeFileSync(${JSON.stringify(input.proofFile)}, crypto.createHash('sha256').update(nonce + ':' + ${JSON.stringify(input.salt)}).digest('hex'));
Promise.all(tries).then(() => setTimeout(() => { say('attempts=' + attempts); process.exit(0); }, 300));
`;
}

/**
 * The survivor check, as a PowerShell script for its own run in the box. It starts a background PowerShell with a plain
 * CreateProcess (`-NoNewWindow`, no job of its own) that writes to `beatFile` for 20 seconds, waits until it has written
 * once, then exits. Only the box's job can stop it. (Node is not used here: libuv puts its children in a job of its own
 * that kills them when Node exits, which would hide whether the box did.)
 */
export function survivorScript(beatFile: string): string {
  // Plain .NET calls only, no cmdlets: found on a GitHub runner, cmdlets may not load in the box at all (a module
  // folder the box cannot read stops auto-loading), and then no background process ran and nothing was tested.
  const loop = `$f='${beatFile.replaceAll("'", "''")}'; $t=[DateTime]::Now; while (([DateTime]::Now - $t).TotalSeconds -lt 20) { [IO.File]::AppendAllText($f, 'b'); [Threading.Thread]::Sleep(100) }`;
  const encoded = Buffer.from(loop, 'utf16le').toString('base64');
  return [
    `$ps = [IO.Path]::Combine($env:SystemRoot, 'System32\\WindowsPowerShell\\v1.0\\powershell.exe')`,
    `$si = [Diagnostics.ProcessStartInfo]::new($ps, '-NoProfile -NonInteractive -EncodedCommand ${encoded}')`,
    // A plain CreateProcess with no job of its own, sharing the console, as Start-Process -NoNewWindow does.
    '$si.UseShellExecute = $false',
    `$si.WorkingDirectory = '${dirname(beatFile).replaceAll("'", "''")}'`,
    '[void][Diagnostics.Process]::Start($si)',
    '$t = [DateTime]::Now',
    `while (-not [IO.File]::Exists('${beatFile.replaceAll("'", "''")}') -and ([DateTime]::Now - $t).TotalSeconds -lt 15) { [Threading.Thread]::Sleep(100) }`,
  ].join('\n');
}

/** Five seconds of heartbeats: far more than a box that ends at once allows. */
const SURVIVOR_BEATS = 50;
const sizeOf = (path: string): Promise<number> => stat(path).then((info) => info.size, () => 0);
const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);

/** Runs the canary in the box and reads the verdict from the host. Run it again whenever the box is made again. */
export async function verifyNativeTier(box: NativeVerifiable, sinks: NonceSinks, options: NativeVerifyOptions): Promise<NativeTierReport> {
  const before = sinks.hits.length;
  const salt = randomBytes(16).toString('hex');
  const nonceFile = join(options.outside, `nonce-${sinks.nonce}.txt`);
  const escapeFile = join(options.outside, `escape-${sinks.nonce}.txt`);
  const proofFile = join(box.tmp, `proof-${sinks.nonce}`);
  const beatFile = join(box.tmp, `beat-${sinks.nonce}`);
  await writeFile(nonceFile, `secret ${sinks.nonce}`);
  const evidence: string[] = [];
  let outcome: RunOutcome | null = null;
  try {
    const script = nativeCanary({ nonce: sinks.nonce, salt, tcpPort: sinks.tcpPort, udpPort: sinks.udpPort, targets: options.targets ?? hostAddresses(), nonceFile, escapeFile, proofFile });
    outcome = await box.run(options.interpreter, ['-'], { cwd: box.work, timeoutMs: options.timeoutMs ?? 60_000, signal: new AbortController().signal, input: script, report: true });
    const survivor = Buffer.from(survivorScript(beatFile), 'utf16le').toString('base64');
    await box.run(options.powershell ?? powershellPath(), ['-NoProfile', '-NonInteractive', '-EncodedCommand', survivor], { cwd: box.work, timeoutMs: options.timeoutMs ?? 60_000, signal: new AbortController().signal });
    await new Promise((resolve) => setTimeout(resolve, options.settleMs ?? 400));
    const first = await sizeOf(beatFile);
    await new Promise((resolve) => setTimeout(resolve, 800));
    const second = await sizeOf(beatFile);
    if (first === 0) evidence.push('No background process ran in the box, so whether one could outlive it was not tested.');
    // The script exits as soon as the background process has written once. Many writes mean it kept going after the
    // script was done, and whatever waited for it (its output pipe) was not the box ending it.
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

  const output = outcome?.stdout.toString('utf8') ?? '';
  const hits = sinks.hits.slice(before);
  const selfReported = output.split(/\r?\n/).filter((line) => /-ok\b/.test(line));
  const attempts = Number(/attempts=(\d+)/.exec(output)?.[1] ?? 0);
  evidence.unshift(...nativeReportProblems(outcome?.report ?? null));
  for (const hit of hits) evidence.push(`A ${hit.protocol.toUpperCase()} connection from the box reached this machine (from ${hit.remote}).`);
  for (const line of selfReported) evidence.push(`The box reported: ${line}`);
  if (attempts === 0) evidence.push(`The canary made no network attempts, so the network was not tested. It printed: ${JSON.stringify(output.slice(0, 300))} ${JSON.stringify(outcome?.stderr.toString('utf8').slice(0, 300) ?? '')}`);
  return { real: evidence.length === 0, evidence, hits, selfReported, report: outcome?.report ?? null, attempts, unchecked: UNCHECKED };
}

/** The tier a verified native box earns: tier 3. Anything unverified is no boundary. */
export const nativeTierOf = (report: NativeTierReport): number => (report.real ? 3 : 2);
