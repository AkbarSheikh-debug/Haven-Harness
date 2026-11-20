// Runs the outside-in check on this machine's native box and prints one row of evidence: where it ran, what the kernel
// offers, which layers held and which were not applied. CI appends the row to the job summary, so each OS's result is
// written down by the run that produced it. Exits 1 when the box does not pass, so a failure is the result, not a hidden one.
//
//   node --disable-proto=throw scripts/box-evidence.ts [--json]

import { existsSync, readFileSync } from 'node:fs';
import { mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { release, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  LinuxBox,
  NativeBox,
  NonceSinks,
  SeatbeltBox,
  describeOsTier,
  detectLinuxSupport,
  findHelper,
  loadBoxConfig,
  osTierOf,
  verifyNativeTier,
  verifyOsBoxTier,
} from '../packages/operations/src/index.ts';

const repoRoot = fileURLToPath(new URL('../', import.meta.url));

function whereItRan(): string {
  if (process.env['GITHUB_ACTIONS'] === 'true') return `a GitHub-hosted runner (${process.env['RUNNER_OS'] ?? process.platform} ${process.env['RUNNER_ARCH'] ?? process.arch})`;
  if (process.platform === 'linux' && existsSync('/.dockerenv')) return 'a container on a developer machine';
  return 'a developer machine';
}

function distribution(): string {
  if (process.platform === 'linux') {
    try {
      return /^PRETTY_NAME="?([^"\n]*)"?/m.exec(readFileSync('/etc/os-release', 'utf8'))?.[1] ?? 'Linux';
    } catch {
      return 'Linux';
    }
  }
  return process.platform === 'darwin' ? 'macOS' : 'Windows';
}

interface Row {
  readonly os: string;
  readonly kernel: string;
  readonly ranOn: string;
  readonly real: boolean;
  readonly tier: number;
  readonly verified: readonly string[];
  readonly notApplied: readonly string[];
  readonly summary: string;
  readonly evidence: readonly string[];
}

async function run(): Promise<Row> {
  const base = await realpath(await mkdtemp(join(tmpdir(), 'hn-evidence-')));
  const outside = join(base, 'outside');
  await mkdir(outside, { recursive: true });
  const sinks = await NonceSinks.open();
  const common = { os: distribution(), kernel: release(), ranOn: whereItRan() };
  try {
    const helper = await findHelper({ env: {}, repoRoot });
    if (helper === null) throw new Error('hn-sandbox is not built. Run: pnpm build:sandbox');
    const interpreter = await realpath(process.execPath);
    if (process.platform === 'win32') {
      const box = await NativeBox.open({ helper, boxDir: join(base, 'session'), sessionId: `evidence-${process.pid}`, config: await loadBoxConfig(join(base, 'no-home')) });
      try {
        const report = await verifyNativeTier(box, sinks, { outside, interpreter });
        return { ...common, real: report.real, tier: report.real ? 3 : 2, verified: report.real ? ['AppContainer', 'job object'] : [], notApplied: [], summary: 'Windows AppContainer and job object', evidence: report.evidence };
      } finally {
        await box.forget();
      }
    }
    const box =
      process.platform === 'darwin'
        ? await SeatbeltBox.open({ boxDir: join(base, 'session'), reads: [interpreter] })
        : await LinuxBox.open({ boxDir: join(base, 'session'), support: await detectLinuxSupport({ helper }), helper, reads: [interpreter] });
    const report = await verifyOsBoxTier(box, sinks, { outside, interpreter });
    return { ...common, real: report.real, tier: osTierOf(report), verified: report.verifiedLayers, notApplied: report.layers.missing.map((entry) => `${entry.layer}: ${entry.reason}`), summary: describeOsTier(report), evidence: report.evidence };
  } finally {
    await sinks.close();
    await rm(base, { recursive: true, force: true, maxRetries: 5 });
  }
}

let row: Row;
try {
  row = await run();
} catch (error) {
  row = { os: distribution(), kernel: release(), ranOn: whereItRan(), real: false, tier: 2, verified: [], notApplied: [], summary: 'the box could not be started', evidence: [error instanceof Error ? error.message : String(error)] };
}

if (process.argv.includes('--json')) console.log(JSON.stringify(row));
else {
  console.log('| OS | Kernel | Where it ran | Result | Tier | Layers verified | Not applied |');
  console.log('|---|---|---|---|---|---|---|');
  console.log(`| ${row.os} | ${row.kernel} | ${row.ranOn} | ${row.real ? 'passed' : 'FAILED'} | ${row.tier} | ${row.verified.join(', ') || 'none'} | ${row.notApplied.join('; ').replaceAll('|', '/') || 'none'} |`);
  for (const line of row.evidence) console.log(`\n- ${line}`);
}
// On GitHub a failed check is also an annotation, readable without signing in to see the log.
if (!row.real && process.env['GITHUB_ACTIONS'] === 'true') for (const line of row.evidence) console.error(`::error::${line.replaceAll('\n', ' ')}`);
process.exit(row.real ? 0 : 1);
