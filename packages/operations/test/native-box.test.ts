import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  NativeBox,
  NonceSinks,
  findHelper,
  loadBoxConfig,
  nativeReportProblems,
  shellInvocation,
  survivorScript,
  verifyNativeTier,
  type NativeReport,
  type NativeVerifiable,
  type RunOutcome,
  type RunRequest,
} from '@hn/operations';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const PERFECT: NativeReport = { appContainer: true, capabilities: 0, integrity: 4096, sid: 'S-1-15-2-1', job: { read: true, killOnClose: true, activeProcessLimit: 256, jobMemoryLimit: 1 } };
const signal = new AbortController().signal;

describe('the native box report and shell, on any platform', () => {
  it('accepts only an AppContainer token with no capabilities, low integrity and a job that kills on close', () => {
    assert.deepEqual(nativeReportProblems(PERFECT), []);
    assert.equal(nativeReportProblems(null).length, 1);
    assert.match(nativeReportProblems({ ...PERFECT, capabilities: 1 }).join(), /1 capabilities/);
    assert.match(nativeReportProblems({ ...PERFECT, appContainer: false }).join(), /not in an AppContainer/);
    assert.match(nativeReportProblems({ ...PERFECT, integrity: 8192 }).join(), /above low/);
    assert.match(nativeReportProblems({ ...PERFECT, job: { ...PERFECT.job, killOnClose: false } }).join(), /does not kill/);
  });

  it('sends PowerShell its script as base64, so no character is re-quoted, and refuses a script too long for a command line', () => {
    const { args } = shellInvocation({ kind: 'powershell', path: 'C:\\ps.exe' }, `echo "a'b" $x; exit 3`, "C:\\it's\\work");
    const script = Buffer.from(args.at(-1) as string, 'base64').toString('utf16le');
    assert.ok(script.includes(`echo "a'b" $x; exit 3`));
    assert.ok(script.includes("-Root 'C:\\it''s\\work'"));
    assert.throws(() => shellInvocation({ kind: 'powershell', path: 'C:\\ps.exe' }, 'x'.repeat(20_000), 'C:\\w'), /too long/);
    assert.deepEqual(shellInvocation({ kind: 'posix', path: 'C:\\t\\busybox.exe' }, 'ls', 'C:\\w').args, ['sh', '-c', 'ls']);
  });

  it('starts the background check with no base64 command line, which Microsoft Defender treats as a Trojan', () => {
    const script = survivorScript("C:\\Users\\a b\\it's\\beat-1");
    assert.doesNotMatch(script, /EncodedCommand|FromBase64|-enc\b/i);
    // The path's quote is doubled once for the loop and once more for the quoted string that carries the loop.
    assert.ok(script.includes("it''''s"), 'a quote in the path is not escaped for both layers');
    assert.match(script, /-Command "\$f=''C:\\Users\\a b\\it''''s\\beat-1''; /);
    assert.doesNotMatch(script.slice(script.indexOf('-Command "') + 10).split('"')[0] ?? '', /"/);
  });

  it('takes a POSIX shell only from the user file, pinned by hash', async () => {
    const home = await mkdtemp(join(tmpdir(), 'hn-boxcfg-'));
    try {
      assert.equal((await loadBoxConfig(home)).shell.kind, 'powershell');
      const shell = join(home, 'busybox.exe');
      await writeFile(shell, 'pretend shell');
      const { createHash } = await import('node:crypto');
      const pin = createHash('sha256').update('pretend shell').digest('hex');
      await writeFile(join(home, 'box.json'), JSON.stringify({ shell, sha256: pin }));
      assert.deepEqual((await loadBoxConfig(home)).shell, { kind: 'posix', path: shell });
      await writeFile(shell, 'swapped shell');
      await assert.rejects(loadBoxConfig(home), /does not match its pinned hash/);
      await writeFile(join(home, 'box.json'), JSON.stringify({ shell, sha256: pin, network: true }));
      await assert.rejects(loadBoxConfig(home), /unknown field "network"/);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});

/** Runs the canary straight on the host, with no box at all, and claims a perfect report. */
function unconfined(work: string, tmp: string, report: NativeReport | null = PERFECT): NativeVerifiable {
  return {
    work,
    tmp,
    run: (program: string, args: readonly string[], request: RunRequest) =>
      new Promise<RunOutcome>((resolve) => {
        const child = spawn(program, args, { cwd: request.cwd, stdio: ['pipe', 'pipe', 'pipe'] });
        const out: Buffer[] = [];
        child.stdout.on('data', (chunk: Buffer) => out.push(chunk));
        child.stdin.end(request.input ?? '');
        child.on('close', (code) => resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.alloc(0), timedOut: false, cancelled: false, clipped: false, report }));
      }),
  };
}

describe('the Windows native box, for real', { skip: process.platform === 'win32' ? false : 'Windows only' }, () => {
  let helper: string;
  let base: string;
  let box: NativeBox;
  let outside: string;
  let sinks: NonceSinks;

  before(async () => {
    const found = await findHelper({ env: {}, repoRoot });
    assert.ok(found !== null, 'hn-sandbox is not built. Run: pnpm build:sandbox');
    helper = found;
    base = await realpath(await mkdtemp(join(tmpdir(), 'hn-native-')));
    outside = await realpath(await mkdtemp(join(tmpdir(), 'hn-outside-')));
    box = await NativeBox.open({ helper, boxDir: join(base, 'session'), sessionId: `test-${process.pid}-${Date.now()}`, config: await loadBoxConfig(join(base, 'no-home')) });
    sinks = await NonceSinks.open();
  });

  after(async () => {
    await sinks?.close();
    await box?.forget();
    await rm(base, { recursive: true, force: true, maxRetries: 10 });
    await rm(outside, { recursive: true, force: true });
  });

  it('passes the outside-in check: the token and job are right, nothing reached this machine, nothing outside was touched, nothing outlived it', async () => {
    const report = await verifyNativeTier(box, sinks, { outside, interpreter: process.execPath });
    assert.deepEqual(report.evidence, [], report.evidence.join('\n'));
    assert.equal(report.real, true);
    assert.ok(report.attempts >= 2, `only ${report.attempts} addresses were tried`);
    assert.equal(report.report?.capabilities, 0);
    assert.equal(report.report?.appContainer, true);
    assert.deepEqual(report.hits, []);
  });

  it('fails a "box" that is really the host: connections arrive, the outside file is written, the background process lives on', async () => {
    const report = await verifyNativeTier(unconfined(box.work, box.tmp), sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.ok(report.hits.length > 0, 'no connection reached the host listener');
    assert.ok(report.evidence.some((line) => /outside its own folder/.test(line)));
    assert.ok(report.evidence.some((line) => /kept running/.test(line)), report.evidence.join(' / '));
  });

  it('fails a real box whose token carries a capability, even though nothing escaped', async () => {
    const withCapability: NativeVerifiable = {
      work: box.work,
      tmp: box.tmp,
      run: async (program, args, request) => {
        const outcome = await box.run(program, args, request);
        return { ...outcome, report: outcome.report === null ? null : { ...outcome.report, capabilities: 1 } };
      },
    };
    const report = await verifyNativeTier(withCapability, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.match(report.evidence.join('\n'), /1 capabilities/);
  });

  it('fails a runner that lies: a perfect report and "attempts=9", but the canary never ran', async () => {
    const liar: NativeVerifiable = {
      work: box.work,
      tmp: box.tmp,
      run: async () => ({ code: 0, stdout: Buffer.from('attempts=9\n'), stderr: Buffer.alloc(0), timedOut: false, cancelled: false, clipped: false, report: PERFECT }),
    };
    const report = await verifyNativeTier(liar, sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.match(report.evidence.join('\n'), /canary did not run/);
  });

  /** A runner that makes the first `failures` background probes fail to start, as Windows now and then does, and runs everything else on `inner`. */
  const probeFailing = (inner: NativeVerifiable, failures: number): NativeVerifiable & { failed: () => number } => {
    let failed = 0;
    return {
      work: inner.work,
      tmp: inner.tmp,
      failed: () => failed,
      run: async (program, args, request) => {
        // The background probe is the only PowerShell the check starts, and it reads its script from stdin.
        if (args.includes('-Command') && request.input !== undefined && failed < failures) {
          failed += 1;
          return { code: 1, stdout: Buffer.alloc(0), stderr: Buffer.from('the process could not be created (0xC0000142)'), timedOut: false, cancelled: false, clipped: false, report: null };
        }
        return inner.run(program, args, request);
      },
    };
  };

  it('tries the background check again when it did not start, and then passes a box that is sound', async () => {
    const runner = probeFailing(box, 1);
    const report = await verifyNativeTier(runner, sinks, { outside, interpreter: process.execPath });
    assert.equal(runner.failed(), 1);
    assert.deepEqual(report.evidence, [], report.evidence.join('\n'));
    assert.equal(report.real, true);
  });

  it('fails closed when the background check never starts, and says how many tries and why', async () => {
    const runner = probeFailing(box, 99);
    const report = await verifyNativeTier(runner, sinks, { outside, interpreter: process.execPath });
    assert.equal(runner.failed(), 3);
    assert.equal(report.real, false);
    assert.match(report.evidence.join('\n'), /No background process ran in the box after 3 tries.*exit 1.*0xC0000142/);
  });

  it('still catches a process that outlives the box when the first try of the check did not start', async () => {
    const report = await verifyNativeTier(probeFailing(unconfined(box.work, box.tmp), 1), sinks, { outside, interpreter: process.execPath });
    assert.equal(report.real, false);
    assert.ok(report.evidence.some((line) => /kept running/.test(line)), report.evidence.join(' / '));
  });

  it('runs PowerShell in the copy, passes exit codes through, and gives the box no key from this process', async () => {
    process.env['ANTHROPIC_API_KEY'] = 'sk-ant-should-never-reach-the-box';
    try {
      const wrote = await box.exec("Set-Content -Path made.txt -Value 'from the box'; Get-Content made.txt; \"key=[$env:ANTHROPIC_API_KEY]\"", { cwd: box.work, timeoutMs: 60_000, signal });
      assert.equal(wrote.code, 0, wrote.stderr.toString());
      assert.match(wrote.stdout.toString(), /from the box/);
      assert.match(wrote.stdout.toString(), /key=\[\]/);
      assert.equal((await readFile(join(box.work, 'made.txt'), 'utf8')).trim(), 'from the box');
      assert.equal((await box.exec('exit 7', { cwd: box.work, timeoutMs: 60_000, signal })).code, 7);
    } finally {
      delete process.env['ANTHROPIC_API_KEY'];
    }
  });

  it('cannot read a file of the user outside the box', async () => {
    const secret = join(outside, 'secret.txt');
    await writeFile(secret, 'host secret');
    const result = await box.exec(`Get-Content -LiteralPath '${secret}'`, { cwd: box.work, timeoutMs: 60_000, signal });
    assert.notEqual(result.code, 0);
    assert.doesNotMatch(result.stdout.toString(), /host secret/);
  });

  it('stops everything in the box when a command times out', async () => {
    const started = Date.now();
    const result = await box.exec('Start-Sleep -Seconds 60', { cwd: box.work, timeoutMs: 2_000, signal });
    assert.equal(result.timedOut, true);
    assert.ok(Date.now() - started < 15_000, 'the timeout did not stop the box');
  });
});
