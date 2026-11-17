// Throwaway CI probe: what does Windows PowerShell see inside the native box on a GitHub runner?
import { mkdtemp, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NativeBox, findHelper, loadBoxConfig } from './packages/operations/src/index.ts';

const helper = await findHelper({ env: {}, repoRoot: process.cwd() });
if (helper === null) throw new Error('no helper');
const base = await realpath(await mkdtemp(join(tmpdir(), 'hn-probe-')));
console.log('tmpdir', tmpdir(), 'base', base);
const box = await NativeBox.open({ helper, boxDir: join(base, 'session'), sessionId: `probe-${process.pid}`, config: await loadBoxConfig(join(base, 'no-home')) });
const signal = new AbortController().signal;
const scripts = [
  '$PSVersionTable.PSVersion.ToString(); $ExecutionContext.SessionState.LanguageMode; "PSModulePath=$env:PSModulePath"; "PWD=$PWD"',
  '[Environment]::GetEnvironmentVariable("PSModulePath","Machine"); $PSHOME',
  'Get-Module -ListAvailable -ErrorAction Continue 2>&1 | Select-Object -First 8 | ForEach-Object { "$_" }',
  'Import-Module Microsoft.PowerShell.Utility -Verbose 4>&1 2>&1 | ForEach-Object { "$_" }; "imported"',
  'Start-Sleep -Seconds 1 2>&1 | ForEach-Object { "$_" }; "slept"',
  "Set-Content -Path made.txt -Value 'from the box' 2>&1 | ForEach-Object { \"$_\" }; Get-Content made.txt 2>&1 | ForEach-Object { \"$_\" }",
  'try { Microsoft.PowerShell.Utility\\Start-Sleep -Seconds 1; "qualified ok" } catch { "caught: $($_.Exception.GetType().FullName): $($_.Exception.Message)" }',
  'Get-ChildItem $PSHOME\\Modules -ErrorAction Continue 2>&1 | ForEach-Object { "$_" } | Select-Object -First 5',
  '[System.IO.File]::WriteAllText("direct.txt","x"); "direct write ok"; [System.IO.File]::ReadAllText("direct.txt")',
  'whoami /all 2>&1 | Select-Object -First 30',
];
for (const script of scripts) {
  const result = await box.exec(script, { cwd: box.work, timeoutMs: 60_000, signal });
  console.log(`\n=== ${script}\ncode=${result.code} timedOut=${result.timedOut}\n--- stdout\n${result.stdout.toString()}\n--- stderr\n${result.stderr.toString()}`);
}
await box.forget();
