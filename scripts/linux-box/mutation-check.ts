// Breaks the Linux box code on purpose, one way at a time, and checks that a test notices each break.
// A mutant that survives is a hole in the tests, not in this script. Run it where the Linux box can run:
//
//   scripts/linux-box/run-in-container.sh node --disable-proto=throw scripts/linux-box/mutation-check.ts
//
// Each mutant edits one source file in the working copy, runs the commands that should catch it, and restores the file.

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

interface Mutant {
  readonly name: string;
  readonly file: string;
  readonly find: string;
  readonly replace: string;
  /** Which kind of test is expected to catch it. */
  readonly via: 'ts' | 'rust';
}

const OS_TESTS = 'node --disable-proto=throw --test --test-timeout=300000 packages/operations/test/os-box.test.ts';
const SESSION = 'node --disable-proto=throw --test --test-timeout=300000 packages/surfaces/test/native-sandbox.test.ts';
const RUST = 'cargo test --manifest-path native/hn-sandbox/Cargo.toml';

const BOXES = 'packages/operations/src/os-boxes.ts';
const VERIFIER = 'packages/operations/src/os-verifier.ts';
const CONFINE = 'native/hn-sandbox/src/confine.rs';
const LINUX = 'packages/operations/src/linux-box.ts';

const mutants: Mutant[] = [
  // A namespace left shared.
  { name: 'bubblewrap no longer unshares every namespace', file: BOXES, find: "'--unshare-all',", replace: "'--unshare-user-try', '--unshare-ipc', '--unshare-uts', '--unshare-net', '--unshare-cgroup-try',", via: 'ts' },
  { name: 'the network namespace is left shared', file: BOXES, find: "'--unshare-all',", replace: "'--unshare-all', '--share-net',", via: 'ts' },
  // A path bound writable that should not be.
  { name: 'the read-only system folders are bound writable', file: BOXES, find: "['--ro-bind-try', dir, dir]", replace: "['--bind-try', dir, dir]", via: 'ts' },
  { name: 'a read grant is bound writable', file: BOXES, find: "const binds = [...LINUX_READ_ONLY, ...LINUX_ETC_FILES, ...reads].flatMap((dir) => ['--ro-bind-try', dir, dir]);", replace: "const binds = [...LINUX_READ_ONLY, ...LINUX_ETC_FILES].flatMap((dir) => ['--ro-bind-try', dir, dir]).concat(reads.flatMap((dir) => ['--bind-try', dir, dir]));", via: 'ts' },
  { name: 'the person\'s home folders become readable', file: BOXES, find: "const FORBIDDEN_READS = new Set(['/', '/home', '/root',", replace: "const FORBIDDEN_READS = new Set(['/',", via: 'ts' },
  { name: 'the box keeps its capabilities', file: BOXES, find: "'--cap-drop', 'ALL',", replace: '', via: 'ts' },
  { name: 'Landlock may write anywhere under the system folders', file: BOXES, find: "...(confine.landlock ? [...reads.flatMap((dir) => ['--read', dir]), ...[paths.copy, paths.home, paths.tmp].flatMap((dir) => ['--write', dir])] : []),", replace: "...(confine.landlock ? [...reads.flatMap((dir) => ['--write', dir]), ...[paths.copy, paths.home, paths.tmp].flatMap((dir) => ['--write', dir])] : []),", via: 'ts' },
  // A filter that lets a denied call through.
  { name: 'the seccomp filter no longer denies ptrace', file: CONFINE, find: '            ("ptrace", libc::SYS_ptrace),\n', replace: '', via: 'rust' },
  { name: 'the seccomp filter returns allow for a listed call', file: CONFINE, find: 'program.push(stmt(BPF_RET_K, RET_ALLOW));\n        program.push(stmt(BPF_RET_K, RET_ERRNO | libc::EPERM as u32));', replace: 'program.push(stmt(BPF_RET_K, RET_ALLOW));\n        program.push(stmt(BPF_RET_K, RET_ALLOW));', via: 'rust' },
  { name: 'seccomp is asked for and never installed', file: CONFINE, find: '        if spec.seccomp {\n            apply_seccomp()?;\n        }', replace: '', via: 'rust' },
  { name: 'Landlock is asked for and never enforced', file: CONFINE, find: 'let restricted = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset as libc::c_long, 0 as libc::c_ulong) };', replace: 'let restricted = 0i64;', via: 'rust' },
  { name: 'Landlock allows every right on the read-only folders', file: CONFINE, find: 'add_path(ruleset, dir, READ_RIGHTS, handled)?;', replace: 'add_path(ruleset, dir, handled, handled)?;', via: 'rust' },
  { name: 'the box applies no Landlock though the kernel has it', file: LINUX, find: 'if (support.landlockAbi >= 1) landlock = true;', replace: 'if (support.landlockAbi >= 1) landlock = false;', via: 'ts' },
  // A claimed tier without the canary.
  { name: 'the verifier calls every box real', file: VERIFIER, find: 'const real = evidence.length === 0;', replace: 'const real = true;', via: 'ts' },
  { name: 'the verifier ignores connections that reached the host', file: VERIFIER, find: 'for (const hit of hits) evidence.push(', replace: 'for (const hit of []) evidence.push(', via: 'ts' },
  { name: 'the verifier ignores a file written outside the box', file: VERIFIER, find: "if (await exists(escapeFile)) evidence.push('The box created a file outside its own folder.');", replace: '', via: 'ts' },
  { name: 'the verifier ignores a process that outlived the box', file: VERIFIER, find: 'else if (second > first || first >= SURVIVOR_BEATS) evidence.push(', replace: 'else if (false) evidence.push(', via: 'ts' },
  { name: 'the verifier does not need the canary to have run', file: VERIFIER, find: 'if (proof !== expected) evidence.push(', replace: 'if (false) evidence.push(', via: 'ts' },
  { name: 'the verifier does not compare namespaces with the host\'s', file: VERIFIER, find: 'facts.get(`ns-${name}`) === host[name]);', replace: 'false);', via: 'ts' },
  { name: 'a box with capabilities passes', file: VERIFIER, find: "if (!/^0+$/.test(capabilities)) problems.push(", replace: 'if (false) problems.push(', via: 'ts' },
  { name: 'a Landlock claim needs no probe', file: VERIFIER, find: "if (facts.get('run-writable') === 'no') verified.push('landlock');", replace: "if (true) verified.push('landlock');", via: 'ts' },
  { name: 'a seccomp claim needs no filter', file: VERIFIER, find: "if (mode !== '2') problems.push(", replace: 'if (false) problems.push(', via: 'ts' },
  { name: 'every verified box is tier 2', file: VERIFIER, find: 'report.real ? 3 : 2', replace: 'report.real ? 2 : 2', via: 'ts' },
  { name: 'a failed box is still tier 3', file: VERIFIER, find: 'report.real ? 3 : 2', replace: 'report.real ? 3 : 3', via: 'ts' },
  { name: 'a session opens a box that failed the check', file: 'packages/surfaces/src/native-sandbox.ts', find: 'if (!report.real) {', replace: 'if (false) {', via: 'ts' },
];

const run = (command: string): { ok: boolean; tail: string } => {
  const result = spawnSync(command, { shell: true, encoding: 'utf8', env: { ...process.env, HN_REQUIRE_BOX: '1' }, maxBuffer: 64 * 1024 * 1024 });
  return { ok: result.status === 0, tail: `${result.stdout}${result.stderr}`.split('\n').filter((line) => /✖|error\[|FAILED|failed|panicked/.test(line)).slice(0, 3).join(' | ') };
};

const survivors: string[] = [];
const only = process.argv[2];
for (const mutant of mutants) {
  if (only !== undefined && !mutant.name.includes(only)) continue;
  const original = readFileSync(mutant.file, 'utf8');
  if (!original.includes(mutant.find)) {
    console.log(`BROKEN  ${mutant.name}: the text to change is not in ${mutant.file}`);
    survivors.push(`${mutant.name} (script out of date)`);
    continue;
  }
  writeFileSync(mutant.file, original.replace(mutant.find, mutant.replace));
  try {
    const commands = mutant.via === 'rust' ? [`${RUST} confine`, `${RUST} --test cli confine`] : [OS_TESTS, SESSION];
    let caught = false;
    let how = '';
    for (const command of commands) {
      const outcome = run(command);
      if (!outcome.ok) {
        caught = true;
        how = outcome.tail;
        break;
      }
    }
    console.log(`${caught ? 'caught  ' : 'SURVIVED'} ${mutant.name}${caught ? `  <- ${how.slice(0, 160)}` : ''}`);
    if (!caught) survivors.push(mutant.name);
  } finally {
    writeFileSync(mutant.file, original);
  }
}
console.log(survivors.length === 0 ? '\nEvery mutant was caught.' : `\n${survivors.length} survived:\n- ${survivors.join('\n- ')}`);
process.exit(survivors.length === 0 ? 0 : 1);
