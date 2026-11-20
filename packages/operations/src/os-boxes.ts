/**
 * The command lines of the Linux and macOS boxes. Building one claims nothing: like every box, it counts only after the
 * outside-in check passes on that machine (`os-verifier.ts`), and the check says which layers were really there.
 *
 * Linux has three layers, and a kernel may lack the last two:
 * - bubblewrap: every namespace unshared and a mount table that shows the box only its copy, home and temp;
 * - Landlock: a filesystem rule the kernel holds for the process, so a wrong mount is not the only thing in the way;
 * - seccomp: calls a coding agent never needs (`ptrace`, `mount`, `bpf`, ...) fail.
 * Landlock and seccomp are applied by `hn-sandbox confine` just before the command runs.
 */

export interface OsBoxPaths {
  /** The box's copy of the project, the only folder it may write besides its home and temp. */
  readonly copy: string;
  readonly home: string;
  readonly tmp: string;
  readonly cwd: string;
}

/** System folders a Linux box may read. Never `/home`, `/root`, `/run` (sockets) or `/var/run`. */
export const LINUX_READ_ONLY = ['/usr', '/bin', '/sbin', '/lib', '/lib32', '/lib64', '/etc/alternatives', '/etc/ssl', '/etc/ca-certificates'] as const;

/** The few files under /etc a program needs to start and to know who it is. No hosts, no resolver, nothing with a secret. */
export const LINUX_ETC_FILES = ['/etc/passwd', '/etc/group', '/etc/nsswitch.conf', '/etc/ld.so.cache', '/etc/localtime', '/etc/os-release'] as const;

export interface BwrapOptions {
  /**
   * Extra files or folders the box may read and run programs from, read-only: the interpreter that runs the canary, a
   * tool the person named. Never the project, never writable, never `/` or a folder that holds the person's files.
   */
  readonly reads?: readonly string[];
  /** Landlock and seccomp through `hn-sandbox confine`. Without it the box is bubblewrap alone. */
  readonly confine?: { readonly helper: string; readonly landlock: boolean; readonly seccomp: boolean };
}

/** Folders a read grant may never name: they hold the person's files, keys or sockets. */
const FORBIDDEN_READS = new Set(['/', '/home', '/root', '/run', '/var', '/var/run', '/proc', '/sys', '/dev', '/mnt', '/media', '/Users', '/Volumes']);

function checkReads(reads: readonly string[]): void {
  for (const read of reads) {
    const clean = read.length > 1 ? read.replace(/\/+$/, '') : read;
    if (!clean.startsWith('/')) throw new Error(`${read} is not an absolute path.`);
    if (FORBIDDEN_READS.has(clean)) throw new Error(`${read} cannot be given to a box: it holds the person's files or keys.`);
    if (clean.split('/').includes('..')) throw new Error(`${read} contains "..".`);
  }
}

/** Everything before the `--`: namespaces, mounts, environment, working folder. */
function bwrapBase(paths: OsBoxPaths, env: Readonly<Record<string, string>>, options: BwrapOptions): string[] {
  for (const path of [paths.copy, paths.home, paths.tmp, paths.cwd]) {
    if (!path.startsWith('/')) throw new Error(`${path} is not an absolute path.`);
  }
  const reads = options.reads ?? [];
  checkReads(reads);
  const binds = [...LINUX_READ_ONLY, ...LINUX_ETC_FILES, ...reads].flatMap((dir) => ['--ro-bind-try', dir, dir]);
  const helper = options.confine === undefined ? [] : ['--ro-bind', options.confine.helper, options.confine.helper];
  const environment = Object.entries(env).flatMap(([key, value]) => ['--setenv', key, value]);
  return [
    '--unshare-all',
    '--die-with-parent',
    '--new-session',
    '--clearenv',
    // Whatever the user id, the box keeps no capability of its own.
    '--cap-drop', 'ALL',
    ...binds,
    ...helper,
    '--proc', '/proc',
    '--dev', '/dev',
    '--tmpfs', '/run',
    '--bind', paths.copy, paths.copy,
    '--bind', paths.home, paths.home,
    '--bind', paths.tmp, paths.tmp,
    '--setenv', 'HOME', paths.home,
    '--setenv', 'TMPDIR', paths.tmp,
    '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin',
    ...environment,
    '--chdir', paths.cwd,
  ];
}

/** The `hn-sandbox confine` prefix that puts Landlock and seccomp on the command, or nothing for bubblewrap alone. */
export function confinePrefix(paths: OsBoxPaths, options: BwrapOptions): string[] {
  const confine = options.confine;
  if (confine === undefined || (!confine.landlock && !confine.seccomp)) return [];
  const reads = [...LINUX_READ_ONLY, ...LINUX_ETC_FILES, '/proc', ...(options.reads ?? []), confine.helper];
  return [
    confine.helper,
    'confine',
    ...(confine.landlock ? ['--landlock'] : []),
    ...(confine.seccomp ? ['--seccomp'] : []),
    ...(confine.landlock ? [...reads.flatMap((dir) => ['--read', dir]), ...[paths.copy, paths.home, paths.tmp].flatMap((dir) => ['--write', dir])] : []),
    '--',
  ];
}

/** bubblewrap's arguments for one program in the box. */
export function bwrapRun(paths: OsBoxPaths, program: string, args: readonly string[], env: Readonly<Record<string, string>>, options: BwrapOptions = {}): string[] {
  if (!program.startsWith('/')) throw new Error(`${program} is not an absolute path.`);
  return [...bwrapBase(paths, env, options), '--', ...confinePrefix(paths, options), program, ...args];
}

/**
 * bubblewrap: every namespace unshared (so no network, no host PIDs, no IPC), the system read-only, the copy, home and
 * temp writable, nothing else of the host, a fresh session (no terminal injection), dies with its parent.
 */
export function bwrapArgs(paths: OsBoxPaths, shell: string, command: string, env: Readonly<Record<string, string>>, options: BwrapOptions = {}): string[] {
  return bwrapRun(paths, shell, ['-c', command], env, options);
}

/** Quotes a path for a Seatbelt profile. A quote or backslash in it could end the string and add a rule. */
function sbplString(path: string): string {
  if (/["\\\u0000-\u001f]/.test(path)) throw new Error(`${path} cannot be put in a sandbox profile.`);
  return `"${path}"`;
}

/** `/a/b/c` gives `/`, `/a`, `/a/b`: the folders a program looks at (not into) on its way to a path. */
export function ancestorsOf(path: string): string[] {
  const parts = path.split('/').filter((part) => part !== '');
  const out = ['/'];
  for (let i = 1; i < parts.length; i += 1) out.push(`/${parts.slice(0, i).join('/')}`);
  return out;
}

export interface SeatbeltOptions {
  /** Extra files or folders to read and run programs from (the interpreter that runs the canary). Never writable. */
  readonly reads?: readonly string[];
}

/** System folders a macOS box may read. Never `/Users`, `/Volumes`, `/private/var/folders` (other apps' temp) or `/private/var/db`. */
export const MACOS_READ_ONLY = ['/usr', '/bin', '/sbin', '/System', '/Library', '/private/etc', '/dev', '/private/var/db/timezone', '/private/var/db/dyld'] as const;

/**
 * A Seatbelt profile: deny by default, no network at all, read the system and the named files, write only the copy,
 * home and temp. A program may look at the folders on the way to an allowed path (their names, not their contents).
 */
export function seatbeltProfile(paths: OsBoxPaths, options: SeatbeltOptions = {}): string {
  const reads = options.reads ?? [];
  checkReads(reads);
  const writable = [paths.copy, paths.home, paths.tmp].map((path) => `(subpath ${sbplString(path)})`).join(' ');
  const readable = [...MACOS_READ_ONLY, ...reads].map((path) => `(subpath ${sbplString(path)})`).join(' ');
  const onTheWay = [...new Set([...ancestorsOf(paths.copy), ...ancestorsOf(paths.home), ...ancestorsOf(paths.tmp), ...ancestorsOf(paths.cwd), ...reads.flatMap(ancestorsOf)])]
    .map((path) => `(literal ${sbplString(path)})`)
    .join(' ');
  return [
    '(version 1)',
    '(deny default)',
    '(allow process-fork)',
    '(allow process-exec)',
    '(allow signal (target same-sandbox))',
    '(allow sysctl-read)',
    '(allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.system.notification_center"))',
    `(allow file-read-metadata ${onTheWay})`,
    `(allow file-read* ${readable} (literal "/"))`,
    `(allow file-map-executable ${readable})`,
    `(allow file-read* ${writable})`,
    `(allow file-write* ${writable} (literal "/dev/null") (literal "/dev/tty") (literal "/dev/dtracehelper"))`,
    '(deny network*)',
  ].join('\n');
}

/** `sandbox-exec -p <profile> <program> <args>`. */
export function seatbeltRun(paths: OsBoxPaths, program: string, args: readonly string[], options: SeatbeltOptions = {}): string[] {
  if (!program.startsWith('/')) throw new Error(`${program} is not an absolute path.`);
  return ['-p', seatbeltProfile(paths, options), program, ...args];
}

/** `sandbox-exec -p <profile> <shell> -c <command>`. */
export function seatbeltArgs(paths: OsBoxPaths, shell: string, command: string, options: SeatbeltOptions = {}): string[] {
  return seatbeltRun(paths, shell, ['-c', command], options);
}
