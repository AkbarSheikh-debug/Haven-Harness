/**
 * Native boxes on Linux and macOS (decision 4): the command lines only. Neither is claimed as a tier by building it:
 * like every box, it counts only after the outside-in check passes on that machine, and that has not been run here.
 * Not built: a Landlock ruleset and a seccomp filter on Linux, which need a helper of their own.
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

/**
 * bubblewrap: every namespace unshared (so no network, no host PIDs, no IPC), the system read-only, the copy, home and
 * temp writable, nothing else of the host, a fresh session (no terminal injection), dies with its parent.
 */
export function bwrapArgs(paths: OsBoxPaths, shell: string, command: string, env: Readonly<Record<string, string>>): string[] {
  for (const path of [paths.copy, paths.home, paths.tmp, paths.cwd, shell]) {
    if (!path.startsWith('/')) throw new Error(`${path} is not an absolute path.`);
  }
  const binds = LINUX_READ_ONLY.flatMap((dir) => ['--ro-bind-try', dir, dir]);
  const environment = Object.entries(env).flatMap(([key, value]) => ['--setenv', key, value]);
  return [
    '--unshare-all',
    '--die-with-parent',
    '--new-session',
    '--clearenv',
    ...binds,
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
    '--',
    shell, '-c', command,
  ];
}

/** Quotes a path for a Seatbelt profile. A quote or backslash in it could end the string and add a rule. */
function sbplString(path: string): string {
  if (/["\\\u0000-\u001f]/.test(path)) throw new Error(`${path} cannot be put in a sandbox profile.`);
  return `"${path}"`;
}

/** A Seatbelt profile: deny by default, no network at all, read the system, write only the copy, home and temp. */
export function seatbeltProfile(paths: OsBoxPaths): string {
  const writable = [paths.copy, paths.home, paths.tmp].map((path) => `(subpath ${sbplString(path)})`).join(' ');
  return [
    '(version 1)',
    '(deny default)',
    '(allow process-fork)',
    '(allow process-exec)',
    '(allow signal (target same-sandbox))',
    '(allow sysctl-read)',
    '(allow mach-lookup (global-name "com.apple.system.logger"))',
    '(allow file-read* (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/System") (subpath "/Library") (subpath "/private/etc") (subpath "/dev") (literal "/") (subpath "/private/var/db/timezone"))',
    `(allow file-read* ${writable})`,
    `(allow file-write* ${writable} (literal "/dev/null") (literal "/dev/tty"))`,
    '(deny network*)',
  ].join('\n');
}

/** `sandbox-exec -p <profile> <shell> -c <command>`. */
export function seatbeltArgs(paths: OsBoxPaths, shell: string, command: string): string[] {
  return ['-p', seatbeltProfile(paths), shell, '-c', command];
}
