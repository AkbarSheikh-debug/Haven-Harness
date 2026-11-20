import type { LaunchSpec } from './acp-client.ts';

/** What a setting may hold before it is put on a command line: no spaces, quotes, pipes or other shell syntax. */
const SAFE_ARG = /^[A-Za-z0-9_.:/\\@=,+-]+$/;

export interface LaunchSettings {
  /** The `hn` command, from the user's own settings. */
  readonly path: string;
  readonly model: string;
  readonly baseUrl: string;
}

/**
 * How to start `hn acp`. Elsewhere the program is started directly with the arguments as a list, so nothing is parsed
 * by a shell. On Windows `hn` installed by npm is a `.cmd` shim, which only `cmd.exe` can run; then the whole line goes
 * to `cmd.exe` as one string, so every value in it must first match SAFE_ARG, and anything else is refused with a
 * reason rather than quoted and hoped for.
 */
export function resolveLaunch(settings: LaunchSettings, cwd: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): LaunchSpec {
  const args = ['acp', ...(settings.model === '' ? [] : ['--model', settings.model]), ...(settings.baseUrl === '' ? [] : ['--base-url', settings.baseUrl])];
  const command = settings.path === '' ? 'hn' : settings.path;
  if (platform !== 'win32' || /\.exe$/i.test(command)) return { command, args, cwd, env };
  for (const value of args) {
    if (!SAFE_ARG.test(value)) throw new Error(`"${value.slice(0, 60)}" cannot go on a Windows command line safely. Use letters, digits and . : / \\ @ = , + - only in hn.model and hn.baseUrl.`);
  }
  if (/["%^&|<>\r\n]/.test(command)) throw new Error('hn.path has a character that cannot go on a Windows command line safely. Use the folder where hn is, without quotes or symbols.');
  return { command: env['ComSpec'] ?? 'cmd.exe', args: ['/d', '/s', '/c', `"${[`"${command}"`, ...args].join(' ')}"`], cwd, env, verbatim: true };
}
