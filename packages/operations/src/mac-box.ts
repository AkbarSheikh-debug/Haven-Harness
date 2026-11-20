import { existsSync, realpathSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { HnError } from '@hn/core';
import { seatbeltRun, type OsBoxPaths, type SeatbeltOptions } from './os-boxes.ts';
import { PosixBox, type BoxLayers } from './posix-box.ts';
import type { ProcessSignal } from './processes.ts';

/**
 * The macOS native box: every command is one `sandbox-exec` with a deny-by-default Seatbelt profile. Apple has marked
 * `sandbox-exec` deprecated, but it still works, and nothing here is claimed until the outside-in check passes on the
 * machine it runs on. A box that cannot start is a finding that is reported, not hidden.
 *
 * Seatbelt cannot clear the environment or put the box in a process tree of its own, so this class does both from
 * outside: the sandbox is started with exactly the box's environment, in its own process group, and the group is ended
 * with the command. A process that makes a session of its own (`setsid`) can outlive the command; that is a known limit
 * of this box and is listed with its tier, not left out of it.
 */

export const SANDBOX_EXEC = '/usr/bin/sandbox-exec';

export interface MacBoxOptions {
  readonly boxDir: string;
  /** Extra files or folders the box may read and run programs from (the interpreter that runs the canary). */
  readonly reads?: readonly string[];
  /** Extra Seatbelt rules, for a test of a box that leaks. Never set in production. */
  readonly extraProfile?: string;
  readonly env?: Readonly<Record<string, string>>;
}

export class SeatbeltBox extends PosixBox {
  readonly kind = 'macos';
  readonly #options: MacBoxOptions;

  private constructor(options: MacBoxOptions) {
    super(options.boxDir);
    this.#options = options;
  }

  static async open(options: MacBoxOptions): Promise<SeatbeltBox> {
    if (process.platform !== 'darwin') throw new HnError('NO_MAC_BOX', 'The Seatbelt box is macOS only.');
    if (!existsSync(SANDBOX_EXEC)) throw new HnError('NO_MAC_BOX', `${SANDBOX_EXEC} was not found, so there is no macOS box.`);
    if (!isAbsolute(options.boxDir)) throw new HnError('NO_MAC_BOX', 'The box folder must be an absolute path.');
    // Seatbelt matches real paths: /var and /tmp are links into /private, and a rule on the link allows nothing.
    const box = new SeatbeltBox({ ...options, boxDir: realpathSync.native(options.boxDir) });
    await box.makeFolders();
    return box;
  }

  get layers(): BoxLayers {
    return {
      applied: ['seatbelt'],
      missing: [{ layer: 'process-tree', reason: 'macOS has no process namespace: a process that calls setsid can outlive the command that started it.' }],
    };
  }

  get shellPath(): string {
    return '/bin/bash';
  }

  /** The box's whole environment. */
  environment(extra: Readonly<Record<string, string>> = {}): Record<string, string> {
    return { HOME: this.home, TMPDIR: this.tmp, PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HN_BOX: '1', LANG: 'en_US.UTF-8', ...this.#options.env, ...extra };
  }

  get #paths(): OsBoxPaths {
    return { copy: this.work, home: this.home, tmp: this.tmp, cwd: this.work };
  }

  get #seatbelt(): SeatbeltOptions {
    return this.#options.reads === undefined ? {} : { reads: this.#options.reads };
  }

  wrap(program: string, args: readonly string[], cwd: string): { file: string; args: string[] } {
    const run = seatbeltRun({ ...this.#paths, cwd }, program, args, this.#seatbelt);
    // `-p` takes the profile; a test of a leaking box appends a rule to it.
    if (this.#options.extraProfile !== undefined) run[1] = `${run[1]}\n${this.#options.extraProfile}`;
    return { file: SANDBOX_EXEC, args: run };
  }

  /** Seatbelt cannot clear the environment, so the process that starts it carries exactly the box's. */
  protected spawnEnv(): NodeJS.ProcessEnv {
    return this.environment();
  }

  protected signalFor(kind: ProcessSignal): NodeJS.Signals {
    return kind === 'interrupt' ? 'SIGINT' : kind === 'terminate' ? 'SIGTERM' : 'SIGKILL';
  }

  async forget(): Promise<void> {
    return undefined;
  }
}
