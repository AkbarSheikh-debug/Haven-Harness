import type { KeyStore } from '@hn/provider';
import { runHandoff } from './handoff-door.ts';
import { runPreset } from './presets.ts';
import { rewindPoints, runRewind } from './rewind.ts';
import type { CliOptions, OpenSession } from './session-types.ts';

/** The REPL's delegation commands: `/handoff`, `/rewind`, `/agents` and the presets. */
export class DelegationDoor {
  readonly #out: (text: string) => void;
  readonly #ask: (prompt: string) => Promise<string>;
  readonly #session: () => OpenSession | undefined;
  readonly #attach: (session: OpenSession, home: string) => void;
  #setup: { options: CliOptions; keys: KeyStore; home: string } | null = null;

  constructor(out: (text: string) => void, ask: (prompt: string) => Promise<string>, session: () => OpenSession | undefined, attach: (session: OpenSession, home: string) => void) {
    this.#out = out;
    this.#ask = ask;
    this.#session = session;
    this.#attach = attach;
  }

  /** What `/handoff` and `/rewind` need to open the next session the same way this one was opened. */
  setup(options: CliOptions, keys: KeyStore, home: string): void {
    this.#setup = { options, keys, home };
  }

  handles(line: string): boolean {
    return line === '/handoff' || line === '/agents' || line === '/rewind' || line.startsWith('/rewind ');
  }

  async command(line: string): Promise<void> {
    const session = this.#session();
    if (session === undefined) return;
    if (line === '/agents') this.#out(`${session.subagents.describe()}\n`);
    else if (line === '/handoff') await this.#handoff(session);
    else await this.#rewind(session, line);
  }

  /** A preset runs like a turn, beside the line loop, so the person can answer a worker's card meanwhile. */
  preset(session: OpenSession, line: string): Promise<boolean> {
    return runPreset(session, line, this.#out);
  }

  /** `/handoff`: the person decides; a new session opens from the note, and the door moves to it. */
  async #handoff(session: OpenSession): Promise<void> {
    const setup = this.#setup;
    if (setup === null) return;
    const next = await runHandoff(session, setup.options, setup.keys, { ask: this.#ask, out: this.#out, home: setup.home }).catch((error: unknown) => {
      this.#out(`The handoff failed: ${error instanceof Error ? error.message : String(error)}\n`);
      return null;
    });
    if (next === null) return;
    this.#attach(next, setup.home);
    for (const note of next.notes) this.#out(`${note}\n`);
  }

  /** `/rewind` lists the turns; `/rewind <n> [--all]` forks before turn n and restores files, and the door moves to the fork. */
  async #rewind(session: OpenSession, line: string): Promise<void> {
    const setup = this.#setup;
    if (setup === null) return;
    const parts = line.split(/\s+/).slice(1);
    const turn = Number(parts.find((part) => /^\d+$/.test(part)));
    if (!Number.isSafeInteger(turn) || turn < 1) {
      const points = rewindPoints(session.agent.events);
      this.#out(points.length === 0 ? 'There is no turn to go back to yet.\n' : `${points.map((point) => `${point.turn}: ${point.text}`).join('\n')}\nUse /rewind <n> to go back to just before turn n, or /rewind <n> --all to restore every file too.\n`);
      return;
    }
    const next = await runRewind(session, setup.options, setup.keys, { out: this.#out }, turn, parts.includes('--all')).catch((error: unknown) => {
      this.#out(`The rewind failed: ${error instanceof Error ? error.message : String(error)}\n`);
      return null;
    });
    if (next !== null) this.#attach(next, setup.home);
  }
}
