import { createHash } from 'node:crypto';
import type { Origin } from '@hn/core';
import type { HarnessExecResult } from './harness-exec.ts';

/** At most this many runs of the check per answer, then the answer goes through with the failure stated. */
export const MAX_VERIFY_RUNS = 3;
const MAX_FEEDBACK_CHARS = 4_000;
/** Rounds that can change the project. A turn that only read and answered is never held for a check. */
const CHANGING_TOOLS = new Set(['write_file', 'edit_file', 'apply_patch', 'bash', 'pwsh', 'terminal_send']);

export interface CheckCommand {
  readonly command: string;
  /** The files that define what the command runs, by hash: an approval dies when one of them changes. */
  readonly scripts: Readonly<Record<string, string>>;
  /** Where the command came from, for the user: `package.json`, `Cargo.toml`, or the configuration. */
  readonly source: string;
}

/** Reads a project file by its path relative to the root, through the safe reader, or null when absent. */
export type ProjectReader = (relativePath: string) => Promise<Buffer | null>;

const hash = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

async function runnerFor(read: ProjectReader): Promise<string> {
  if ((await read('pnpm-lock.yaml')) !== null) return 'pnpm';
  if ((await read('yarn.lock')) !== null) return 'yarn';
  if ((await read('bun.lockb')) !== null) return 'bun';
  return 'npm';
}

async function fromPackageJson(read: ProjectReader): Promise<CheckCommand | null> {
  const bytes = await read('package.json');
  if (bytes === null) return null;
  let test: unknown;
  try {
    test = (JSON.parse(bytes.toString('utf8')) as { scripts?: Record<string, unknown> }).scripts?.['test'];
  } catch {
    return null;
  }
  // npm's placeholder fails on purpose; it is not a check.
  if (typeof test !== 'string' || test.trim() === '' || /no test specified/i.test(test)) return null;
  return { command: `${await runnerFor(read)} test`, scripts: { 'package.json': hash(bytes) }, source: 'package.json' };
}

async function fromMarker(
  read: ProjectReader,
  file: string,
  command: string,
  applies?: (text: string) => boolean,
): Promise<CheckCommand | null> {
  const bytes = await read(file);
  if (bytes === null || (applies !== undefined && !applies(bytes.toString('utf8')))) return null;
  return { command, scripts: { [file]: hash(bytes) }, source: file };
}

/**
 * The project's own check: `package.json` test script, `cargo test`, `go test ./...`, or pytest. The first that
 * applies wins. Each comes with the hash of the file that defines it.
 */
export async function detectCheck(read: ProjectReader): Promise<CheckCommand | null> {
  return (
    (await fromPackageJson(read)) ??
    (await fromMarker(read, 'Cargo.toml', 'cargo test')) ??
    (await fromMarker(read, 'go.mod', 'go test ./...')) ??
    (await fromMarker(read, 'pytest.ini', 'python -m pytest -q')) ??
    (await fromMarker(read, 'pyproject.toml', 'python -m pytest -q', (text) => /pytest/.test(text)))
  );
}

export type StopVerdict =
  | { readonly kind: 'accept'; readonly note?: string }
  | { readonly kind: 'retry'; readonly text: string; readonly origin: Origin };

export interface StopVerifierOptions {
  /** Finds the check afresh before every run, so the hash is of the file as it is now. Null means none is known. */
  readonly find: () => Promise<CheckCommand | null>;
  /** A gated `HarnessExec` run with purpose `verify`. */
  readonly run: (check: CheckCommand, signal: AbortSignal) => Promise<HarnessExecResult>;
}

/**
 * Verify-on-stop: when the model says it is done after changing something, the project's check runs. A failure
 * goes back to the model with the output and the answer waits; three failures and the answer goes through, with
 * the failure stated rather than hidden. Done means the check passed, not that the model said so.
 */
export class StopVerifier {
  readonly #options: StopVerifierOptions;
  #dirty = false;
  #runs = 0;

  constructor(options: StopVerifierOptions) {
    this.#options = options;
  }

  noteRound(toolNames: readonly string[]): void {
    if (toolNames.some((name) => CHANGING_TOOLS.has(name))) this.#dirty = true;
  }

  async check(signal: AbortSignal): Promise<StopVerdict> {
    if (!this.#dirty) return { kind: 'accept' };
    const check = await this.#options.find();
    if (check === null) return this.#settle(null);
    this.#runs += 1;
    const result = await this.#options.run(check, signal);
    const named = `The check \`${check.command}\``;
    if (result.ok) return this.#settle(`${named} passed.`);
    if (result.code === null) return this.#settle(`${named} did not run: ${(result.reason ?? 'refused').replace(/\.+$/, '')}. The answer is not verified.`);
    if (this.#runs >= MAX_VERIFY_RUNS) return this.#settle(`${named} still fails after ${this.#runs} runs. The answer is not verified.`);
    const output = result.output.length > MAX_FEEDBACK_CHARS ? result.output.slice(-MAX_FEEDBACK_CHARS) : result.output;
    const text = [
      `Before your answer goes to the user, the project's check ran: \`${check.command}\` (from ${check.source}), run ${this.#runs} of ${MAX_VERIFY_RUNS}.`,
      `It failed: ${result.reason ?? ''}`,
      output.trim() === '' ? '(no output)' : output.trimEnd(),
      'Your answer is on hold. Fix the problem, then answer again.',
    ].join('\n');
    return { kind: 'retry', text, origin: 'tool-output' };
  }

  #settle(note: string | null): StopVerdict {
    this.#dirty = false;
    this.#runs = 0;
    return note === null ? { kind: 'accept' } : { kind: 'accept', note };
  }
}
