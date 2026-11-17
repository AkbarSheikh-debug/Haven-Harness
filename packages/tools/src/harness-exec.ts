import { randomUUID } from 'node:crypto';
import type { Operations } from '@hn/operations';
import type { Gate } from '@hn/security';

/**
 * Everything the harness starts because of project-influenced data (verify, an LSP server, a
 * `validate:` line, worktree setup, a hook) is a gated call, because the project wrote the command
 * and the scripts it runs. Starting it from harness code does not make it trusted.
 */

export const EXEC_PURPOSES = ['verify', 'lsp', 'validate', 'setup', 'hook'] as const;
export type ExecPurpose = (typeof EXEC_PURPOSES)[number];

export interface HarnessExecRequest {
  readonly purpose: ExecPurpose;
  readonly command: string;
  /** Path to SHA-256 of each script the command runs, so editing one voids the approval. */
  readonly scripts?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
  /** Standard input for the command, such as a hook's JSON payload. */
  readonly input?: string;
}

export interface HarnessExecResult {
  readonly ok: boolean;
  readonly code: number | null;
  readonly output: string;
  /** Why it did not run, or why it failed. Present whenever `ok` is false. */
  readonly reason?: string;
}

export interface HarnessExecOptions {
  readonly gate: Gate;
  readonly ops: Operations;
  readonly workdir: string;
  /** The sandbox tier. Below 3 there is no boundary, so a human must approve every run. */
  readonly tier: number;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_OUTPUT_CHARS = 20_000;

export class HarnessExec {
  readonly #options: HarnessExecOptions;

  constructor(options: HarnessExecOptions) {
    this.#options = options;
  }

  /** The gate's answer alone, for something the caller starts itself and keeps running (a language server). */
  async allow(request: HarnessExecRequest): Promise<{ readonly ok: boolean; readonly reason: string }> {
    const decision = await this.#check(request);
    return decision.kind === 'allowed-once' ? { ok: true, reason: '' } : { ok: false, reason: decision.reason };
  }

  #check(request: HarnessExecRequest): ReturnType<Gate['check']> {
    const { gate, tier } = this.#options;
    return gate.check({
      id: randomUUID(),
      tool: `harness:${request.purpose}`,
      args: { purpose: request.purpose, command: request.command },
      effect: 'execution',
      paths: [],
      command: request.command,
      summary: `${request.purpose}: ${request.command}`,
      target: request.command,
      ...(request.scripts === undefined ? {} : { scripts: request.scripts }),
      // Below tier 3 nothing contains what this runs, so it is never automatic and never remembered.
      requiresHuman: tier < 3,
    });
  }

  async run(request: HarnessExecRequest, signal: AbortSignal): Promise<HarnessExecResult> {
    const { ops, workdir } = this.#options;
    const decision = await this.#check(request);
    if (decision.kind !== 'allowed-once') return { ok: false, code: null, output: '', reason: decision.reason };

    const timeoutMs = request.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const input = request.input === undefined ? {} : { input: request.input };
    const result = await ops.bash.exec(request.command, { cwd: workdir, timeoutMs, signal, ...input });
    const raw = `${result.stdout.toString('utf8')}${result.stderr.length > 0 ? `\n${result.stderr.toString('utf8')}` : ''}`;
    const output = raw.length > MAX_OUTPUT_CHARS ? `${raw.slice(0, MAX_OUTPUT_CHARS / 2)}\n... output cut ...\n${raw.slice(-MAX_OUTPUT_CHARS / 2)}` : raw;
    if (result.cancelled) return { ok: false, code: result.code, output, reason: 'The run was cancelled.' };
    if (result.timedOut) return { ok: false, code: result.code, output, reason: 'The run timed out.' };
    return result.code === 0 ? { ok: true, code: 0, output } : { ok: false, code: result.code, output, reason: `It exited with code ${result.code}.` };
  }
}
