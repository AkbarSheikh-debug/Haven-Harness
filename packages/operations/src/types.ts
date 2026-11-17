import type { ProcessOperations } from './processes.ts';
/** Tools say what. These interfaces say where, so a tool can move machines without changing. */

export interface ReadOperations {
  readFile(path: string): Promise<Buffer>;
  realpath(path: string): Promise<string>;
}

export interface WriteOperations {
  writeFile(path: string, content: Buffer): Promise<void>;
  mkdir(path: string): Promise<void>;
}

export interface ExecOptions {
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
  /** Written to standard input, then closed. Without it the command gets no input at all. */
  readonly input?: string;
}

export interface ExecResult {
  readonly code: number | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  /** True when output passed the capture limit. */
  readonly clipped: boolean;
}

export interface BashOperations {
  exec(command: string, options: ExecOptions): Promise<ExecResult>;
  /**
   * What the shell really is, when it is not bash (the Windows box runs PowerShell). Added to the `bash` tool's
   * description when the session starts, so the model writes commands for the shell it has.
   */
  readonly shell?: string;
}

export interface SearchRequest {
  readonly pattern: string;
  readonly root: string;
  readonly glob?: string;
  readonly ignoreCase?: boolean;
  readonly limit: number;
  readonly excludeGlobs: readonly string[];
}

export interface SearchOperations {
  grep(request: SearchRequest): Promise<string[]>;
  listFiles(request: Omit<SearchRequest, 'pattern' | 'ignoreCase'>): Promise<string[]>;
}

/** Holds tool output too large for the conversation. */
export interface SpillOperations {
  spill(name: string, content: Buffer): Promise<string>;
}

export interface Operations {
  readonly read: ReadOperations;
  readonly write: WriteOperations;
  readonly bash: BashOperations;
  readonly search: SearchOperations;
  readonly spill: SpillOperations;
  /** Jobs and terminals. Absent where a backend cannot keep a process alive; then bash runs to completion. */
  readonly processes?: ProcessOperations;
}
