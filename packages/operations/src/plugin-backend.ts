import { randomBytes, createHash } from 'node:crypto';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { readFile, rm, stat, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { HnError } from '@hn/core';
import { nativeCanary } from './native-verifier.ts';
import { hostAddresses, type NonceSinks, type SinkHit } from './verifier.ts';
import type { ExecOptions, ExecResult } from './types.ts';

/**
 * Backend plugins. A plugin is a program the user names in `~/.hn/backends.json`, run out of
 * process, spoken to over JSON-RPC on its standard streams, and given no keys. Whatever tier it claims is ignored: a
 * plugin earns tier 3, marked asserted (so never yolo), only when the canary run through it reaches nothing here.
 * Otherwise it is tier 2, which is no boundary.
 */

export interface PluginConfig {
  readonly name: string;
  /** Absolute path. A bare name could be found in the project folder. */
  readonly command: string;
  readonly args: readonly string[];
  /** What the plugin says about itself. Recorded, never used. */
  readonly claimedTier?: number;
}

const FIELDS = new Set(['name', 'command', 'args', 'claimedTier']);

/** `~/.hn/backends.json`: `{ "backends": [{ "name", "command", "args", "claimedTier" }] }`. User level only; a project cannot add one. */
export async function loadPluginConfigs(home: string): Promise<PluginConfig[]> {
  const text = await readFile(join(home, 'backends.json'), 'utf8').catch(() => null);
  if (text === null) return [];
  const parsed = JSON.parse(text) as unknown;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new HnError('BAD_BACKENDS', 'backends.json must be an object.');
  const record = parsed as Record<string, unknown>;
  for (const key of Object.keys(record)) if (key !== 'backends') throw new HnError('BAD_BACKENDS', `backends.json has an unknown field "${key}".`);
  if (!Array.isArray(record['backends'])) throw new HnError('BAD_BACKENDS', 'backends.json needs a "backends" list.');
  return record['backends'].map((entry: unknown) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) throw new HnError('BAD_BACKENDS', 'Each backend must be an object.');
    const item = entry as Record<string, unknown>;
    for (const key of Object.keys(item)) if (!FIELDS.has(key)) throw new HnError('BAD_BACKENDS', `A backend has an unknown field "${key}".`);
    if (typeof item['name'] !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(item['name'])) throw new HnError('BAD_BACKENDS', 'A backend name is 1 to 32 lowercase letters, digits or dashes.');
    if (typeof item['command'] !== 'string' || !isAbsolute(item['command'])) throw new HnError('BAD_BACKENDS', `Backend ${item['name']}: "command" must be an absolute path.`);
    const args = item['args'] ?? [];
    if (!Array.isArray(args) || !args.every((arg) => typeof arg === 'string')) throw new HnError('BAD_BACKENDS', `Backend ${item['name']}: "args" must be strings.`);
    return { name: item['name'], command: item['command'], args: args as string[], ...(typeof item['claimedTier'] === 'number' ? { claimedTier: item['claimedTier'] } : {}) };
  });
}

interface Pending {
  resolve(value: unknown): void;
  reject(error: Error): void;
}

const MAX_LINE = 64 * 1024 * 1024;

/** A running plugin. `exec` runs a shell command where the plugin runs things; `run` runs one program there. */
export class PluginBackend {
  readonly config: PluginConfig;
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #pending = new Map<number, Pending>();
  #next = 1;
  #buffer = '';
  #closed = false;

  private constructor(config: PluginConfig, child: ChildProcessWithoutNullStreams) {
    this.config = config;
    this.#child = child;
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => this.#read(chunk));
    child.on('close', () => this.#fail(new Error(`The backend plugin ${config.name} exited.`)));
    child.on('error', (error) => this.#fail(error));
    child.stdin.on('error', () => undefined);
  }

  /** Starts the plugin with an environment that holds no key and no session secret. */
  static start(config: PluginConfig): PluginBackend {
    if (!isAbsolute(config.command)) throw new HnError('BAD_BACKENDS', 'A backend plugin must be started by absolute path.');
    const env: Record<string, string> = {};
    for (const name of ['SystemRoot', 'PATH', 'Path', 'TEMP', 'TMP']) if (process.env[name] !== undefined) env[name] = process.env[name] as string;
    const child = spawn(config.command, [...config.args], { stdio: ['pipe', 'pipe', 'pipe'], env, windowsHide: true });
    return new PluginBackend(config, child);
  }

  #fail(error: Error): void {
    this.#closed = true;
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
  }

  #read(chunk: string): void {
    this.#buffer += chunk;
    if (this.#buffer.length > MAX_LINE) {
      this.#child.kill();
      return;
    }
    let newline = this.#buffer.indexOf('\n');
    while (newline >= 0) {
      const line = this.#buffer.slice(0, newline);
      this.#buffer = this.#buffer.slice(newline + 1);
      newline = this.#buffer.indexOf('\n');
      let message: { id?: unknown; result?: unknown; error?: { message?: unknown } };
      try {
        message = JSON.parse(line) as typeof message;
      } catch {
        continue;
      }
      const pending = typeof message.id === 'number' ? this.#pending.get(message.id) : undefined;
      if (pending === undefined) continue;
      this.#pending.delete(message.id as number);
      if (message.error !== undefined) pending.reject(new Error(String(message.error.message ?? 'The plugin refused.')));
      else pending.resolve(message.result);
    }
  }

  #call(method: string, params: Record<string, unknown>, timeoutMs: number): Promise<unknown> {
    if (this.#closed) return Promise.reject(new Error(`The backend plugin ${this.config.name} is not running.`));
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`The backend plugin ${this.config.name} did not answer in time.`));
      }, timeoutMs + 5_000);
      this.#pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      this.#child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }

  static #result(raw: unknown): ExecResult {
    const value = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
    const bytes = (field: unknown): Buffer => Buffer.from(typeof field === 'string' ? field : '', 'base64');
    return { code: typeof value['code'] === 'number' ? value['code'] : null, stdout: bytes(value['stdout']), stderr: bytes(value['stderr']), timedOut: value['timedOut'] === true, cancelled: false, clipped: false };
  }

  async exec(command: string, options: Omit<ExecOptions, 'signal'>): Promise<ExecResult> {
    return PluginBackend.#result(await this.#call('exec', { command, cwd: options.cwd, timeoutMs: options.timeoutMs, input: options.input ?? '' }, options.timeoutMs));
  }

  async run(program: string, args: readonly string[], options: { cwd: string; timeoutMs: number; input?: string }): Promise<ExecResult> {
    return PluginBackend.#result(await this.#call('run', { program, args, cwd: options.cwd, timeoutMs: options.timeoutMs, input: options.input ?? '' }, options.timeoutMs));
  }

  close(): void {
    this.#closed = true;
    this.#child.kill();
  }
}

/** What a plugin earned. `claimed` is kept only to show it was not used. */
export interface PluginTier {
  readonly tier: 2 | 3;
  readonly asserted: true;
  readonly claimed: number | null;
  readonly evidence: readonly string[];
  readonly hits: readonly SinkHit[];
}

export interface PluginVerifyOptions {
  /** A folder the plugin works in, where the canary leaves its proof. */
  readonly scratch: string;
  /** A folder on this machine the plugin must not reach. */
  readonly outside: string;
  readonly interpreter: string;
  readonly targets?: readonly string[];
}

const exists = (path: string): Promise<boolean> => stat(path).then(() => true, () => false);

/** Runs the canary through the plugin while host listeners watch, and decides the tier from what the host saw. */
export async function verifyPluginBackend(plugin: PluginBackend, sinks: NonceSinks, options: PluginVerifyOptions): Promise<PluginTier> {
  const before = sinks.hits.length;
  const salt = randomBytes(16).toString('hex');
  const nonceFile = join(options.outside, `nonce-${sinks.nonce}.txt`);
  const escapeFile = join(options.outside, `escape-${sinks.nonce}.txt`);
  const proofFile = join(options.scratch, `proof-${sinks.nonce}`);
  await writeFile(nonceFile, `secret ${sinks.nonce}`);
  const evidence: string[] = [];
  let output = '';
  try {
    const script = nativeCanary({ nonce: sinks.nonce, salt, tcpPort: sinks.tcpPort, udpPort: sinks.udpPort, targets: options.targets ?? hostAddresses(), nonceFile, escapeFile, proofFile });
    const result = await plugin.run(options.interpreter, ['-'], { cwd: options.scratch, timeoutMs: 60_000, input: script }).catch((error: unknown) => {
      evidence.push(`The plugin did not run the canary: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    });
    output = result?.stdout.toString('utf8') ?? '';
    await new Promise((resolve) => setTimeout(resolve, 400));
    if (await exists(escapeFile)) evidence.push('The plugin created a file outside the folder it works in.');
    const proof = await readFile(proofFile, 'utf8').catch(() => '');
    if (proof !== createHash('sha256').update(`${sinks.nonce}:${salt}`).digest('hex')) evidence.push('The canary did not run through the plugin (its proof is missing or wrong), so nothing was tested.');
  } finally {
    await rm(nonceFile, { force: true });
    await rm(escapeFile, { force: true });
    await rm(proofFile, { force: true });
  }
  const hits = sinks.hits.slice(before);
  for (const hit of hits) evidence.push(`A ${hit.protocol.toUpperCase()} connection through the plugin reached this machine (from ${hit.remote}).`);
  for (const line of output.split(/\r?\n/).filter((text) => /-ok\b/.test(text))) evidence.push(`The plugin's box reported: ${line}`);
  if (!/attempts=[1-9]/.test(output)) evidence.push('The canary made no network attempts through the plugin.');
  return { tier: evidence.length === 0 ? 3 : 2, asserted: true, claimed: plugin.config.claimedTier ?? null, evidence, hits };
}
