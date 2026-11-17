import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import { SafeFileError, type BashOperations, type SafeFiles } from '@hn/operations';
import type { TrustStore } from '@hn/security';
import {
  DEFAULT_HOOK_TIMEOUT_MS,
  HOOK_EVENTS,
  HookRunner,
  MAX_HOOK_TIMEOUT_MS,
  type HarnessExec,
  type HarnessExecResult,
  type HookEvent,
  type HookSpec,
} from '@hn/tools';
import type { InstructionApprover } from './instructions.ts';

const MAX_BYTES = 64 * 1024;
const MAX_HOOKS = 50;
const HOOK_KEYS = new Set(['name', 'event', 'command', 'tools', 'timeoutMs', 'security']);
const PROJECT_FILE = '.hn/hooks.json';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function parseEntry(entry: unknown, at: string, scope: HookSpec['scope'], bad: (message: string) => never): HookSpec {
  if (!isRecord(entry)) return bad(`${at} must be an object.`);
  for (const key of Object.keys(entry)) if (!HOOK_KEYS.has(key)) return bad(`${at} has an unknown field "${key}".`);
  const { name, event, command, tools, timeoutMs, security } = entry;
  if (typeof name !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(name)) {
    return bad(`${at}.name must be lowercase letters, digits, "_" or "-".`);
  }
  if (typeof event !== 'string' || !(HOOK_EVENTS as readonly string[]).includes(event)) {
    return bad(`${at}.event must be one of ${HOOK_EVENTS.join(', ')}.`);
  }
  if (typeof command !== 'string' || command.trim() === '' || command.length > 2_000) return bad(`${at}.command must be a command line.`);
  if (tools !== undefined && (!Array.isArray(tools) || tools.some((tool) => typeof tool !== 'string'))) {
    return bad(`${at}.tools must be a list of tool names.`);
  }
  const wholeMs = typeof timeoutMs === 'number' && Number.isInteger(timeoutMs) && timeoutMs >= 100 && timeoutMs <= MAX_HOOK_TIMEOUT_MS;
  if (timeoutMs !== undefined && !wholeMs) return bad(`${at}.timeoutMs must be a whole number from 100 to ${MAX_HOOK_TIMEOUT_MS}.`);
  if (security !== undefined && typeof security !== 'boolean') return bad(`${at}.security must be true or false.`);
  return {
    name,
    event: event as HookEvent,
    command,
    tools: tools === undefined ? null : (tools as string[]),
    timeoutMs: (timeoutMs as number | undefined) ?? DEFAULT_HOOK_TIMEOUT_MS,
    security: security === true,
    scope,
  };
}

/** Parses a hooks file strictly: unknown fields, odd names and oversize files are errors, never ignored. */
export function parseHooks(text: string, where: string, scope: HookSpec['scope']): { hooks: HookSpec[]; projectHooks: boolean } {
  const bad = (message: string): never => {
    throw new HnError('HOOKS_CONFIG_INVALID', `${where}: ${message}`);
  };
  if (Buffer.byteLength(text) > MAX_BYTES) return bad(`the file is larger than ${MAX_BYTES} bytes.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return bad('the file is not valid JSON.');
  }
  const allowed = scope === 'user' ? ['hooks', 'projectHooks'] : ['hooks'];
  if (!isRecord(parsed) || Object.keys(parsed).some((key) => !allowed.includes(key)) || !Array.isArray(parsed['hooks'])) {
    return bad(`expected {${allowed.map((key) => `"${key}"`).join(', ')}} and nothing else.`);
  }
  if (parsed['hooks'].length > MAX_HOOKS) return bad(`more than ${MAX_HOOKS} hooks.`);
  const hooks = parsed['hooks'].map((entry: unknown, index) => parseEntry(entry, `hooks[${index}]`, scope, bad));
  const names = hooks.map((hook) => hook.name);
  const twice = names.find((name, index) => names.indexOf(name) !== index);
  if (twice !== undefined) return bad(`the hook name "${twice}" is used twice.`);
  return { hooks, projectHooks: parsed['projectHooks'] === true };
}

async function readUserHooks(home: string): Promise<{ hooks: HookSpec[]; projectHooks: boolean }> {
  try {
    return parseHooks(await readFile(join(home, 'hooks.json'), 'utf8'), 'hooks.json', 'user');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { hooks: [], projectHooks: false };
    throw error;
  }
}

async function readProjectFile(files: SafeFiles, projectRoot: string): Promise<Buffer | null> {
  try {
    return await files.read(projectRoot, join(projectRoot, PROJECT_FILE), MAX_BYTES + 1);
  } catch (error) {
    if (error instanceof SafeFileError) return null;
    throw error;
  }
}

/** A user hook is the user's own program on the user's own machine: it runs on the host shell, not in a box. */
function userExec(hostBash: BashOperations, cwd: string) {
  return async (hook: HookSpec, payload: string, signal: AbortSignal): Promise<HarnessExecResult> => {
    const result = await hostBash.exec(hook.command, { cwd, timeoutMs: hook.timeoutMs, signal, input: payload });
    const stderr = result.stderr.length === 0 ? '' : `\n${result.stderr.toString('utf8')}`;
    const output = `${result.stdout.toString('utf8')}${stderr}`;
    if (result.timedOut) return { ok: false, code: result.code, output, reason: `It timed out after ${hook.timeoutMs} ms.` };
    if (result.cancelled) return { ok: false, code: result.code, output, reason: 'It was cancelled.' };
    if (result.code === 0) return { ok: true, code: 0, output };
    return { ok: false, code: result.code, output, reason: `It exited with code ${result.code}.` };
  };
}

export interface HookOptions {
  readonly home: string;
  readonly projectRoot: string;
  readonly files: SafeFiles | null;
  readonly hostBash: BashOperations;
  readonly hostCwd: string;
  readonly exec: HarnessExec;
  readonly tier: number;
  readonly trust: TrustStore;
  readonly approve?: InstructionApprover;
  readonly sessionId: string;
  readonly cwd: string;
  readonly record: (type: 'hook/invoked' | 'hook/result', data: Record<string, unknown>) => void;
}

/** The project's hooks, only if the user turned them on, the session is boxed, and a person approved the bytes. */
async function projectHooks(options: HookOptions, enabled: boolean, notes: string[]): Promise<{ hooks: HookSpec[]; hash: string }> {
  const none = { hooks: [], hash: '' };
  const bytes = options.files === null ? null : await readProjectFile(options.files, options.projectRoot);
  if (bytes === null) return none;
  if (!enabled) {
    notes.push('Project hooks in .hn/hooks.json are off. Turn them on with "projectHooks": true in your own hooks.json.');
    return none;
  }
  if (options.tier < 3) {
    notes.push(`Project hooks in .hn/hooks.json run only in a sandbox (tier 3 or higher); this session has tier ${options.tier}.`);
    return none;
  }
  const path = join(options.projectRoot, PROJECT_FILE);
  const check = options.trust.check(path, bytes);
  if (check.state !== 'trusted') {
    const file = { path, display: PROJECT_FILE, state: check.state, diff: check.diff ?? null, content: bytes } as const;
    if (options.approve === undefined || !(await options.approve(file))) {
      notes.push('Project hooks in .hn/hooks.json are not loaded until you approve the file.');
      return none;
    }
    await options.trust.approve(path, bytes);
  }
  const hash = createHash('sha256').update(bytes).digest('hex');
  return { hooks: parseHooks(bytes.toString('utf8'), PROJECT_FILE, 'project').hooks, hash };
}

export interface HookSetup {
  readonly runner: HookRunner | null;
  readonly notes: readonly string[];
}

/**
 * Hooks for a session. User hooks come from `<home>/hooks.json`. Project hooks in `.hn/hooks.json` run only when
 * the user's file says `"projectHooks": true`, the session is in a verified box (tier 3 or higher), and a person
 * approved the file's exact bytes; each run is then a gated `HarnessExec` call inside the box.
 */
export async function openHooks(options: HookOptions): Promise<HookSetup> {
  const user = await readUserHooks(options.home);
  const notes: string[] = [];
  const project = await projectHooks(options, user.projectHooks, notes);
  const hooks = [...user.hooks, ...project.hooks];
  if (hooks.length === 0) return { runner: null, notes };
  const forUser = userExec(options.hostBash, options.hostCwd);
  const scripts = { [PROJECT_FILE]: project.hash };
  const runner = new HookRunner({
    hooks,
    sessionId: options.sessionId,
    cwd: options.cwd,
    record: options.record,
    exec: (hook, payload, signal) =>
      hook.scope === 'user'
        ? forUser(hook, payload, signal)
        : options.exec.run({ purpose: 'hook', command: hook.command, timeoutMs: hook.timeoutMs, input: payload, scripts }, signal),
  });
  return { runner, notes };
}
