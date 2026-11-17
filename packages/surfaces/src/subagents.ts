import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { projectKey } from '@hn/config';
import { BUILT_IN_ROLES, DelegationRefused, GRANT_TTL_MS, SubagentManager, createChildTools, createSubagentTool, loadRoles, newChannelToken, newNonce, serveChild, signGrant, type ChildRun, type DelegationLimits, type LaunchSpec, type RateGate, type WorkspaceHooks, type ResolvedModel, type Role } from '@hn/delegate';
import type { EventType, SessionEvent } from '@hn/core';
import { runChildAgent, type SafeFiles, type Workspaces } from '@hn/operations';
import { resolveCaps, type KeyStore, type ModelCaps } from '@hn/provider';
import type { Gate, Mode, TrustStore } from '@hn/security';
import { forkSession, lastForkBoundary, parseLog } from '@hn/session';
import type { HookRunner, ToolDefinition } from '@hn/tools';
import { safeInstructionReader, type InstructionApprover } from './instructions.ts';

/** Where a session's children keep their logs: beside the parent's log, never inside another session's. */
export function childrenFolder(sessions: string, workdir: string, parentId: string): string {
  return join(sessions, projectKey(workdir), `${parentId}.children`);
}

export interface ChildArgsInput {
  readonly brief: string;
  readonly model: string;
  readonly baseUrl?: string;
  readonly window?: number;
  readonly tainted: boolean;
}

/**
 * The child's command line. It runs headless and reports one JSON line. Its mode, tools and budgets are not here:
 * they come only from the signed grant on its standard input, so nothing on a command line can widen them. A
 * tainted parent's child starts tainted.
 */
export function childArgs(input: ChildArgsInput): string[] {
  return [
    '-p',
    input.brief,
    '--json',
    '--keys-stdin',
    '--model',
    input.model,
    ...(input.baseUrl === undefined ? [] : ['--base-url', input.baseUrl]),
    ...(input.window === undefined ? [] : ['--window', String(input.window)]),
    ...(input.tainted ? ['--inherit-taint', 'untrusted'] : []),
  ];
}

/**
 * Which model a role runs on: `main` is the parent's, `cheap` the route's cheap tier, anything else a model the policy
 * must allow. A local route serves whatever model it is given, with the window the session was started with.
 */
export function modelResolver(input: { readonly cheap: string; readonly model: string; readonly cli: string; readonly caps: ModelCaps; readonly local: boolean; readonly allowed: (model: string) => boolean }): (role: Role) => ResolvedModel {
  // A child is started with the model exactly as the parent was given it (`ollama/qwen3:14b`), or it would take another route.
  const ollama = input.cli.startsWith('ollama/');
  return (role) => {
    if (role.model === 'main') return { model: input.cli, caps: input.caps };
    if (role.model === 'cheap') return input.cheap === input.model ? { model: input.cli, caps: input.caps } : { model: input.cheap, caps: resolveCaps(input.cheap) };
    if (!input.allowed(role.model)) throw new DelegationRefused(`The policy does not allow the model ${role.model}, which the ${role.name} role names.`);
    return { model: ollama && !role.model.startsWith('ollama/') ? `ollama/${role.model}` : role.model, caps: input.local ? input.caps : resolveCaps(role.model) };
  };
}

/** The newest end of a whole turn, for a fork: the child gets the parent's finished turns, never half of the current one. */
export function lastFinishedTurn(events: readonly SessionEvent[]): number {
  const turnEnd = [...events].reverse().find((event) => event.type === 'turn/end');
  return turnEnd === undefined ? 0 : lastForkBoundary(events, turnEnd.seq);
}

export interface SubagentSetup {
  readonly nested: boolean;
  /** The project: where the parent's log, and so its children's logs, are filed. */
  readonly workdir: string;
  /**
   * Where a child works unless it has a clone: the project, or in a boxed session the box's copy of it, so a child's
   * changes come back through the box's reviewed import like everything else the box wrote.
   */
  readonly cwd?: string;
  readonly sessions: string;
  /** The parent's hn home: a child must use the same log key and sessions folder, whatever its environment says. */
  readonly home: string;
  readonly sessionId: string;
  /** The parent's own log, read for a fork. */
  readonly parentLog: string;
  readonly logKey: Buffer;
  readonly model: string;
  readonly baseUrl?: string;
  readonly window?: number;
  readonly keys: KeyStore;
  readonly gate: Gate;
  readonly rate: RateGate;
  readonly hooks: HookRunner | null;
  readonly roles: readonly Role[];
  readonly tier: number;
  readonly allow: readonly string[];
  readonly resolveModel: (role: Role) => ResolvedModel;
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  readonly events: () => readonly SessionEvent[];
  readonly parentTools: () => readonly string[];
  readonly contextTokens: () => number;
  readonly tainted: () => boolean;
  readonly limits?: Partial<DelegationLimits>;
  /** A background child settled: its framed report, for the parent's next step. */
  readonly notify?: (text: string) => void;
  /** Private clones for parallel writers. Absent in a box, where there is no host repository to clone. */
  readonly workspaces?: Workspaces;
  /** Runs before a writer's work is applied to the project, with the files it changes: the checkpoint. */
  readonly beforeLand?: (files: readonly string[]) => Promise<void>;
  /** Where team members' requests and inbox routes go, once a team exists. */
  readonly teamHub?: { current: { memberRequest(name: string, request: Readonly<Record<string, unknown>>): Promise<unknown>; port(name: string, send: ((message: unknown) => void) | null): void } | null };
}

/** The manager's view of the clones: one per writer, harvested and applied in order, removed afterwards. */
export function workspaceHooks(workspaces: Workspaces, beforeLand?: (files: readonly string[]) => Promise<void>): WorkspaceHooks {
  const bases = new Map<string, string>();
  return {
    check: () => workspaces.check(),
    create: async (childId) => {
      const { path, base } = await workspaces.create(childId);
      bases.set(childId, base);
      return path;
    },
    land: async (childId, summary) => {
      const base = bases.get(childId);
      if (base === undefined) return { ok: false, text: 'Its clone was never made, so nothing was applied.' };
      try {
        const harvest = await workspaces.harvest(childId, base, summary);
        if (harvest === null) return { ok: true, text: 'It changed no files.' };
        await beforeLand?.(harvest.files);
        const landing = await workspaces.land(harvest);
        if (landing.ok) return { ok: true, text: `Its changes were applied to the project: ${landing.files.join(', ')}.` };
        return { ok: false, text: `Its changes conflict with work that was applied first, so they were not applied (${landing.why}). They are kept at ${landing.ref} in this repository.` };
      } catch (error) {
        return { ok: false, text: `Its changes could not be brought back: ${error instanceof Error ? error.message : String(error)}` };
      } finally {
        bases.delete(childId);
        await workspaces.remove(childId).catch(() => undefined);
      }
    },
  };
}

export interface Subagents {
  readonly manager: SubagentManager;
  readonly tools: readonly ToolDefinition[];
  /** The private clones, shared with workflows so their writers land through the same queue. */
  readonly workspaces?: WorkspaceHooks;
}

/**
 * The parent's side of delegation: a manager whose launcher signs a grant, opens the private channel to this
 * session's gate and rate limiter, and starts the child as its own process.
 */
export function createSubagents(setup: SubagentSetup): Subagents {
  const entry = fileURLToPath(new URL('./main.ts', import.meta.url));
  const folder = childrenFolder(setup.sessions, setup.workdir, setup.sessionId);
  const launch = async (spec: LaunchSpec): Promise<ChildRun> => {
    const logPath = join(folder, spec.childId);
    if (spec.fork && !spec.resume) {
      const source = parseLog(await readFile(setup.parentLog), setup.logKey);
      const writer = await forkSession({ source, path: logPath, sessionId: spec.childId, key: setup.logKey, boundarySeq: lastFinishedTurn(source.events) });
      await writer.close();
    }
    const token = newChannelToken();
    const grant = signGrant(
      {
        v: 1,
        parent: setup.sessionId,
        child: spec.childId,
        mode: spec.mode,
        allow: [...spec.allow],
        tools: [...spec.tools],
        maxIterations: spec.maxIterations,
        tokenBudget: spec.tokenBudget,
        role: { name: spec.role.name, hash: spec.role.hash, body: spec.role.body },
        channel: true,
        project: projectKey(setup.workdir),
        ...(spec.team === undefined ? {} : { team: { name: spec.team } }),
        expires: Date.now() + GRANT_TTL_MS,
        nonce: newNonce(),
      },
      setup.logKey,
    );
    const args = childArgs({
      brief: spec.brief,
      model: spec.model,
      ...(setup.baseUrl === undefined ? {} : { baseUrl: setup.baseUrl }),
      ...(setup.window === undefined ? {} : { window: setup.window }),
      tainted: spec.tainted,
    });
    // process.env no longer holds any model key (captured at startup), and HN_PARENT_SESSION names this session.
    const env = { ...process.env, HN_HOME: setup.home, HN_PARENT_SESSION: setup.sessionId };
    const label = `${spec.role.name} ${spec.childId.slice(0, 8)}`;
    const result = await runChildAgent({
      node: process.execPath,
      entry,
      args,
      cwd: spec.workdir ?? setup.cwd ?? setup.workdir,
      env,
      stdin: JSON.stringify({ 'hn-handoff': 1, keys: JSON.parse(setup.keys.toHandoff()) as unknown, grant, channel: token }),
      timeoutMs: 15 * 60_000,
      signal: spec.signal,
      // The Lead's pushes to a member carry this child's token, or the member's end drops them.
      ...(spec.team === undefined ? {} : { onPort: (send: ((message: unknown) => void) | null) => setup.teamHub?.current?.port(spec.team as string, send === null ? null : (message) => send({ ...(message as object), t: token })) }),
      onMessage: serveChild(token, {
        approve: (card) => setup.gate.relay(card, label),
        rate: setup.rate,
        ...(spec.team === undefined
          ? {}
          : {
              team: async (request: Readonly<Record<string, unknown>>) => {
                const hub = setup.teamHub?.current;
                if (hub === null || hub === undefined) throw new Error('There is no team.');
                return hub.memberRequest(spec.team as string, request);
              },
            }),
        onDropped: () => setup.record('sandbox/event', { kind: 'channel-message-dropped', child: spec.childId }),
      }),
    });
    return { ...result, stderr: setup.keys.redact(result.stderr), logPath };
  };
  const hooks = setup.hooks;
  const workspaces = setup.workspaces === undefined ? undefined : workspaceHooks(setup.workspaces, setup.beforeLand);
  const manager = new SubagentManager({
    parentId: setup.sessionId,
    nested: setup.nested,
    roles: setup.roles,
    parentMode: () => setup.gate.mode as Mode,
    parentAllow: setup.allow,
    parentTools: setup.parentTools,
    tier: setup.tier,
    resolveModel: setup.resolveModel,
    launch,
    record: setup.record,
    events: setup.events,
    contextTokens: setup.contextTokens,
    tainted: setup.tainted,
    ...(setup.limits === undefined ? {} : { limits: setup.limits }),
    ...(setup.notify === undefined ? {} : { notify: setup.notify }),
    ...(workspaces === undefined ? {} : { workspaces }),
    childLog: async (childId) => {
      if (!/^[A-Za-z0-9-]{1,64}$/.test(childId)) return null;
      const log = parseLog(await readFile(join(folder, childId)), setup.logKey);
      return log.trust === 'verified' ? log.events : null;
    },
    ...(hooks === null
      ? {}
      : {
          onStart: async (brief: string, signal: AbortSignal) => {
            await hooks.subagentStart(brief, signal);
          },
          onStop: async (report: string, signal: AbortSignal) => {
            await hooks.subagentStop(report, signal);
          },
        }),
  });
  return { manager, tools: [createSubagentTool(manager), ...createChildTools(manager)], ...(workspaces === undefined ? {} : { workspaces }) };
}

/** Roles from the user's and the project's agents folders. A project role nobody approved is offered on a card; without a person it stays out. */
export async function openRoles(options: {
  readonly files: SafeFiles | null;
  readonly hnHome: string;
  readonly projectRoot: string;
  readonly trust: TrustStore;
  readonly approve?: InstructionApprover;
}): Promise<{ readonly roles: readonly Role[]; readonly notes: readonly string[] }> {
  if (options.files === null) return { roles: BUILT_IN_ROLES, notes: [] };
  const roots = {
    user: join(options.hnHome, 'agents'),
    project: join(options.projectRoot, '.hn', 'agents'),
    projectRoot: options.projectRoot,
    reader: safeInstructionReader(options.files),
    trust: options.trust,
  };
  let set = await loadRoles(roots);
  let approved = false;
  const notes: string[] = [];
  for (const file of set.pending) {
    if (options.approve !== undefined && (await options.approve(file))) {
      await options.trust.approve(file.path, file.content);
      approved = true;
    } else notes.push(`Role not loaded until approved (${file.state}): ${file.display}`);
  }
  if (approved) set = await loadRoles(roots);
  for (const notice of set.notices) if (!/until you approve/.test(notice.message)) notes.push(`Role ${notice.file} ${notice.message}.`);
  return { roles: set.roles, notes };
}
