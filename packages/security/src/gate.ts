import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { HnError, type EventType } from '@hn/core';
import { MAX_CARD_BYTES, PromptLimiter, approvalHash, changeDigest, type ProposedChange } from './approval.ts';
import { analyzeBash, type BashAnalysis } from './bash-policy.ts';
import type { BashParser } from './bash.ts';
import { Jail, JailError } from './jail.ts';
import { deniedCommandReason, hardlineReason, isGitInternal, isSecretPath } from './rules.ts';
import type { TaintTracker } from './taint.ts';
import { hostExecReasons } from './manifest.ts';
import { isControlPath } from './trust.ts';
import { EXIT_PLAN_TOOL, modeVerdict } from './mode-verdict.ts';
import { relayCard } from './relay.ts';
export { EXIT_PLAN_TOOL } from './mode-verdict.ts';

export const MODES = ['read-only', 'plan', 'safe', 'accept-edits', 'smart', 'dont-ask', 'yolo'] as const;
export type Mode = (typeof MODES)[number];

export type Effect = 'observe' | 'reversible' | 'execution' | 'external' | 'irreversible';

/** Only the first kind allows. Everything else, including any failure, stops the call. */
export type Decision =
  | { readonly kind: 'allowed-once' }
  | { readonly kind: 'rejected'; readonly reason: string }
  | { readonly kind: 'cancelled'; readonly reason: string }
  | { readonly kind: 'unavailable'; readonly reason: string };

export interface PathUse {
  readonly path: string;
  readonly write: boolean;
}

export interface GateCall {
  readonly id: string;
  readonly tool: string;
  readonly args: unknown;
  readonly effect: Effect;
  readonly paths: readonly PathUse[];
  readonly command?: string;
  /** The exact action, as the human will see it. */
  readonly summary: string;
  /** The real destination (a path, a host, a command), shown apart from the model's own words. */
  readonly target?: string;
  /** Hashes of scripts this call will run. Editing one after approval voids the approval. */
  readonly scripts?: Readonly<Record<string, string>>;
  /** The caller already knows a human must decide, for example a subprocess started from project data with no sandbox. */
  readonly requiresHuman?: boolean;
  /** Builds the file change this call would make. Called only once every check has passed and a person is about to be asked. */
  readonly preview?: () => Promise<ProposedChange | null>;
}

export interface ApprovalCard {
  readonly approvalId: string;
  readonly tool: string;
  readonly effect: Effect;
  readonly summary: string;
  readonly target?: string;
  readonly byteCount: number;
  /** The file change, for a door that can show a diff (an editor). Absent for calls that change no file. */
  readonly change?: ProposedChange;
  /** Only an exact, reversible edit may be remembered, and never one that needs a human. */
  readonly canRememberForSession: boolean;
}

export type ApprovalAnswer = 'once' | 'session' | 'deny';
export type Approver = (card: ApprovalCard) => Promise<ApprovalAnswer>;
export type Audit = (type: EventType, data: Record<string, unknown>) => void;
/** A second model or rule engine that may wave through small, reversible calls. It can never approve external effects or anything that needs a human. */
export type Guardian = (card: ApprovalCard) => Promise<'allow' | 'deny'>;

/** The order the gate checks in. Each step can only stop a call or pass it on. */
export const STEPS = ['org-policy', 'hardline', 'deny-rules', 'path-jail', 'taint', 'mode', 'remembered', 'guardian-or-human'] as const;
export type Step = (typeof STEPS)[number] | 'allowed' | 'error';

export interface GateOptions {
  readonly mode: string;
  readonly workdir: string;
  readonly jail: Jail;
  readonly audit: Audit;
  readonly approver?: Approver;
  /** Tool names `dont-ask` may run. Nothing else runs, and it never asks. */
  readonly allow?: readonly string[];
  /** Where tools run. A grant for one backend is not a grant for another. */
  readonly backend?: string;
  /** More prompts than this inside the window pause prompting. */
  readonly promptLimit?: { readonly max: number; readonly windowMs: number };
  readonly now?: () => number;
  /** Step 1. Returns a reason to deny. Deny-only: nothing below can override it. */
  readonly policy?: (call: GateCall) => string | null;
  /** Parses `command` for step 2 and 3, and raises the effect. Without it only string rules apply. */
  readonly bash?: BashParser;
  readonly taint?: TaintTracker;
  readonly guardian?: Guardian;
  /** How long a remembered approval lasts. Default 30 minutes. */
  readonly grantTtlMs?: number;
  /** The sandbox tier. Below 3 there is no boundary. Unset means 0. */
  readonly tier?: number;
  /** True when an operator claimed the boundary instead of it being verified from outside. It never counts for yolo. */
  readonly assertedTier?: boolean;
  /** The mode `exit_plan_mode` moves to, chosen at launch and never by the model. Default `safe`. */
  readonly afterPlan?: string;
}


export class UnsupportedModeError extends HnError {
  constructor(mode: string, reason?: string) {
    super('UNSUPPORTED_MODE', reason === undefined ? `Mode "${mode}" is not available. Choose from: ${MODES.join(', ')}.` : `Mode "${mode}" is not available: ${reason}`);
  }
}

/** The mode exists but this session cannot run it safely, for example `yolo` with no verified sandbox. */
export class ModeRefusedError extends UnsupportedModeError {}

/** After this many guardian denials the session stops asking the guardian and a person decides, as in `safe`. */
const GUARDIAN_DENIAL_LIMIT = 3;

const EFFECT_ORDER: readonly Effect[] = ['observe', 'reversible', 'execution', 'external', 'irreversible'];
const worst = (a: Effect, b: Effect): Effect => (EFFECT_ORDER.indexOf(a) >= EFFECT_ORDER.indexOf(b) ? a : b);

interface Verdict {
  readonly decision: Decision;
  readonly step: Step;
  readonly requiresHuman: boolean;
  readonly effect: Effect;
}

const stop = (step: Step, reason: string, effect: Effect, requiresHuman = false): Verdict => ({
  decision: { kind: 'rejected', reason },
  step,
  requiresHuman,
  effect,
});

/** Every tool call passes here, in this order, and each step can only stop it or pass it on. */
export class Gate {
  readonly #options: GateOptions;
  #mode: Mode;
  /** Remembered approvals: grant hash to expiry time. */
  readonly #grants = new Map<string, number>();
  readonly #limiter: PromptLimiter;
  /** Cards are shown one at a time, and a reply answers only the card in front of the human. */
  #queue: Promise<unknown> = Promise.resolve();
  #guardianDenials = 0;

  constructor(options: GateOptions) {
    if (!(MODES as readonly string[]).includes(options.mode)) throw new UnsupportedModeError(options.mode);
    this.#options = options;
    this.#mode = options.mode as Mode;
    Gate.#assertAllowed(this.#mode, options);
    if (options.afterPlan !== undefined) {
      if (!(MODES as readonly string[]).includes(options.afterPlan) || options.afterPlan === 'plan') {
        throw new UnsupportedModeError(options.afterPlan, 'it cannot be the mode after a plan.');
      }
      Gate.#assertAllowed(options.afterPlan as Mode, options);
    }
    const limit = options.promptLimit ?? { max: 20, windowMs: 5 * 60_000 };
    this.#limiter = new PromptLimiter(limit.max, limit.windowMs, options.now);
  }

  /** The same rules apply to a mode chosen at launch and to the mode a plan leads into. */
  static #assertAllowed(mode: Mode, options: GateOptions): void {
    const tier = options.tier ?? 0;
    if (mode === 'yolo' && (tier < 3 || options.assertedTier === true)) {
      throw new ModeRefusedError(
        'yolo',
        options.assertedTier === true
          ? 'it needs a boundary verified from outside, and this one was only claimed by the operator.'
          : `it needs a verified sandbox (tier 3 or higher), and this session has tier ${tier}. Below that there is no boundary, so yolo would run with nothing between the model and your machine.`,
      );
    }
    if (mode === 'smart' && options.guardian === undefined) throw new ModeRefusedError('smart', 'it needs a guardian to review each call, and none is configured.');
  }

  get mode(): Mode {
    return this.#mode;
  }

  /**
   * Called by `exit_plan_mode` after the gate let it through, which in plan mode means a person said yes.
   * The new mode was fixed at launch; the model never chooses it.
   */
  leavePlan(): Mode {
    if (this.#mode !== 'plan') throw new ModeRefusedError(this.#mode, 'the session is not in plan mode.');
    const next = (this.#options.afterPlan ?? 'safe') as Mode;
    this.#mode = next;
    this.#options.audit('mode/change', { from: 'plan', to: next, by: 'human' });
    return next;
  }

  async check(call: GateCall): Promise<Decision> {
    const verdict = await this.#decide(call).catch(
      (error: unknown): Verdict => ({
        decision: {
          kind: 'unavailable',
          reason: `The safety check failed, so the call was stopped: ${error instanceof Error ? error.message : 'unknown error'}`,
        },
        step: 'error',
        requiresHuman: false,
        effect: call.effect,
      }),
    );
    const { decision } = verdict;
    this.#options.audit('audit/decision', {
      callId: call.id,
      tool: call.tool,
      decision: decision.kind,
      step: decision.kind === 'allowed-once' ? 'allowed' : verdict.step,
      effect: verdict.effect,
      requiresHuman: verdict.requiresHuman,
      ...(decision.kind === 'allowed-once' ? {} : { reason: decision.reason }),
    });
    return decision;
  }

  async #decide(call: GateCall): Promise<Verdict> {
    const { bash, taint, policy } = this.#options;
    let effect = call.effect;
    let requiresHuman = call.requiresHuman === true;

    // 1. Org policy: deny-only, cannot be overridden.
    const denied = policy?.(call) ?? null;
    if (denied !== null) return stop('org-policy', `Blocked by policy: ${denied}`, effect);

    // Parse once. A parser that is missing leaves only the string rules, and bash stays at least `execution`.
    let analysis: BashAnalysis | undefined;
    if (call.command !== undefined && bash !== undefined) {
      analysis = analyzeBash(bash, call.command);
      effect = worst(effect, analysis.effect);
      requiresHuman ||= analysis.requiresHuman;
    }

    // 2. Hardline floor.
    if (call.command !== undefined) {
      const hardline = hardlineReason(call.command) ?? analysis?.hardline ?? null;
      if (hardline !== null) return stop('hardline', `Blocked: ${hardline}. No mode allows this.`, effect);
    }

    // 3. Deny rules: secrets, force push, download-into-shell. Control files do not deny, they need a human.
    if (call.command !== undefined) {
      const reason = deniedCommandReason(call.command) ?? analysis?.blocked ?? null;
      if (reason !== null) return stop('deny-rules', `Blocked: ${reason}.`, effect);
    }

    // 4. Path jail, for the declared paths and for every file a shell redirect writes.
    const uses: PathUse[] = [...call.paths, ...(analysis?.writes ?? []).map((target) => ({ path: target, write: true }))];
    const checked = await this.#checkPaths(uses);
    if (checked.problem !== null) return stop('path-jail', checked.problem, effect);
    requiresHuman ||= checked.controlWrite;

    // 6. Taint rule: untrusted data flowing to an external effect.
    if (taint?.requiresHuman(effect) === true) requiresHuman = true;
    // A door that cannot reopen always needs a person, in every mode, yolo included.
    if (effect === 'irreversible') requiresHuman = true;

    // 7. Effect class by mode.
    const verdict = modeVerdict({
      mode: this.#mode,
      tool: call.tool,
      effect,
      requiresHuman,
      allow: this.#options.allow ?? [],
      tier: this.#options.tier ?? 0,
      isShell: call.command !== undefined,
    });
    if (verdict === 'allow') return { decision: { kind: 'allowed-once' }, step: 'allowed', requiresHuman, effect };
    if (verdict !== 'ask') return stop('mode', verdict, effect, requiresHuman);

    // 8. Remembered approvals, scoped and expiring. Never for a call that needs a human.
    const hash = this.#grantHash(call);
    if (!requiresHuman && this.#grantValid(hash)) return { decision: { kind: 'allowed-once' }, step: 'remembered', requiresHuman, effect };

    // 9. Guardian or human. Fails closed.
    return { decision: await this.#askHuman(call, hash, effect, requiresHuman), step: 'guardian-or-human', requiresHuman, effect };
  }

  async #checkPaths(uses: readonly PathUse[]): Promise<{ problem: string | null; controlWrite: boolean }> {
    let controlWrite = false;
    for (const use of uses) {
      if (isSecretPath(use.path)) return { problem: `Blocked: ${use.path} may hold secrets.`, controlWrite };
      let resolved: string;
      try {
        resolved = await this.#options.jail.resolve(use.path);
      } catch (error) {
        if (error instanceof JailError) return { problem: `Blocked: ${error.message}`, controlWrite };
        throw error;
      }
      // Checked again after links are resolved, so a harmless name cannot point at a secret.
      if (isSecretPath(resolved)) return { problem: `Blocked: ${use.path} leads to a file that may hold secrets.`, controlWrite };
      if (use.write && isGitInternal(resolved)) return { problem: `Blocked: ${use.path} is inside .git.`, controlWrite };
      if (use.write) {
        const relative = (this.#options.workdir.includes('\\') ? path.win32 : path.posix).relative(this.#options.workdir, resolved);
        if (isControlPath(relative)) controlWrite = true;
        // Written straight onto the host (below tier 3), a hook, a CI workflow or a build file makes the host run code the next time
        // anything touches it, so a person decides in every mode, accept-edits included. In a box the hand-back decides instead.
        // package.json is left to the hand-back too: whether it matters depends on its scripts, which a path cannot show.
        else if ((this.#options.tier ?? 0) < 3 && !/(^|\/)package\.json$/i.test(relative.replaceAll('\\', '/')) && hostExecReasons(relative).length > 0) controlWrite = true;
      }
    }
    return { problem: null, controlWrite };
  }

  /** Binds a grant to exactly what runs, so it dies as soon as the arguments change. */
  #grantHash(call: GateCall): string {
    return approvalHash({
      tool: call.tool,
      args: call.args,
      workdir: this.#options.workdir,
      backend: this.#options.backend ?? 'local',
      scripts: call.scripts,
    });
  }

  #now(): number {
    return (this.#options.now ?? Date.now)();
  }

  #grantValid(hash: string): boolean {
    const expires = this.#grants.get(hash);
    if (expires === undefined) return false;
    if (expires > this.#now()) return true;
    this.#grants.delete(hash);
    return false;
  }

  /**
   * A child's approval card (decision 2 of Phase 5). Children never ask anyone themselves: the card comes here and is
   * shown to this session's person in the same one-at-a-time queue and under the same prompt limit, labelled with the
   * child. The guardian never decides it, a yes counts once (no grant crosses from parent to child or back), and with
   * nobody here, or in a mode that never asks, the answer is no.
   */
  relay(card: ApprovalCard, from: string): Promise<'once' | 'deny'> {
    const { approver, audit } = this.#options;
    const turn = this.#queue.then(() => relayCard({ approver, audit, neverAsks: this.#mode === 'dont-ask', allowPrompt: () => this.#limiter.allow() }, card, from));
    this.#queue = turn.catch(() => undefined);
    return turn;
  }

  #askHuman(call: GateCall, hash: string, effect: Effect, requiresHuman: boolean): Promise<Decision> {
    const turn = this.#queue.then(() => this.#ask(call, hash, effect, requiresHuman));
    this.#queue = turn.catch(() => undefined);
    return turn;
  }

  async #ask(call: GateCall, hash: string, effect: Effect, requiresHuman: boolean): Promise<Decision> {
    const { approver, guardian, audit } = this.#options;
    // The guardian belongs to `smart`. It never decides external or irreversible calls, never one that needs a human,
    // and below tier 3 there is nothing it may safely wave through. After three denials a person decides, as in `safe`.
    const guardianMayDecide =
      this.#mode === 'smart' &&
      guardian !== undefined &&
      !requiresHuman &&
      (effect === 'reversible' || effect === 'execution') &&
      (this.#options.tier ?? 0) >= 3 &&
      this.#guardianDenials < GUARDIAN_DENIAL_LIMIT;
    if (approver === undefined && !guardianMayDecide) {
      return { kind: 'unavailable', reason: `${call.tool} needs approval, and nobody is here to give it.` };
    }
    const size = Buffer.byteLength(call.summary);
    if (size > MAX_CARD_BYTES) {
      return { kind: 'rejected', reason: `${call.tool} is ${size} bytes, too much for a person to review. Split it into smaller steps.` };
    }
    if (!this.#limiter.allow()) {
      return { kind: 'unavailable', reason: 'Too many approval prompts in a short time, so prompting is paused. Ask the user how to proceed.' };
    }

    const change = call.preview === undefined ? null : await call.preview().catch(() => null);
    const approvalId = randomUUID();
    const canRememberForSession = effect === 'reversible' && !requiresHuman;
    const card: ApprovalCard = {
      approvalId,
      tool: call.tool,
      effect,
      summary: call.summary,
      ...(call.target === undefined ? {} : { target: call.target }),
      ...(change === null ? {} : { change }),
      byteCount: size,
      canRememberForSession,
    };
    audit('approval/asked', { approvalId, callId: call.id, tool: call.tool, summary: call.summary, requiresHuman, ...(change === null ? {} : { changeDigest: changeDigest(change) }) });

    if (guardianMayDecide) {
      const answer = await guardian(card);
      audit('approval/decided', { approvalId, callId: call.id, answer: answer === 'allow' ? 'once' : 'deny', by: 'guardian' });
      if (answer === 'allow') return { kind: 'allowed-once' };
      this.#guardianDenials += 1;
      return { kind: 'rejected', reason: 'The guardian declined. Ask the user what they want instead.' };
    }

    const answer = await (approver as Approver)(card);
    audit('approval/decided', { approvalId, callId: call.id, answer, by: 'human' });
    if (answer === 'deny') return { kind: 'rejected', reason: 'The user said no. Ask what they want instead.' };
    if (answer === 'session' && canRememberForSession) this.#grants.set(hash, this.#now() + (this.#options.grantTtlMs ?? 30 * 60_000));
    return { kind: 'allowed-once' };
  }
}
