import type { Effect, Mode } from './gate.ts';

/** The one tool that leaves plan mode. It always needs a person, so a plan is never approved by the model itself. */
export const EXIT_PLAN_TOOL = 'exit_plan_mode';

export interface ModeFacts {
  readonly mode: Mode;
  readonly tool: string;
  readonly effect: Effect;
  readonly requiresHuman: boolean;
  readonly allow: readonly string[];
  readonly tier: number;
  readonly isShell: boolean;
}

export function modeVerdict(facts: ModeFacts): 'allow' | 'ask' | string {
  const { mode, tool, effect, requiresHuman, allow, tier, isShell } = facts;
  if (tool === EXIT_PLAN_TOOL) {
    // Leaving plan mode is a person's decision in every mode that has one; nothing remembers it.
    return mode === 'plan' ? 'ask' : `${tool} only works in plan mode, and this session is in ${mode} mode.`;
  }
  if (effect === 'observe' && !requiresHuman) return 'allow';
  if (mode === 'plan') {
    return `${tool} changes things, and this session is in plan mode. Read, plan, and call ${EXIT_PLAN_TOOL} with the plan when it is ready.`;
  }
  if (mode === 'read-only') return `${tool} changes things, and this session is in read-only mode.`;
  if (mode === 'dont-ask') {
    if (requiresHuman) return `${tool} needs a human, and this run never asks.`;
    if (effect !== 'reversible' && effect !== 'execution') return `${tool} needs a human, and this run never asks.`;
    // A shell with no boundary around it cannot be allowlisted by name, because a name says nothing about what it runs.
    if (isShell && tier < 3) return `${tool} runs a shell, and an unattended run needs a sandbox (tier 3 or higher) for that. This session has tier ${tier}.`;
    return allow.includes(tool) ? 'allow' : `${tool} is not on the allowlist for this run.`;
  }
  // yolo never asks, except where a human must decide. The hardline floor and the jail still ran above.
  if (mode === 'yolo') return requiresHuman ? 'ask' : 'allow';
  if (mode === 'accept-edits' && effect === 'reversible' && !requiresHuman) return 'allow';
  return 'ask';
}
