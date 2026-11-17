import type { EventType, Origin } from '@hn/core';
import type { SubagentManager } from '@hn/delegate';
import { ScheduleStore, createRalphTool, createScheduleTools, schedulesFile, type RalphCheck } from '@hn/orchestrate';
import { scanThreat } from '@hn/security';
import type { HarnessExec, ToolDefinition } from '@hn/tools';

export interface RootToolsSetup {
  readonly manager: SubagentManager;
  readonly exec: HarnessExec;
  /** True once the session has seen untrusted data. */
  readonly tainted: () => boolean;
  readonly worst: () => Origin;
  readonly home: string;
  readonly logKey: Buffer;
  readonly workdir: string;
  readonly sessionId: string;
  /** Null when a person approves each call; otherwise this session's own allowlist, the most a schedule made here may allow. */
  readonly allowCeiling: () => readonly string[] | null;
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  readonly route: { readonly model?: string; readonly baseUrl?: string; readonly window?: number };
}

/** The strict scan as one reason, or null when clean. A scan that times out or fails is a refusal. */
export async function strictProblem(text: string): Promise<string | null> {
  const verdict = await scanThreat(text, 'strict');
  if (verdict.clean) return null;
  return verdict.reason ?? (verdict.findings.map((finding) => finding.label).join('; ') || 'it did not pass the scan');
}

/** A gated `HarnessExec` run as a check: refused by the gate means it never ran, which is never a pass. */
export async function gatedCheck(exec: HarnessExec, command: string, signal: AbortSignal): Promise<RalphCheck> {
  const result = await exec.run({ purpose: 'verify', command }, signal);
  const ran = result.ok || result.code !== null || result.output !== '';
  return { ran, passed: result.ok, output: result.output, ...(result.reason === undefined ? {} : { reason: result.reason }) };
}

/** Tools only a root session has (children never get them): `ralph` and the `schedule_*` tools. */
export function createRootTools(setup: RootToolsSetup): ToolDefinition[] {
  const ralph = createRalphTool({
    runLap: async (prompt, signal) => {
      const result = await setup.manager.single({ agent: 'worker', task: prompt }, { start: 'spawn' }, signal).catch((error: unknown) => ({ content: error instanceof Error ? error.message : String(error), ok: false }));
      return { end: result.ok ? 'done' : 'failed', text: result.content, tokens: 0 };
    },
    runCheck: (command, signal) => gatedCheck(setup.exec, command, signal),
    tainted: setup.tainted,
    scan: strictProblem,
  });
  const schedules = createScheduleTools({
    store: new ScheduleStore(schedulesFile(setup.home), setup.logKey),
    workdir: setup.workdir,
    sessionId: setup.sessionId,
    tainted: setup.tainted,
    worst: setup.worst,
    allowCeiling: setup.allowCeiling,
    scan: strictProblem,
    record: setup.record,
    route: setup.route,
  });
  return [ralph, ...schedules];
}
