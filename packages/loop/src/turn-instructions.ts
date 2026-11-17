import type { SessionEvent } from '@hn/core';
import { deriveSurface } from '@hn/session';
import type { LiveLog, LoopConfig, ToolCallRequest } from './types.ts';

/** File tools whose paths can bring a folder's `AGENTS.md` into the chain. `cd` in bash does not. */
const REFRESHING_TOOLS = new Set(['read_file', 'write_file', 'edit_file']);

/** The frame a chain produces. The loop only appends it; the chain decides what it says. */
export interface InstructionFrameLike {
  readonly text: string;
  readonly origin: SessionEvent['origin'];
  readonly digest: string;
}

/** What the loop needs from the instruction chain. */
export interface InstructionHooks {
  snapshot(): Promise<InstructionFrameLike>;
  touched(paths: readonly string[]): Promise<InstructionFrameLike | null>;
}

export function isInstructionRow(row: SessionEvent): boolean {
  return row.data['instructions'] === true;
}

/** The pinned snapshot the model sees now, if any. */
function currentSnapshot(events: readonly SessionEvent[]): SessionEvent | undefined {
  return deriveSurface(events).find((row) => isInstructionRow(row) && row.data['pinned'] === true);
}

function appendSnapshot(log: LiveLog, frame: InstructionFrameLike, replacing: SessionEvent | undefined): void {
  const data: Record<string, unknown> = { text: frame.text, instructions: true, pinned: true, digest: frame.digest };
  if (replacing !== undefined) {
    data['surfaceOp'] = { op: 'replace', startSeq: replacing.seq, endSeq: replacing.seq, shadowedSeqs: [replacing.seq] };
  }
  log.append('user/message', data, frame.origin);
}

/**
 * Before the first turn of this process: one pinned snapshot after the cached prefix. On a resume the
 * logged one stays unless the files changed while the session was closed, and then the fresh one replaces it.
 */
export async function ensureSnapshot(config: LoopConfig, log: LiveLog): Promise<void> {
  if (config.instructions === undefined) return;
  const frame = await config.instructions.snapshot();
  const existing = currentSnapshot(log.events);
  if (existing !== undefined && existing.data['digest'] === frame.digest) return;
  appendSnapshot(log, frame, existing);
}

/** After a fold the deltas may be gone, so the whole chain is sent again, in place of the old snapshot. */
export async function reemitSnapshot(config: LoopConfig, log: LiveLog): Promise<void> {
  if (config.instructions === undefined) return;
  appendSnapshot(log, await config.instructions.snapshot(), currentSnapshot(log.events));
}

/** After a tool round: a delta row when a file tool brought new, changed or removed instructions. */
export async function refreshAfterTools(
  config: LoopConfig,
  log: LiveLog,
  calls: readonly ToolCallRequest[],
): Promise<void> {
  if (config.instructions === undefined) return;
  const paths = calls.flatMap((call) => {
    if (!REFRESHING_TOOLS.has(call.name)) return [];
    const path = (call.args as { path?: unknown } | null)?.path;
    return typeof path === 'string' && path !== '' ? [path] : [];
  });
  if (paths.length === 0) return;
  const frame = await config.instructions.touched(paths);
  if (frame !== null) {
    log.append('user/message', { text: frame.text, instructions: true, digest: frame.digest }, frame.origin);
  }
}
