import { basename } from 'node:path';
import type { Origin } from '@hn/core';
import { MemoryFile, type ApplyResult, type MemoryOp } from './memory-file.ts';
import { dailyNotePath, type MemoryPaths } from './paths.ts';
import type { MemoryEntry, MemoryScope, Writer } from './record.ts';

/** `notes` is today's daily note, `memory` is MEMORY.md, `user` is USER.md. */
export const MEMORY_TARGETS = ['notes', 'memory', 'user'] as const;
export type MemoryTarget = (typeof MEMORY_TARGETS)[number];

/**
 * Phase 4 decision 3: the user's own words in this turn ask to remember. A fixed list, no model,
 * so nothing the model reads can argue its way past it. A miss costs one card, never a wrong write.
 */
const REMEMBER = /\b(remember|memori[sz]e|don'?t forget|do not forget|keep in mind|note that|save (?:this|that|it)? ?(?:to|in) memory|from now on)\b/i;

export function rememberRequested(userText: string | null): boolean {
  return userText !== null && REMEMBER.test(userText);
}

const SCOPE: Readonly<Record<MemoryTarget, MemoryScope>> = { notes: 'daily', memory: 'project', user: 'user' };

export async function openTarget(paths: MemoryPaths, target: MemoryTarget, now: Date): Promise<MemoryFile> {
  const scope = SCOPE[target];
  const path = target === 'notes' ? dailyNotePath(paths, now) : target === 'memory' ? paths.memory : paths.user;
  return MemoryFile.open({ path, scope, project: target === 'user' ? null : paths.projectKey, now: () => now });
}

export interface MemoryWrite {
  readonly paths: MemoryPaths;
  readonly target: MemoryTarget;
  readonly ops: readonly MemoryOp[];
  readonly who: Writer;
  readonly sourceSession: string | null;
  readonly origin: Origin;
  readonly taint: 'clean' | 'untrusted';
  readonly why: string;
  /** `user-request`, `human:<name>`, or null. A long-term target refuses null. */
  readonly approvedBy: string | null;
  readonly now?: Date;
}

export interface MemoryWriteResult {
  readonly result: ApplyResult;
  readonly file: string;
  /** The `memory/write` log row, written whether the write landed or not, so a refusal is on the record too. */
  readonly record: Readonly<Record<string, unknown>>;
}

/** The one path every memory write takes: the tool, a morning card, background review. */
export async function writeMemory(write: MemoryWrite): Promise<MemoryWriteResult> {
  const now = write.now ?? new Date();
  const file = await openTarget(write.paths, write.target, now);
  const result = await file.apply(write.ops, {
    who: write.who,
    sourceSession: write.sourceSession,
    origin: write.origin,
    taint: write.taint,
    why: write.why,
    approvedBy: write.approvedBy,
  });
  const record = {
    target: write.target,
    file: basename(file.path),
    ops: write.ops.map((op) => ({ ...op })),
    who: write.who,
    origin: write.origin,
    taint: write.taint,
    approvedBy: write.approvedBy,
    ok: result.ok,
    ...(result.ok ? { used: result.used, cap: result.cap } : { reason: result.reason }),
  };
  return { result, file: basename(file.path), record };
}

/** Entries as the model and a person see them: numbered, with where each came from. */
export function listEntries(entries: readonly MemoryEntry[]): string {
  if (entries.length === 0) return '(empty)';
  return entries.map((entry, index) => `${index + 1}. [${entry.origin}] ${entry.text}`).join('\n');
}
