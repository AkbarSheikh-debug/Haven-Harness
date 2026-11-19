import { createHash } from 'node:crypto';
import { sanitizeForDisplay } from '@hn/core';
import { Redactor, isUntrusted } from '@hn/security';
import type { MemoryPaths } from './paths.ts';
import { pendingProposals, proposalHash, readAnswers, readProposals, recordAnswer, type Proposal } from './proposals.ts';
import { writeMemory } from './write-path.ts';

/** At most three cards per morning (10.8). */
export const MAX_CARDS = 3;

/**
 * The exact bytes a yes would store: the proposal's text as the store will keep it, trimmed and
 * redacted. The card shows these, so it can never show one thing and store another.
 */
export function storedBytes(proposal: Pick<Proposal, 'text'>, redactor = new Redactor()): string {
  return redactor.redact(proposal.text.trim());
}

export const bytesHash = (bytes: string): string => createHash('sha256').update(bytes).digest('hex');

const TARGET: Readonly<Record<Proposal['kind'], string>> = { memory: 'MEMORY.md', user: 'USER.md', rule: 'AGENTS.md', skill: 'a new skill' };

/** The rule as a one-line addition to AGENTS.md, shown as a diff that must be opened before a yes counts. */
export function ruleDiff(current: string | null, rule: string): { readonly next: string; readonly diff: string } {
  const before = current ?? '';
  const line = `- ${rule.trim()}`;
  const next = `${before}${before === '' || before.endsWith('\n') ? '' : '\n'}${line}\n`;
  return { next, diff: `--- AGENTS.md\n+++ AGENTS.md\n@@ end of file @@\n+${line}` };
}

/**
 * Cards for this session start: up to three, best first. Any proposal past its expiry is answered
 * `expired` on the way, so an unanswered card never comes back.
 */
export async function morningCards(paths: MemoryPaths, now: Date): Promise<Proposal[]> {
  const answered = new Set((await readAnswers(paths)).map((answer) => answer.id));
  for (const proposal of await readProposals(paths)) {
    if (!answered.has(proposal.id) && Date.parse(proposal.expires) <= now.getTime()) {
      await recordAnswer(paths, { id: proposal.id, answer: 'expired', by: 'hn', at: now.toISOString(), textHash: proposalHash(proposal) });
    }
  }
  return (await pendingProposals(paths, now)).slice(0, MAX_CARDS);
}

/** A card drawn only by the harness. Every byte that came from a model or a log goes through `sanitizeForDisplay`. */
export function renderMemoryCard(proposal: Proposal, position: { readonly index: number; readonly of: number }): string {
  const bytes = storedBytes(proposal);
  const shown = sanitizeForDisplay(bytes);
  const lines = [
    `── Memory card ${position.index} of ${position.of} · from ${proposal.source === 'dream' ? 'dreaming' : 'background review'} · would add to ${TARGET[proposal.kind]} ──`,
    `Why: ${sanitizeForDisplay(proposal.why)}`,
    `Would store exactly (${Buffer.byteLength(bytes)} bytes, sha256 ${bytesHash(bytes).slice(0, 12)}):`,
    ...shown.split('\n').map((line) => `  │ ${line}`),
    ...(shown !== bytes ? ['  (some characters could not be shown as they are and were escaped above)'] : []),
    `Evidence (${proposal.evidence.length}), with where each came from:`,
    ...proposal.evidence.slice(0, 5).map((item) => `  - [${item.origin}] ${sanitizeForDisplay(item.session)} #${item.seq}: ${sanitizeForDisplay(item.quote.replace(/\s+/g, ' ').slice(0, 160))}`),
    ...(proposal.evidence.length > 5 ? [`  … and ${proposal.evidence.length - 5} more`] : []),
    ...(isUntrusted(proposal.origin) ? [`  Note: some of this came from ${proposal.origin}, not from you.`] : []),
    proposal.kind === 'rule' || proposal.kind === 'skill'
      ? '[d] open the diff first   [n] no, and do not ask again   [enter] later'
      : '[y] save it   [n] no, and do not ask again   [enter] later',
  ];
  return `${lines.join('\n')}\n`;
}

export type CardAnswer =
  | { readonly kind: 'yes'; readonly by: string; readonly shownHash: string; readonly diffOpened?: boolean }
  | { readonly kind: 'no'; readonly by: string };

export type CardOutcome =
  | { readonly ok: true; readonly message: string; readonly rule?: string }
  | { readonly ok: false; readonly message: string };

/**
 * A person's answer. Yes writes through the same path as the memory tool, with its scan and caps,
 * recording who approved; it is refused when the bytes to store are not the ones that were shown.
 * No records a suppression. A rule is not written here: the caller writes AGENTS.md after the diff.
 */
export async function answerCard(paths: MemoryPaths, id: string, answer: CardAnswer, now: Date): Promise<CardOutcome> {
  const proposal = (await readProposals(paths)).find((candidate) => candidate.id === id);
  if (proposal === undefined) return { ok: false, message: 'That card is gone.' };
  if ((await readAnswers(paths)).some((existing) => existing.id === id)) return { ok: false, message: 'That card was already answered.' };
  const record = (kind: 'yes' | 'no') => recordAnswer(paths, { id, answer: kind, by: answer.by, at: now.toISOString(), textHash: proposalHash(proposal) });
  if (answer.kind === 'no') {
    await record('no');
    return { ok: true, message: 'Not saved, and it will not be asked again.' };
  }
  const bytes = storedBytes(proposal);
  if (bytesHash(bytes) !== answer.shownHash) return { ok: false, message: 'The text to store changed after the card was shown, so nothing was saved.' };
  if (proposal.kind === 'skill') return { ok: false, message: 'A skill card is answered by running /learn on what it names, after reading it.' };
  if (proposal.kind === 'rule') {
    if (answer.diffOpened !== true) return { ok: false, message: 'Open the diff first: a rule changes AGENTS.md, so one key is not enough.' };
    await record('yes');
    return { ok: true, message: 'Approved for AGENTS.md.', rule: bytes };
  }
  const write = await writeMemory({
    paths,
    target: proposal.kind,
    // The store trims and redacts, which turns this into exactly `bytes`; handing it `bytes` would trip its sentinel check.
    ops: [{ op: 'add', text: proposal.text }],
    who: proposal.source === 'dream' ? 'dream' : 'review',
    sourceSession: proposal.evidence[0]?.session ?? null,
    origin: proposal.origin,
    taint: isUntrusted(proposal.origin) ? 'untrusted' : 'clean',
    why: proposal.why,
    approvedBy: `human:${answer.by}`,
    now,
  });
  if (!write.result.ok) return { ok: false, message: write.result.reason };
  await record('yes');
  return { ok: true, message: `Saved to ${TARGET[proposal.kind]}.` };
}
