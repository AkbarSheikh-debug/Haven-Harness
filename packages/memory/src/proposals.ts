import { createHash, randomBytes } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { ORIGINS, type Origin } from '@hn/core';
import { readOrNull, withLock } from './disk.ts';
import type { MemoryPaths } from './paths.ts';

/** What a card would change: MEMORY.md, USER.md, a new skill (through /learn), or a rule for AGENTS.md (as a diff). */
export const PROPOSAL_KINDS = ['memory', 'user', 'skill', 'rule'] as const;
export type ProposalKind = (typeof PROPOSAL_KINDS)[number];

export interface Evidence {
  readonly session: string;
  readonly seq: number;
  readonly origin: Origin;
  readonly quote: string;
}

/**
 * One proposal. `text` is the exact bytes a yes would store, so a card can never show a friendly
 * summary while storing something else (10.8). Proposals are appended, never edited.
 */
export interface Proposal {
  readonly v: 1;
  readonly id: string;
  readonly kind: ProposalKind;
  readonly text: string;
  readonly why: string;
  readonly evidence: readonly Evidence[];
  readonly source: 'review' | 'dream';
  /** The worst origin among the evidence. */
  readonly origin: Origin;
  readonly created: string;
  readonly expires: string;
  readonly score: number | null;
}

export interface Answer {
  readonly v: 1;
  readonly id: string;
  readonly answer: 'yes' | 'no' | 'expired';
  readonly by: string;
  readonly at: string;
  /** A no suppresses the same text from coming back under a new id. */
  readonly textHash: string;
}

/** Unanswered cards expire after a week. */
export const PROPOSAL_TTL_MS = 7 * 86_400_000;
const ORIGIN_SET: ReadonlySet<string> = new Set(ORIGINS);
const answersPath = (paths: MemoryPaths): string => join(dirname(paths.proposals), 'answers.jsonl');

export const textHash = (text: string): string => createHash('sha256').update(text).digest('hex');
/** What makes two proposals the same card: the kind and the exact bytes. */
export const proposalHash = (proposal: Pick<Proposal, 'kind' | 'text'>): string => textHash(`${proposal.kind}\n${proposal.text}`);
export const newProposalId = (): string => randomBytes(8).toString('hex');

function parseEvidence(raw: unknown): Evidence | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const { session, seq, origin, quote } = raw as Record<string, unknown>;
  if (typeof session !== 'string' || !Number.isSafeInteger(seq) || typeof quote !== 'string') return null;
  if (typeof origin !== 'string' || !ORIGIN_SET.has(origin)) return null;
  return { session, seq: seq as number, origin: origin as Origin, quote };
}

/** A proposal from one JSON line, or null if any part is malformed. */
export function parseProposal(line: string): Proposal | null {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (r['v'] !== 1 || typeof r['id'] !== 'string' || !/^[0-9a-f]{16}$/.test(r['id'])) return null;
  if (!(PROPOSAL_KINDS as readonly unknown[]).includes(r['kind'])) return null;
  if (typeof r['text'] !== 'string' || r['text'] === '' || typeof r['why'] !== 'string') return null;
  if (r['source'] !== 'review' && r['source'] !== 'dream') return null;
  if (typeof r['origin'] !== 'string' || !ORIGIN_SET.has(r['origin'])) return null;
  if (typeof r['created'] !== 'string' || typeof r['expires'] !== 'string' || Number.isNaN(Date.parse(r['created'])) || Number.isNaN(Date.parse(r['expires']))) return null;
  if (!(r['score'] === null || typeof r['score'] === 'number')) return null;
  if (!Array.isArray(r['evidence'])) return null;
  const evidence = r['evidence'].map(parseEvidence);
  if (evidence.some((item) => item === null)) return null;
  return {
    v: 1, id: r['id'], kind: r['kind'] as ProposalKind, text: r['text'], why: r['why'], evidence: evidence as Evidence[],
    source: r['source'], origin: r['origin'] as Origin, created: r['created'], expires: r['expires'], score: r['score'] as number | null,
  };
}

async function appendLine(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await withLock(path, () => appendFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600, flush: true }));
}

export async function appendProposal(paths: MemoryPaths, proposal: Proposal): Promise<void> {
  await appendLine(paths.proposals, proposal);
}

export async function readProposals(paths: MemoryPaths): Promise<Proposal[]> {
  const text = (await readOrNull(paths.proposals)) ?? '';
  return text.split('\n').flatMap((line) => {
    const parsed = line.trim() === '' ? null : parseProposal(line);
    return parsed === null ? [] : [parsed];
  });
}

export async function readAnswers(paths: MemoryPaths): Promise<Answer[]> {
  const text = (await readOrNull(answersPath(paths))) ?? '';
  return text.split('\n').flatMap((line) => {
    try {
      const raw = JSON.parse(line) as Answer;
      return raw.v === 1 && typeof raw.id === 'string' && ['yes', 'no', 'expired'].includes(raw.answer) && typeof raw.textHash === 'string' ? [raw] : [];
    } catch {
      return [];
    }
  });
}

export async function recordAnswer(paths: MemoryPaths, answer: Omit<Answer, 'v'>): Promise<void> {
  await appendLine(answersPath(paths), { v: 1, ...answer });
}

/**
 * Cards still waiting: not answered, not expired, not the text of an earlier no, and not a copy of
 * another waiting card. Best score first, then oldest.
 */
export async function pendingProposals(paths: MemoryPaths, now: Date): Promise<Proposal[]> {
  const answers = await readAnswers(paths);
  const answered = new Set(answers.map((answer) => answer.id));
  const refused = new Set(answers.filter((answer) => answer.answer === 'no').map((answer) => answer.textHash));
  const accepted = new Set(answers.filter((answer) => answer.answer === 'yes').map((answer) => answer.textHash));
  const seen = new Set<string>();
  const out: Proposal[] = [];
  for (const proposal of await readProposals(paths)) {
    const hash = proposalHash(proposal);
    if (answered.has(proposal.id) || refused.has(hash) || accepted.has(hash) || seen.has(hash)) continue;
    if (Date.parse(proposal.expires) <= now.getTime()) continue;
    seen.add(hash);
    out.push(proposal);
  }
  return out.sort((a, b) => (b.score ?? 0) - (a.score ?? 0) || a.created.localeCompare(b.created));
}
