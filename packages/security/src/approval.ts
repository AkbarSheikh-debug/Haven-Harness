import { createHash } from 'node:crypto';
import type { ApprovalCard } from './gate.ts';

/** Key order must not change a hash, so objects are written with sorted keys. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export interface ApprovalBinding {
  readonly tool: string;
  readonly args: unknown;
  readonly workdir: string;
  /** Where the action runs, so a yes for the local machine is not a yes for a container. */
  readonly backend: string;
  /** Hashes of scripts the command will run, so editing the script after approval voids it. */
  readonly scripts?: Readonly<Record<string, string>> | undefined;
}

/** A grant is bound to exactly what runs. Change an argument, a script or the backend and the grant is dead. */
export function approvalHash(binding: ApprovalBinding): string {
  return createHash('sha256')
    .update(canonical([binding.tool, binding.args, binding.workdir, binding.backend, binding.scripts ?? {}]))
    .digest('hex');
}

/** What a human can review in one sitting. Anything longer is refused, never approved unseen. */
export const MAX_CARD_BYTES = 8_192;

/**
 * Everything outside printable ASCII is shown as an escape, so a right-to-left override, a
 * lookalike letter or a zero-width character cannot make an approval read as something else.
 * Newlines and tabs stay so a diff is readable.
 */
export function escapeForCard(text: string): string {
  let out = '';
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    if (char === '\n' || char === '\t' || (code >= 0x20 && code <= 0x7e)) out += char;
    else out += `\\u{${code.toString(16)}}`;
  }
  return out;
}

/** The glyph that frames a card. Model text is escaped to ASCII first, so it can never contain it. */
export const CARD_MARK = '▌';

/** Drawn only by the harness. Every line of model-supplied text is escaped and prefixed. */
export function renderCard(card: ApprovalCard): string {
  const body = escapeForCard(card.summary)
    .split('\n')
    .map((line) => `${CARD_MARK} | ${line}`)
    .join('\n');
  const target = card.target === undefined ? '' : `\n${CARD_MARK} target: ${escapeForCard(card.target)}`;
  const session = card.canRememberForSession ? ', [s]ession' : '';
  return `\n${CARD_MARK} hn approval: ${card.tool} (${card.effect}, ${card.byteCount} bytes)${target}\n${body}\n${CARD_MARK} Allow? [y]es once${session}, [N]o: `;
}

/** More than `max` prompts inside `windowMs` pauses prompting, so a loop cannot wear a human down into saying yes. */
export class PromptLimiter {
  readonly #max: number;
  readonly #windowMs: number;
  readonly #now: () => number;
  #times: number[] = [];

  constructor(max: number, windowMs: number, now: () => number = Date.now) {
    this.#max = max;
    this.#windowMs = windowMs;
    this.#now = now;
  }

  /** Records a prompt and says whether it may be shown. */
  allow(): boolean {
    const now = this.#now();
    this.#times = this.#times.filter((time) => now - time < this.#windowMs);
    if (this.#times.length >= this.#max) return false;
    this.#times.push(now);
    return true;
  }
}
