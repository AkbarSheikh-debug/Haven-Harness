import { sanitizeForDisplay } from '@hn/core';

/**
 * The full-screen TUI's two pure parts: reading keys and drawing the screen. Kept apart from the terminal
 * so both are tested as plain functions.
 *
 * Two rules hold here. Every escape sequence the terminal sends is a key or nothing, never typed text, so a
 * terminal's reply (a cursor report, a colour answer) cannot become an answer to an approval. And only the harness draws
 * with colour: model text passes `sanitizeForDisplay`, which removes every escape, so the reverse-video frame of a card
 * is a style model content cannot produce.
 */

export type Key =
  | { readonly kind: 'text'; readonly text: string }
  | { readonly kind: 'enter' | 'backspace' | 'tab' | 'up' | 'down' | 'pageup' | 'pagedown' | 'escape' | 'interrupt' | 'eof' };

/** Splits raw terminal input into keys. Escape sequences that are not keys this UI uses are dropped whole. */
export function parseKeys(input: string): Key[] {
  const keys: Key[] = [];
  let text = '';
  const flush = (): void => {
    if (text !== '') keys.push({ kind: 'text', text });
    text = '';
  };
  for (let i = 0; i < input.length; i += 1) {
    const c = input[i] as string;
    const code = c.charCodeAt(0);
    if (c === '\u001b' || c === '\u009b') {
      flush();
      // CSI: ESC [ params... final byte. OSC/DCS/APC/PM/SOS: up to BEL or ST. SS3: ESC O x. Anything else: ESC x.
      const next = c === '\u009b' ? '[' : input[i + 1];
      const start = c === '\u009b' ? i + 1 : i + 2;
      if (next === '[') {
        let j = start;
        while (j < input.length && !/[@-~]/.test(input[j] as string)) j += 1;
        const body = input.slice(start, j);
        const final = input[j] ?? '';
        if (body === '' && final === 'A') keys.push({ kind: 'up' });
        else if (body === '' && final === 'B') keys.push({ kind: 'down' });
        else if (body === '5' && final === '~') keys.push({ kind: 'pageup' });
        else if (body === '6' && final === '~') keys.push({ kind: 'pagedown' });
        else if (body === 'Z' || (body === '' && final === 'Z')) keys.push({ kind: 'tab' });
        i = j;
      } else if (next === ']' || next === 'P' || next === '_' || next === '^' || next === 'X') {
        let j = start;
        while (j < input.length && input[j] !== '\u0007' && !(input[j] === '\u001b' && input[j + 1] === '\\')) j += 1;
        i = input[j] === '\u001b' ? j + 1 : j;
      } else if (next === 'O') {
        const final = input[i + 2];
        if (final === 'A') keys.push({ kind: 'up' });
        else if (final === 'B') keys.push({ kind: 'down' });
        i += 2;
      } else if (next === undefined) {
        keys.push({ kind: 'escape' });
      } else {
        i += 1;
      }
      continue;
    }
    if (c === '\r' || c === '\n') {
      flush();
      keys.push({ kind: 'enter' });
      if (c === '\r' && input[i + 1] === '\n') i += 1;
    } else if (code === 0x7f || code === 0x08) {
      flush();
      keys.push({ kind: 'backspace' });
    } else if (c === '\t') {
      flush();
      keys.push({ kind: 'tab' });
    } else if (code === 0x03) {
      flush();
      keys.push({ kind: 'interrupt' });
    } else if (code === 0x04) {
      flush();
      keys.push({ kind: 'eof' });
    } else if (code >= 0x20 && !(code >= 0x80 && code < 0xa0)) {
      text += c;
    }
  }
  flush();
  return keys;
}

export interface Entry {
  readonly who: 'you' | 'hn' | 'tool' | 'note';
  readonly text: string;
}

export interface InboxCard {
  readonly approvalId: string;
  readonly tool: string;
  readonly effect: string;
  readonly summary: string;
  readonly target?: string;
}

export interface InboxDraft {
  readonly kind: string;
  readonly text: string;
  readonly why: string;
}

export interface ScreenState {
  readonly mode: string;
  readonly tier: number;
  readonly model: string;
  readonly view: 'chat' | 'inbox';
  readonly transcript: readonly Entry[];
  readonly input: string;
  readonly busy: boolean;
  readonly tokens: number;
  readonly cacheHit: number | null;
  readonly cards: readonly InboxCard[];
  readonly drafts: readonly InboxDraft[];
  readonly selected: number;
  /** Lines scrolled up from the bottom of the transcript. */
  readonly scroll: number;
}

const SGR = { reverse: '\u001b[7m', bold: '\u001b[1m', red: '\u001b[31m', dim: '\u001b[2m', reset: '\u001b[0m' };

/** Cuts text to lines of at most `width` characters, after removing every escape and control character. */
export function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  for (const raw of sanitizeForDisplay(text).split('\n')) {
    const line = raw.replaceAll('\t', '  ');
    if (line === '') out.push('');
    for (let i = 0; i < line.length; i += width) out.push(line.slice(i, i + width));
  }
  return out;
}

const pad = (text: string, width: number): string => (text.length >= width ? text.slice(0, width) : text + ' '.repeat(width - text.length));

/** The harness's card frame. Model text inside it is sanitized; the frame's colour is the harness's alone. */
function cardLines(card: InboxCard, width: number, selected: boolean): string[] {
  const inner = Math.max(10, width - 4);
  const frame = `${SGR.reverse}${SGR.red}`;
  const head = ` hn asks: ${card.tool} (${card.effect}) ${selected ? '<' : ''}`;
  const lines = [`${frame}${pad(head, width)}${SGR.reset}`];
  for (const line of [...wrap(card.summary, inner), ...(card.target === undefined ? [] : wrap(`target: ${card.target}`, inner))]) lines.push(`${frame} ${SGR.reset} ${pad(line, inner)} ${frame} ${SGR.reset}`);
  lines.push(`${frame}${pad(selected ? ' type yes and Enter to allow once; anything else and Enter denies' : '', width)}${SGR.reset}`);
  return lines;
}

/** The whole screen as lines, exactly `height` of them. */
export function renderScreen(state: ScreenState, width: number, height: number): string[] {
  const top = `${SGR.bold} hn ${SGR.reset} ${sanitizeForDisplay(state.model)}  mode ${state.mode}  tier ${state.tier}  ${state.view === 'inbox' ? '[inbox]' : '[chat]'}  inbox ${state.cards.length + state.drafts.length}`;
  const banner = state.tier < 3 ? `${SGR.reverse} NOT SANDBOXED: tools run on this machine with your rights. ${SGR.reset}` : `${SGR.dim} sandboxed (tier ${state.tier}), working on a copy ${SGR.reset}`;
  const status = `${SGR.dim} ${state.busy ? 'working...' : 'ready'}  tokens ${state.tokens}${state.cacheHit === null ? '' : `  cache ${Math.round(state.cacheHit * 100)}%`}  Tab: ${state.view === 'chat' ? 'inbox' : 'chat'}  Ctrl+C: stop or quit ${SGR.reset}`;
  const prompt = `> ${sanitizeForDisplay(state.input)}`.slice(-width);
  const bodyHeight = Math.max(1, height - 4);
  let body: string[];
  if (state.view === 'inbox') {
    body = [];
    if (state.cards.length === 0 && state.drafts.length === 0) body.push('Nothing is waiting for you.');
    state.cards.forEach((card, index) => body.push(...cardLines(card, width, index === state.selected), ''));
    if (state.drafts.length > 0) body.push(`${SGR.bold}Drafts waiting for your YES (review them with the morning cards in the line REPL):${SGR.reset}`);
    for (const draft of state.drafts) body.push(...wrap(`- ${draft.kind}: ${draft.text}  (${draft.why})`, width));
    body = body.slice(0, bodyHeight);
  } else {
    const all: string[] = [];
    for (const entry of state.transcript) {
      const label = entry.who === 'you' ? 'you> ' : entry.who === 'tool' ? '  . ' : entry.who === 'note' ? '  ! ' : '';
      const lines = wrap(`${label}${entry.text}`, width);
      all.push(...lines);
    }
    const end = Math.max(0, all.length - state.scroll);
    body = all.slice(Math.max(0, end - bodyHeight), end);
  }
  while (body.length < bodyHeight) body.push('');
  return [top, banner, ...body, status, prompt].map((line) => line);
}
