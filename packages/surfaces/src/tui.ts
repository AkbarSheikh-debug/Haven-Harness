import { HnError, sanitizeForDisplay } from '@hn/core';
import { pendingProposals } from '@hn/memory';
import type { KeyStore } from '@hn/provider';
import type { ApprovalAnswer, ApprovalCard } from '@hn/security';
import { Harness, type HarnessOptions } from './harness.ts';
import { parseApproval } from './repl.ts';
import type { CliOptions } from './session.ts';
import { parseKeys, renderScreen, type Entry, type InboxCard, type InboxDraft, type Key, type ScreenState } from './tui-screen.ts';

/**
 * `hn tui` (decision 13): the same session as the line REPL, full screen, with an inbox of what waits for a person:
 * approval cards, and memory drafts that need a YES. The controller holds all the behaviour and no terminal, so it is
 * tested by feeding it keys. An approval is decided only by Enter on a typed answer: "yes" allows once, anything else
 * denies, and an empty Enter decides nothing.
 */
export class TuiController {
  readonly #options: HarnessOptions;
  readonly #changed: () => void;
  #harness: Harness | null = null;
  #transcript: Entry[] = [];
  #input = '';
  #busy = false;
  #view: 'chat' | 'inbox' = 'chat';
  #selected = 0;
  #scroll = 0;
  #tokens = 0;
  #mode = '';
  #tier = 0;
  #cards: { card: InboxCard; resolve: (answer: ApprovalAnswer) => void; raw: ApprovalCard }[] = [];
  #drafts: InboxDraft[] = [];
  #quit: (() => void) | null = null;
  readonly quit: Promise<void>;
  #running: Promise<unknown> = Promise.resolve();

  constructor(options: HarnessOptions, changed: () => void) {
    this.#options = options;
    this.#changed = changed;
    this.quit = new Promise((resolve) => (this.#quit = resolve));
  }

  async open(): Promise<void> {
    const harness = new Harness({
      ...this.#options,
      approver: (card) =>
        new Promise<ApprovalAnswer>((resolve) => {
          this.#cards.push({ card: { approvalId: card.approvalId, tool: card.tool, effect: card.effect, summary: card.summary, ...(card.target === undefined ? {} : { target: card.target }) }, resolve, raw: card });
          this.#view = 'inbox';
          this.#changed();
        }),
      onEvent: (event) => {
        if (event.type === 'text') {
          const last = this.#transcript.at(-1);
          if (last?.who === 'hn') this.#transcript[this.#transcript.length - 1] = { who: 'hn', text: last.text + event.text };
          else this.#transcript.push({ who: 'hn', text: event.text });
        } else if (event.type === 'tool_input') {
          this.#transcript.push({ who: 'tool', text: event.name });
        }
        this.#changed();
      },
    });
    this.#harness = harness;
    const session = await harness.open();
    this.#mode = session.gate.mode;
    this.#tier = session.tier;
    for (const note of session.notes) this.#transcript.push({ who: 'note', text: note });
    if (session.memoryPaths !== null) {
      const drafts = await pendingProposals(session.memoryPaths, new Date()).catch(() => []);
      this.#drafts = drafts.map((draft) => ({ kind: draft.kind, text: draft.text, why: draft.why }));
    }
    this.#changed();
  }

  get state(): ScreenState {
    return {
      mode: this.#mode,
      tier: this.#tier,
      model: this.#options.model ?? "",
      view: this.#view,
      transcript: this.#transcript,
      input: this.#input,
      busy: this.#busy,
      tokens: this.#tokens,
      cacheHit: null,
      cards: this.#cards.map((entry) => entry.card),
      drafts: this.#drafts,
      selected: this.#selected,
      scroll: this.#scroll,
    };
  }

  /** Resolves once the turn now running (if any) has ended. */
  get settled(): Promise<unknown> {
    return this.#running;
  }

  #submit(text: string): void {
    const harness = this.#harness;
    if (harness === null) return;
    if (this.#busy) {
      // Typed during a turn: a steer, which arrives at the next step boundary.
      harness.steer(text);
      this.#transcript.push({ who: 'you', text: `(steer) ${text}` });
      return;
    }
    this.#transcript.push({ who: 'you', text });
    this.#busy = true;
    this.#running = harness
      .run(text, { origin: 'user' })
      .then((result) => {
        this.#tokens += result.usage.input + result.usage.output;
        if (this.#transcript.at(-1)?.who !== 'hn') this.#transcript.push({ who: 'hn', text: result.text });
        if (result.end !== 'done') this.#transcript.push({ who: 'note', text: `The turn ended: ${result.end}${result.detail === undefined ? '' : ` (${result.detail})`}` });
      })
      .catch((error: unknown) => this.#transcript.push({ who: 'note', text: sanitizeForDisplay(error instanceof Error ? error.message : String(error)) }))
      .finally(() => {
        this.#busy = false;
        this.#changed();
      });
  }

  #decide(): void {
    const entry = this.#cards[this.#selected];
    const typed = this.#input;
    if (entry === undefined || typed.trim() === '') return;
    this.#input = '';
    this.#cards.splice(this.#selected, 1);
    this.#selected = Math.max(0, Math.min(this.#selected, this.#cards.length - 1));
    const answer = parseApproval(typed, entry.raw);
    this.#transcript.push({ who: 'note', text: `${answer === 'deny' ? 'Denied' : 'Allowed once'}: ${entry.card.summary}` });
    if (this.#cards.length === 0) this.#view = 'chat';
    entry.resolve(answer === 'deny' ? 'deny' : 'once');
  }

  feed(keys: readonly Key[]): void {
    for (const key of keys) {
      if (key.kind === 'text') this.#input += key.text;
      else if (key.kind === 'backspace') this.#input = this.#input.slice(0, -1);
      else if (key.kind === 'tab') this.#view = this.#view === 'chat' ? 'inbox' : 'chat';
      else if (key.kind === 'up') this.#view === 'inbox' ? (this.#selected = Math.max(0, this.#selected - 1)) : (this.#scroll += 1);
      else if (key.kind === 'down') this.#view === 'inbox' ? (this.#selected = Math.min(Math.max(0, this.#cards.length - 1), this.#selected + 1)) : (this.#scroll = Math.max(0, this.#scroll - 1));
      else if (key.kind === 'pageup') this.#scroll += 10;
      else if (key.kind === 'pagedown') this.#scroll = Math.max(0, this.#scroll - 10);
      else if (key.kind === 'enter') {
        if (this.#view === 'inbox' && this.#cards.length > 0) this.#decide();
        else if (this.#input.trim() !== '') {
          const text = this.#input;
          this.#input = '';
          this.#scroll = 0;
          this.#submit(text);
        }
      } else if (key.kind === 'interrupt') {
        if (this.#busy) this.#harness?.stop();
        else this.#quit?.();
      } else if (key.kind === 'eof' && !this.#busy) this.#quit?.();
    }
    this.#changed();
  }

  async close(): Promise<void> {
    for (const entry of this.#cards.splice(0)) entry.resolve('deny');
    await this.#harness?.close();
  }
}

/** Runs the TUI on this terminal until Ctrl+C with nothing running. */
export async function runTui(options: CliOptions, keys: KeyStore): Promise<number> {
  const input = process.stdin;
  const output = process.stdout;
  if (input.isTTY !== true || output.isTTY !== true) throw new HnError('NO_TERMINAL', 'hn tui needs a terminal. Use hn for the line REPL, or hn -p for a headless run.');
  let controller: TuiController | null = null;
  const draw = (): void => {
    if (controller === null) return;
    const lines = renderScreen(controller.state, output.columns || 80, output.rows || 24);
    output.write(`\u001b[H${lines.map((line) => `${line}\u001b[K`).join('\r\n')}`);
  };
  controller = new TuiController({ ...options, keys }, draw);
  output.write('\u001b[?1049h\u001b[?25l\u001b[2J');
  input.setRawMode(true);
  input.setEncoding('utf8');
  const onData = (chunk: string): void => controller?.feed(parseKeys(chunk));
  input.on('data', onData);
  output.on('resize', draw);
  try {
    await controller.open();
    await controller.quit;
  } finally {
    input.off('data', onData);
    output.off('resize', draw);
    input.setRawMode(false);
    input.pause();
    await controller.close();
    output.write('\u001b[?25h\u001b[?1049l');
  }
  return 0;
}
