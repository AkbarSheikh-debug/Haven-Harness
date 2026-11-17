export const REDACTED = '[REDACTED]';

/** Secrets with a recognisable shape. Every match is replaced. */
const SHAPES: readonly RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\bsk-ant-[A-Za-z0-9_-]{16,}/g,
  /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{30,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\bAIza[A-Za-z0-9_-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}/gi,
];

/** `name=value` and `"name": "value"` where the name says it is a secret. The name stays, the value goes. */
const ASSIGNMENT =
  /((?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential)[A-Za-z0-9_]*["']?\s*[:=]\s*["']?)([^\s"'&,;]{6,})/gi;

/** `scheme://user:password@host` and `scheme://token@host`. */
const URL_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@"'<>]+@/gi;

/** How much text a stream holds back, so a secret split across two chunks is whole when it is checked. */
const STREAM_HOLD = 256;

/** Every spelling an encoder could give a known secret, because a model can base64 or percent-encode what it was shown. */
export function variantsOf(secret: string): string[] {
  if (secret.length < 8) return [];
  const bytes = Buffer.from(secret, 'utf8');
  const variants = new Set<string>([secret, encodeURIComponent(secret), bytes.toString('hex')]);
  // Base64 depends on where the secret starts inside a longer message, so try all three offsets.
  for (const pad of [0, 1, 2]) {
    const encoded = Buffer.concat([Buffer.alloc(pad, 0x78), bytes]).toString('base64').replace(/=+$/, '');
    // The first and last characters mix in neighbouring bytes, so only the stable middle is matched.
    const core = encoded.slice(Math.ceil((pad * 8) / 6), encoded.length - 4);
    if (core.length >= 8) {
      variants.add(core);
      variants.add(core.replaceAll('+', '-').replaceAll('/', '_'));
    }
  }
  return [...variants].filter((variant) => variant.length >= 8);
}

export class Redactor {
  readonly #known = new Set<string>();

  /** Registers an exact secret, such as a model key, so it is caught in any common encoding. */
  addSecret(secret: string): void {
    for (const variant of variantsOf(secret)) this.#known.add(variant);
  }

  redact(text: string): string {
    let out = text;
    // Longest first, so a secret that contains another one is replaced whole.
    for (const known of [...this.#known].sort((a, b) => b.length - a.length)) out = out.split(known).join(REDACTED);
    out = out.replace(URL_USERINFO, (_whole, scheme: string) => `${scheme}${REDACTED}@`);
    for (const shape of SHAPES) out = out.replace(shape, REDACTED);
    return out.replace(ASSIGNMENT, (_whole, name: string, value: string) => {
      // An unquoted value after a colon is a JSON number or word: the replacement is quoted and any closing brackets
      // are kept, so a redacted log row is still valid JSON (found by testing: "tokenBudget":3000000 broke a log).
      if (/:\s*$/.test(name)) {
        const head = /^[[{]*/.exec(value)?.[0] ?? '';
        const tail = /[\]}]+.*$/.exec(value.slice(head.length))?.[0] ?? '';
        return `${name}${head}"${REDACTED}"${tail}`;
      }
      return `${name}${REDACTED}`;
    });
  }

  /** Redacts every string inside a value, keys included, without changing its shape. */
  redactDeep<T>(value: T): T {
    if (typeof value === 'string') return this.redact(value) as T;
    if (Array.isArray(value)) return value.map((item) => this.redactDeep(item)) as T;
    if (typeof value === 'object' && value !== null) {
      const out = Object.create(null) as Record<string, unknown>;
      for (const [key, item] of Object.entries(value)) out[this.redact(key)] = this.redactDeep(item);
      return out as T;
    }
    return value;
  }

  /** A redactor for text that arrives in pieces. */
  stream(): RedactingStream {
    return new RedactingStream(this);
  }
}

/** A stream that never reaches a safe cut point is cut anyway at this size, so memory stays bounded. */
const STREAM_MAX_HOLD = 64 * 1024;
const MAX_CUT_TRIES = 128;

export class RedactingStream {
  readonly #redactor: Redactor;
  /** Raw, not yet redacted: a secret that has only half arrived must still be recognisable when the rest does. */
  #held = '';

  constructor(redactor: Redactor) {
    this.#redactor = redactor;
  }

  /** Returns the text that is safe to emit now. The newest characters wait for the next chunk. */
  push(chunk: string): string {
    this.#held += chunk;
    if (this.#held.length <= STREAM_HOLD) return '';
    const cut = this.#safeCut();
    if (cut === null) return '';
    const emit = this.#redactor.redact(this.#held.slice(0, cut));
    this.#held = this.#held.slice(cut);
    return emit;
  }

  /** Emits whatever is still held. Call once, when the stream ends. */
  end(): string {
    const rest = this.#redactor.redact(this.#held);
    this.#held = '';
    return rest;
  }

  /** A cut is safe when redacting the two halves apart gives the same text as redacting the whole, so no secret straddles it. */
  #safeCut(): number | null {
    const held = this.#held;
    const whole = this.#redactor.redact(held);
    let cut = held.length - STREAM_HOLD;
    for (let tries = 0; tries < MAX_CUT_TRIES && cut > 0; tries += 1) {
      const at = held.slice(0, cut).search(/\s\S*$/);
      if (at < 0) break;
      cut = at + 1;
      if (this.#redactor.redact(held.slice(0, cut)) + this.#redactor.redact(held.slice(cut)) === whole) return cut;
      cut = at;
    }
    return held.length > STREAM_MAX_HOLD ? held.length - STREAM_HOLD : null;
  }
}

export function containsSentinel(text: string): boolean {
  return text.includes(REDACTED);
}

/**
 * The model saw `[REDACTED]` where a secret was. If it writes that back, the real secret is
 * destroyed, so a write that carries more sentinels than the file already had is refused.
 */
export function sentinelWriteProblem(existing: string | null, proposed: string): string | null {
  const before = existing === null ? 0 : existing.split(REDACTED).length - 1;
  const after = proposed.split(REDACTED).length - 1;
  if (after <= before) return null;
  return `The text contains ${REDACTED}, which stands for a secret you were not shown. Writing it would destroy the real value. Edit around that part instead.`;
}
