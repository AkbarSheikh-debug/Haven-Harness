import { Worker } from 'node:worker_threads';

/**
 * Scanning is a speed bump. Provenance (taint) is the control. These patterns catch the lazy
 * and the copy-pasted, and they run in a worker so a pattern that backtracks forever is killed
 * and the text is denied instead of hanging the harness.
 */

export const SCOPES = ['all', 'context', 'strict'] as const;
export type ThreatScope = (typeof SCOPES)[number];

export interface Finding {
  readonly id: string;
  readonly label: string;
}

export interface ExtraPattern {
  readonly source: string;
  readonly flags: string;
  readonly id: string;
}

interface Rule {
  readonly id: string;
  readonly label: string;
  readonly pattern: RegExp;
}

/** Applies to every scope. Written against normalised text: lowercase, NFKC, confusables folded. */
const ALL: readonly Rule[] = [
  { id: 'ignore-instructions', label: 'tells the model to ignore its instructions', pattern: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system|your)\b[^.\n]{0,30}\b(instructions?|rules?|prompts?|guidelines?)\b/ },
  { id: 'reveal-prompt', label: 'asks for the system prompt', pattern: /\b(reveal|print|show|repeat|output)\b[^.\n]{0,30}\b(system|hidden|initial)\s+(prompt|instructions?|message)\b/ },
  { id: 'hide-from-user', label: 'asks the model to hide something from the user', pattern: /\b(do not|don'?t|never)\s+(tell|inform|show|mention)[^.\n]{0,20}\b(the )?user\b/ },
  { id: 'exfil-secret-env', label: 'sends a secret from the environment somewhere', pattern: /\b(curl|wget|nc|ncat|invoke-webrequest|iwr)\b[^\n]{0,200}\$\{?[a-z_]*(key|token|secret|password)/ },
  { id: 'read-ssh', label: 'reads SSH keys or credential stores', pattern: /(~|\$home|%userprofile%)[\\/](\.ssh|\.aws|\.gnupg|\.netrc)\b|\bauthorized_keys\b/ },
  { id: 'pipe-to-shell', label: 'pipes a download into a shell', pattern: /\b(curl|wget)\b[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b/ },
];

/** Adds what only matters for text that lives in the prompt: role markers and fake system frames. */
const CONTEXT: readonly Rule[] = [
  { id: 'role-tag', label: 'imitates a system or role message', pattern: /<\/?\s*(system|assistant|developer|system-reminder|instructions?)\s*>|\[\s*(system|inst)\s*\]/ },
  { id: 'new-instructions', label: 'introduces new instructions', pattern: /\b(new|updated|real|actual)\s+(instructions?|rules?|system prompt)\s*:/ },
  { id: 'persona-switch', label: 'switches the model to another persona', pattern: /\byou are now\b|\bact as (an? )?(unrestricted|jailbroken|different)\b|\bdeveloper mode\b/ },
];

/** Adds what only matters for text that persists: memory, skills, summaries. */
const STRICT: readonly Rule[] = [
  { id: 'persist-order', label: 'tries to install a standing order', pattern: /\b(from now on|in (all )?future (sessions|conversations)|always remember|never forget)\b/ },
  { id: 'conceal-rule', label: 'tells the model to keep a rule secret', pattern: /\b(never|do not|don'?t)\s+(reveal|disclose|share)\b[^.\n]{0,40}\b(this|these|the)\s+(rule|instruction|note|memory)s?\b/ },
  { id: 'url-with-data', label: 'builds a URL that carries private data', pattern: /https?:\/\/[^\s"')]{0,100}[?&][a-z_]*=\s*\$?\{?[a-z_]*(key|token|secret|password|env)/ },
];

const RULES: Readonly<Record<ThreatScope, readonly Rule[]>> = {
  all: ALL,
  context: [...ALL, ...CONTEXT],
  strict: [...ALL, ...CONTEXT, ...STRICT],
};

/** Invisible and direction-changing characters. Checked on raw text, because NFKC would erase some of them. */
const INVISIBLE_CLASS =
  '[\\u00ad\\u034f\\u061c\\u115f\\u1160\\u17b4\\u17b5\\u180e\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u206f\\ufeff\\u3164\\uffa0]|[\\u{e0000}-\\u{e007f}]';
const INVISIBLE = new RegExp(INVISIBLE_CLASS, 'u');
const INVISIBLE_ALL = new RegExp(INVISIBLE_CLASS, 'gu');

/** A small curated table of letters that look like Latin ones. NFKC already folds fullwidth forms. */
const CONFUSABLES: Readonly<Record<string, string>> = {
  а: 'a', с: 'c', ԁ: 'd', е: 'e', һ: 'h', і: 'i', ј: 'j', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', ѕ: 's', т: 't', у: 'y', х: 'x',
  α: 'a', ε: 'e', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x',
  ı: 'i', ɡ: 'g',
};
const CONFUSABLE_RUN = new RegExp(`[${Object.keys(CONFUSABLES).join('')}]`, 'g');

/** Lowercase, NFKC, confusables folded, invisible characters dropped. */
export function normalizeForScan(text: string): string {
  return text
    .replace(INVISIBLE_ALL, '')
    .normalize('NFKC')
    .toLowerCase()
    .replace(CONFUSABLE_RUN, (letter) => CONFUSABLES[letter] ?? letter)
    .replace(/\s+/g, ' ');
}

/** The synchronous core. The worker calls this, and tests may too, but production code uses `scanThreat`. */
export function scanSync(texts: readonly string[], scope: ThreatScope, extra: readonly ExtraPattern[] = []): Finding[] {
  const found = new Map<string, Finding>();
  const rules: Rule[] = [
    ...RULES[scope],
    ...extra.map((e) => ({ id: e.id, label: 'matched a custom pattern', pattern: new RegExp(e.source, e.flags) })),
  ];
  for (const raw of texts) {
    if (INVISIBLE.test(raw)) found.set('invisible-unicode', { id: 'invisible-unicode', label: 'contains invisible or direction-changing characters' });
    const text = normalizeForScan(raw);
    for (const rule of rules) if (rule.pattern.test(text)) found.set(rule.id, { id: rule.id, label: rule.label });
  }
  return [...found.values()];
}

export interface ThreatVerdict {
  /** Only true when the scan finished and found nothing. A timeout, a crash or an oversize input is false. */
  readonly clean: boolean;
  readonly findings: readonly Finding[];
  readonly reason: string | null;
}

export interface ScanOptions {
  readonly timeoutMs?: number;
  /** Total characters allowed. Over the cap is denied, never truncated, because the unscanned tail is where an attack hides. */
  readonly maxChars?: number;
  readonly extra?: readonly ExtraPattern[];
}

const DEFAULT_TIMEOUT_MS = 2_000;
const DEFAULT_MAX_CHARS = 5_000_000;

const deny = (reason: string, findings: readonly Finding[] = []): ThreatVerdict => ({ clean: false, findings, reason });

/**
 * Scans every entry, plus the entries joined with a space and with nothing, so an attack split
 * across two memory entries or two chunks is still one string to the scanner. Runs in a worker
 * with a timeout, and any trouble means deny.
 */
export function scanThreat(entries: string | readonly string[], scope: ThreatScope, options: ScanOptions = {}): Promise<ThreatVerdict> {
  const list = typeof entries === 'string' ? [entries] : [...entries];
  const total = list.reduce((sum, entry) => sum + entry.length, 0);
  if (total > (options.maxChars ?? DEFAULT_MAX_CHARS)) return Promise.resolve(deny('The text is too large to scan, so it was not accepted.'));
  const texts = list.length > 1 ? [...list, list.join(' '), list.join('')] : list;

  return new Promise((resolve) => {
    const worker = new Worker(new URL('./threat-worker.ts', import.meta.url), {
      workerData: { texts, scope, extra: options.extra ?? [] },
    });
    let settled = false;
    const finish = (verdict: ThreatVerdict): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve(verdict);
    };
    const timer = setTimeout(() => finish(deny('The scan timed out, so the text was not accepted.')), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    worker.once('message', (findings: Finding[]) =>
      finish(findings.length === 0 ? { clean: true, findings, reason: null } : deny(`Blocked: ${findings.map((f) => f.label).join('; ')}.`, findings)),
    );
    worker.once('error', () => finish(deny('The scan failed, so the text was not accepted.')));
    worker.once('exit', () => finish(deny('The scan stopped early, so the text was not accepted.')));
  });
}
