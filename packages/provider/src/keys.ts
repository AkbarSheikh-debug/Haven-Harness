import { ProviderError } from './errors.ts';

export const KEY_ENV_NAMES = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'DEEPSEEK_API_KEY', 'OPENROUTER_API_KEY'] as const;

export type KeyName = (typeof KEY_ENV_NAMES)[number];

const REDACTED = '[REDACTED]';

/**
 * Takes keys out of the environment at startup, so no child process can inherit them.
 * This is the Phase 1 store. The OS keychain replaces it in Phase 2.
 */
export class KeyStore {
  #keys = new Map<KeyName, string>();

  /** Moves every known key out of `env`. Call it once, before anything is spawned. */
  static capture(env: NodeJS.ProcessEnv = process.env): KeyStore {
    const store = new KeyStore();
    for (const name of KEY_ENV_NAMES) {
      const value = env[name];
      delete env[name];
      if (value !== undefined && value !== '') store.#keys.set(name, value);
    }
    return store;
  }

  /**
   * The keys as JSON, for a child harness's standard input. Never its environment: on Linux a process's starting
   * environment stays readable at /proc/<pid>/environ even after the variable is deleted.
   */
  toHandoff(): string {
    return JSON.stringify(Object.fromEntries(this.#keys));
  }

  /** The child's end of the hand-off: known key names only, everything else ignored. */
  static fromHandoff(text: string): KeyStore {
    const store = new KeyStore();
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return store;
    for (const name of KEY_ENV_NAMES) {
      const value = (parsed as Record<string, unknown>)[name];
      if (typeof value === 'string' && value !== '') store.#keys.set(name, value);
    }
    return store;
  }

  has(name: KeyName): boolean {
    return this.#keys.has(name);
  }

  get(name: KeyName): string {
    const key = this.#keys.get(name);
    if (key === undefined) throw new ProviderError('auth', `${name} is not set.`);
    return key;
  }

  /** Removes every held key from text bound for a log, a screen or a report. */
  redact(text: string): string {
    let clean = text;
    for (const key of this.#keys.values()) clean = clean.replaceAll(key, REDACTED);
    return clean;
  }
}
