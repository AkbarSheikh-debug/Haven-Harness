import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdir, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { Origin } from '@hn/core';
import { occurrences, parseRRule } from './rrule.ts';

export const MAX_SCHEDULES = 100;
export const MAX_SCHEDULE_PROMPT = 8_000;
/** A missed run inside this window runs once when hn next looks; older ones are skipped and noted. */
export const DEFAULT_CATCH_UP_MS = 6 * 60 * 60_000;
/** A scheduled run is stopped after this long with nothing happening, measured as idle, not wall clock. */
export const SCHEDULE_IDLE_MS = 600_000;
const STORE_VERSION = 1;
const LOCK_STALE_MS = 10 * 60_000;

export interface Schedule {
  readonly id: string;
  readonly name: string;
  readonly rrule: string;
  /** ISO time the rule counts from. */
  readonly dtstart: string;
  readonly prompt: string;
  /** The project folder the run works in. */
  readonly workdir: string;
  /** What the unattended (`dont-ask`) run may do without asking: shown on the card when the schedule was made. */
  readonly allow: readonly string[];
  readonly model?: string;
  readonly baseUrl?: string;
  readonly window?: number;
  /** Who wrote the prompt. A model-written one is never `user`, so the run never treats it as a person's words. */
  readonly origin: Origin;
  /** The session that made it, or `cli`. */
  readonly createdBy: string;
  readonly createdAt: string;
  readonly enabled: boolean;
  readonly catchUpMs: number;
  /** The newest occurrence already run or skipped, so each occurrence happens at most once. */
  readonly lastRun: string | null;
}

export interface StoreLoad {
  readonly schedules: readonly Schedule[];
  /** Entries whose signature does not verify: edited outside hn, or forged. They never run. */
  readonly rejected: readonly { readonly id: string; readonly why: string }[];
}

const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};

/** Checks a schedule's fields; null when it is well formed. */
export function scheduleProblem(schedule: Schedule): string | null {
  if (!/^[a-z0-9]{6,16}$/.test(schedule.id)) return 'bad id';
  if (typeof schedule.name !== 'string' || !/^[\w .-]{1,64}$/.test(schedule.name)) return 'A schedule name is 1 to 64 letters, digits, spaces, dots, dashes or underscores.';
  const rule = parseRRule(schedule.rrule);
  if (typeof rule === 'string') return rule;
  if (Number.isNaN(Date.parse(schedule.dtstart))) return 'dtstart is not a time.';
  if (typeof schedule.prompt !== 'string' || schedule.prompt.trim() === '' || schedule.prompt.length > MAX_SCHEDULE_PROMPT) return `A schedule's prompt is 1 to ${MAX_SCHEDULE_PROMPT} characters.`;
  if (!Array.isArray(schedule.allow) || !schedule.allow.every((name) => typeof name === 'string' && /^[\w:.-]{1,64}$/.test(name))) return 'allow is a list of tool names.';
  if (!(Number.isSafeInteger(schedule.catchUpMs) && schedule.catchUpMs >= 0 && schedule.catchUpMs <= 7 * 24 * 60 * 60_000)) return 'The catch-up window is at most a week.';
  return null;
}

/** A new schedule id: short, random, lower case. */
export const newScheduleId = (): string => randomBytes(5).toString('hex');

/**
 * The schedules, in one user-level file, every entry HMACed with the log key, so an entry written by
 * anything but hn (a tool's shell, a planted file) does not verify and never runs. Writes are atomic and under a lock.
 */
export class ScheduleStore {
  readonly #path: string;
  readonly #key: Buffer;

  constructor(path: string, key: Buffer) {
    this.#path = path;
    this.#key = key;
  }

  get path(): string {
    return this.#path;
  }

  #mac(schedule: Schedule): string {
    return createHmac('sha256', this.#key).update(canonical(schedule)).digest('base64url');
  }

  #verify(schedule: Schedule, mac: unknown): boolean {
    if (typeof mac !== 'string') return false;
    const want = Buffer.from(this.#mac(schedule));
    const given = Buffer.from(mac);
    return want.length === given.length && timingSafeEqual(want, given);
  }

  async load(): Promise<StoreLoad> {
    const text = await readFile(this.#path, 'utf8').catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (text === null) return { schedules: [], rejected: [] };
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return { schedules: [], rejected: [{ id: '?', why: 'the schedules file is not JSON' }] };
    }
    const entries = typeof parsed === 'object' && parsed !== null && (parsed as Record<string, unknown>)['v'] === STORE_VERSION ? (parsed as Record<string, unknown>)['entries'] : null;
    if (!Array.isArray(entries)) return { schedules: [], rejected: [{ id: '?', why: 'the schedules file is not one hn wrote' }] };
    const schedules: Schedule[] = [];
    const rejected: { id: string; why: string }[] = [];
    for (const entry of entries.slice(0, MAX_SCHEDULES * 2)) {
      const schedule = (entry as Record<string, unknown> | null)?.['schedule'] as Schedule | undefined;
      const id = typeof schedule?.id === 'string' ? schedule.id : '?';
      if (schedule === undefined || typeof schedule !== 'object') rejected.push({ id, why: 'not a schedule' });
      else if (!this.#verify(schedule, (entry as Record<string, unknown>)['mac'])) rejected.push({ id, why: 'its signature does not verify: it was changed outside hn' });
      else if (scheduleProblem(schedule) !== null) rejected.push({ id, why: scheduleProblem(schedule) as string });
      else schedules.push(schedule);
    }
    return { schedules, rejected };
  }

  /** Changes the store under its lock: `change` gets the verified schedules and returns the new list. Rejected entries are dropped. */
  async update<T>(change: (schedules: readonly Schedule[]) => { readonly schedules: readonly Schedule[]; readonly result: T }): Promise<T> {
    const lock = `${this.#path}.lock`;
    await mkdir(dirname(this.#path), { recursive: true, mode: 0o700 });
    await takeLock(lock);
    try {
      const { schedules } = await this.load();
      const next = change(schedules);
      if (next.schedules.length > MAX_SCHEDULES) throw new Error(`There may be at most ${MAX_SCHEDULES} schedules.`);
      for (const schedule of next.schedules) {
        const problem = scheduleProblem(schedule);
        if (problem !== null) throw new Error(problem);
      }
      const body = JSON.stringify({ v: STORE_VERSION, entries: next.schedules.map((schedule) => ({ schedule, mac: this.#mac(schedule) })) }, null, 1);
      const temporary = `${this.#path}.${process.pid}.tmp`;
      await writeFile(temporary, body, { mode: 0o600 });
      await rename(temporary, this.#path);
      return next.result;
    } finally {
      await rm(lock, { force: true });
    }
  }
}

async function takeLock(path: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      const handle = await open(path, 'wx');
      await handle.close();
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      // A lock left by a process that died long ago is taken over.
      const info = await stat(path).catch(() => null);
      if (info !== null && Date.now() - info.mtimeMs > LOCK_STALE_MS) await rm(path, { force: true });
      else await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  throw new Error('The schedules file is locked by another hn.');
}

export interface DueDecision {
  /** The occurrence to run now, or null. */
  readonly run: Date | null;
  /** Occurrences passed over: older missed ones, or one outside the catch-up window. */
  readonly skipped: number;
  /** What `lastRun` becomes. Null when nothing changed. */
  readonly lastRun: Date | null;
  readonly note?: string;
}

/**
 * What to do about a schedule now. Only the newest missed occurrence can run, and only inside the catch-up window, so a
 * laptop that slept through six runs runs once, not six times; a run missed by more than the window is skipped and said.
 */
export function dueDecision(schedule: Schedule, now: Date): DueDecision {
  const rule = parseRRule(schedule.rrule);
  if (typeof rule === 'string' || !schedule.enabled) return { run: null, skipped: 0, lastRun: null };
  // Occurrences are whole minutes, so the start is too: otherwise a start at 10:00:30 would never run its 10:00 occurrence.
  const start = new Date(schedule.dtstart);
  start.setSeconds(0, 0);
  const after = schedule.lastRun === null ? new Date(start.getTime() - 1) : new Date(schedule.lastRun);
  const missed = occurrences(rule, start, after, now, 10_000);
  const latest = missed.at(-1);
  if (latest === undefined) return { run: null, skipped: 0, lastRun: null };
  if (now.getTime() - latest.getTime() > schedule.catchUpMs) {
    return { run: null, skipped: missed.length, lastRun: latest, note: `missed ${missed.length} run(s), the newest at ${latest.toISOString()}, outside the catch-up window, so none was run` };
  }
  return { run: latest, skipped: missed.length - 1, lastRun: latest, ...(missed.length > 1 ? { note: `${missed.length - 1} older missed run(s) were skipped; only the newest runs` } : {}) };
}

export interface IdleWatchdogOptions {
  readonly idleMs: number;
  /** Something that changes whenever there is activity, such as the length of the session's log. */
  readonly activity: () => number;
  readonly onIdle: () => void;
  readonly checkEveryMs?: number;
  readonly now?: () => number;
}

/** Stops a run that has done nothing for `idleMs` (idle, not wall clock: a long run that keeps working is never stopped). */
export function startIdleWatchdog(options: IdleWatchdogOptions): { stop(): void; readonly fired: boolean } {
  const now = options.now ?? Date.now;
  let last = options.activity();
  let lastChange = now();
  let fired = false;
  const timer = setInterval(() => {
    const current = options.activity();
    if (current !== last) {
      last = current;
      lastChange = now();
      return;
    }
    if (!fired && now() - lastChange >= options.idleMs) {
      fired = true;
      options.onIdle();
    }
  }, options.checkEveryMs ?? Math.min(15_000, Math.max(10, Math.floor(options.idleMs / 4))));
  timer.unref?.();
  return {
    stop: () => clearInterval(timer),
    get fired() {
      return fired;
    },
  };
}

/** Where schedules live: user level only, never the project. */
export const schedulesFile = (home: string): string => join(home, 'schedules.json');
export const scheduleRunsFile = (home: string): string => join(home, 'schedules', 'runs.jsonl');
