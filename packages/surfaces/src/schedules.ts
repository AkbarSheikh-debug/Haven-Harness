import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolvePaths } from '@hn/config';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { DEFAULT_CATCH_UP_MS, SCHEDULE_IDLE_MS, ScheduleStore, dueDecision, newScheduleId, nextOccurrence, parseRRule, scheduleRunsFile, schedulesFile, startIdleWatchdog, type Schedule } from '@hn/orchestrate';
import type { KeyStore } from '@hn/provider';
import { loadOrCreateLogKey } from '@hn/session';
import { Harness, type HarnessOptions } from './harness.ts';

export interface ScheduleRun {
  readonly id: string;
  readonly name: string;
  readonly status: 'ran' | 'skipped' | 'refused';
  readonly occurrence?: string;
  readonly sessionId?: string;
  readonly end?: string;
  /** True when the idle watchdog stopped it. */
  readonly idleStopped?: boolean;
  readonly note?: string;
}

export interface RunDueOptions {
  readonly keys: KeyStore;
  readonly env?: NodeJS.ProcessEnv;
  readonly now?: Date;
  /** 600 s with nothing happening. Tests use less. */
  readonly idleMs?: number;
  /** Model settings for schedules that name none. */
  readonly defaults?: Pick<HarnessOptions, 'model' | 'baseUrl' | 'window'>;
  /** Tests only: added to each run's harness. */
  readonly extras?: Partial<HarnessOptions>;
}

async function storeFor(env?: NodeJS.ProcessEnv): Promise<{ store: ScheduleStore; home: string }> {
  const paths = resolvePaths(env);
  return { store: new ScheduleStore(schedulesFile(paths.home), await loadOrCreateLogKey(paths.logKey)), home: paths.home };
}

/**
 * `hn schedule run-due`, which the OS scheduler calls: every due schedule runs once, one after another, as
 * an unattended root session in its project: `dont-ask` with the allowlist shown when it was made, its prompt with the
 * origin of whoever wrote it (a model-written one is never `user`), stopped by the idle watchdog. Each occurrence is
 * marked as run before it starts, so a crash never makes it run twice. An entry that does not verify never runs.
 */
export async function runDueSchedules(options: RunDueOptions): Promise<ScheduleRun[]> {
  const { store, home } = await storeFor(options.env);
  const now = options.now ?? new Date();
  const { schedules, rejected } = await store.load();
  const reports: ScheduleRun[] = rejected.map((entry) => ({ id: entry.id, name: '?', status: 'refused' as const, note: entry.why }));
  for (const schedule of schedules) {
    const decision = dueDecision(schedule, now);
    if (decision.lastRun === null) continue;
    const lastRun = decision.lastRun.toISOString();
    const still = await store.update((list) => {
      const found = list.find((entry) => entry.id === schedule.id);
      return found === undefined ? { schedules: list, result: false } : { schedules: list.map((entry) => (entry.id === schedule.id ? { ...entry, lastRun } : entry)), result: true };
    });
    if (!still) continue;
    if (decision.run === null) {
      reports.push({ id: schedule.id, name: schedule.name, status: 'skipped', ...(decision.note === undefined ? {} : { note: decision.note }) });
      continue;
    }
    reports.push(await runOne(schedule, decision.run, options, decision.note));
  }
  if (reports.length > 0) {
    const file = scheduleRunsFile(home);
    await mkdir(dirname(file), { recursive: true, mode: 0o700 });
    await appendFile(file, reports.map((report) => `${JSON.stringify({ ts: now.toISOString(), ...report })}\n`).join(''), { mode: 0o600 });
  }
  return reports;
}

async function runOne(schedule: Schedule, occurrence: Date, options: RunDueOptions, note?: string): Promise<ScheduleRun> {
  const model = schedule.model ?? options.defaults?.model;
  const baseUrl = schedule.baseUrl ?? options.defaults?.baseUrl;
  const window = schedule.window ?? options.defaults?.window;
  const harness = new Harness({
    ...options.extras,
    workdir: schedule.workdir,
    mode: 'dont-ask',
    allow: schedule.allow,
    keys: options.keys,
    verify: 'off',
    control: true,
    ...(options.env === undefined ? {} : { env: options.env }),
    ...(model === undefined ? {} : { model }),
    ...(baseUrl === undefined ? {} : { baseUrl }),
    ...(window === undefined ? {} : { window }),
  });
  const base = { id: schedule.id, name: schedule.name, occurrence: occurrence.toISOString(), ...(note === undefined ? {} : { note }) };
  let watchdog: ReturnType<typeof startIdleWatchdog> | null = null;
  try {
    const session = await harness.open();
    watchdog = startIdleWatchdog({ idleMs: options.idleMs ?? SCHEDULE_IDLE_MS, activity: () => session.agent.events.length, onIdle: () => harness.stop() });
    const result = await harness.run(schedule.prompt, { origin: schedule.origin === 'user' ? 'user' : schedule.origin === 'harness' || schedule.origin === 'human-selected' ? 'model-derived' : schedule.origin });
    return { ...base, status: 'ran', sessionId: result.sessionId, end: result.end, idleStopped: watchdog.fired };
  } catch (error) {
    return { ...base, status: 'refused', note: error instanceof Error ? error.message : String(error) };
  } finally {
    watchdog?.stop();
    await harness.close();
  }
}

/** What `hn schedule install` prints: the line for the OS scheduler. hn never installs it itself. */
export function installInstructions(platform: NodeJS.Platform = process.platform): string {
  const node = process.execPath;
  const main = fileURLToPath(new URL('./main.ts', import.meta.url));
  if (platform === 'win32') {
    return `hn does not install this for you. To run due schedules every 5 minutes, run this once in a terminal:\n  schtasks /Create /SC MINUTE /MO 5 /TN hn-schedules /TR "\\"${node}\\" --disable-proto=throw \\"${main}\\" schedule run-due"\nRemove it with: schtasks /Delete /TN hn-schedules\n`;
  }
  return `hn does not install this for you. To run due schedules every 5 minutes, add this line with crontab -e:\n  */5 * * * * "${node}" --disable-proto=throw "${main}" schedule run-due\n`;
}

export interface ScheduleCommandContext {
  readonly positionals: readonly string[];
  readonly nested: boolean;
  readonly keys: KeyStore;
  readonly flags: Readonly<Record<string, string | boolean | undefined>>;
  readonly defaults: Pick<HarnessOptions, 'model' | 'baseUrl' | 'window'>;
  readonly out: (text: string) => void;
}

/** `hn schedule list|add|remove|run-due|install`. A schedule typed here by the person is `user`; it runs in this folder. */
export async function runScheduleCommand(context: ScheduleCommandContext): Promise<number | null> {
  const [command, sub, ...rest] = context.positionals;
  if (command !== 'schedule') return null;
  if (context.nested) throw new HnError('NESTED_HN', 'hn schedule cannot be used from inside an hn session.');
  const out = (text: string): void => context.out(`${sanitizeForDisplay(text)}\n`);
  if (sub === 'install') {
    context.out(installInstructions());
    return 0;
  }
  const { store } = await storeFor();
  if (sub === 'list' || sub === undefined) {
    const { schedules, rejected } = await store.load();
    if (schedules.length === 0 && rejected.length === 0) out('No schedules.');
    for (const schedule of schedules) {
      const rule = parseRRule(schedule.rrule);
      const next = typeof rule === 'string' || !schedule.enabled ? null : nextOccurrence(rule, new Date(schedule.dtstart), new Date());
      out(`${schedule.id} "${schedule.name}" ${schedule.rrule} in ${schedule.workdir}; next ${next === null ? 'none' : next.toString()}; allow ${schedule.allow.join(',') || 'nothing'}; written by ${schedule.origin}`);
    }
    for (const entry of rejected) out(`${entry.id}: will not run: ${entry.why}`);
    return 0;
  }
  if (sub === 'add') {
    const name = context.flags['name'];
    const rrule = context.flags['rrule'];
    const prompt = rest.join(' ');
    if (typeof name !== 'string' || typeof rrule !== 'string' || prompt.trim() === '') throw new HnError('USAGE', 'Use: hn schedule add --name <name> --rrule <rule> [--allow tools] [--start <iso>] <prompt>');
    const rule = parseRRule(rrule);
    if (typeof rule === 'string') throw new HnError('USAGE', `--rrule: ${rule}`);
    const start = typeof context.flags['start'] === 'string' ? new Date(context.flags['start']) : new Date();
    if (Number.isNaN(start.getTime())) throw new HnError('USAGE', '--start takes an ISO time.');
    const schedule: Schedule = {
      id: newScheduleId(),
      name,
      rrule: rrule.replace(/^RRULE:/i, ''),
      dtstart: start.toISOString(),
      prompt,
      workdir: process.cwd(),
      allow: typeof context.flags['allow'] === 'string' ? context.flags['allow'].split(',') : [],
      ...(context.defaults.model === undefined ? {} : { model: context.defaults.model }),
      ...(context.defaults.baseUrl === undefined ? {} : { baseUrl: context.defaults.baseUrl }),
      ...(context.defaults.window === undefined ? {} : { window: context.defaults.window }),
      origin: 'user',
      createdBy: 'cli',
      createdAt: new Date().toISOString(),
      enabled: true,
      catchUpMs: DEFAULT_CATCH_UP_MS,
      lastRun: null,
    };
    await store.update((list) => ({ schedules: [...list, schedule], result: null }));
    out(`Added schedule ${schedule.id}. It runs when hn schedule run-due is called; see hn schedule install.`);
    return 0;
  }
  if (sub === 'remove') {
    const id = rest[0] ?? '';
    const removed = await store.update((list) => ({ schedules: list.filter((entry) => entry.id !== id), result: list.some((entry) => entry.id === id) }));
    out(removed ? `Removed ${id}.` : `There is no schedule ${id}.`);
    return removed ? 0 : 1;
  }
  if (sub === 'run-due') {
    const reports = await runDueSchedules({ keys: context.keys, defaults: context.defaults });
    for (const report of reports) out(`${report.id} "${report.name}": ${report.status}${report.end === undefined ? '' : ` (${report.end})`}${report.idleStopped === true ? ', stopped as idle' : ''}${report.note === undefined ? '' : `; ${report.note}`}`);
    return reports.some((report) => report.status === 'refused') ? 1 : 0;
  }
  throw new HnError('USAGE', 'Use: hn schedule list | add | remove <id> | run-due | install');
}
