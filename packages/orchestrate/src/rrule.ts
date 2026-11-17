/**
 * The RRULE subset schedules use (RFC 5545): FREQ of MINUTELY, HOURLY, DAILY or WEEKLY, with INTERVAL, BYDAY (plain
 * weekdays), BYHOUR, BYMINUTE, COUNT and UNTIL. Times are the machine's local time, to the minute. Anything else is
 * refused rather than half-understood, because a rule read differently from how it was meant runs at the wrong time.
 */

export type Frequency = 'MINUTELY' | 'HOURLY' | 'DAILY' | 'WEEKLY';

export interface RRule {
  readonly freq: Frequency;
  readonly interval: number;
  /** 0 is Sunday, as `Date.getDay`. */
  readonly byDay?: readonly number[];
  readonly byHour?: readonly number[];
  readonly byMinute?: readonly number[];
  readonly count?: number;
  readonly until?: Date;
}

const DAYS = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA'] as const;
const MINUTE = 60_000;
const PERIOD_MS: Readonly<Record<Frequency, number>> = { MINUTELY: MINUTE, HOURLY: 60 * MINUTE, DAILY: 24 * 60 * MINUTE, WEEKLY: 7 * 24 * 60 * MINUTE };
export const MAX_COUNT = 10_000;
/** How many periods one lookup may walk. A rule whose filters never match ends here instead of spinning. */
const MAX_PERIODS = 200_000;

function numbers(value: string, low: number, high: number, name: string): number[] | string {
  const parts = value.split(',');
  const out: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,2}$/.test(part)) return `${name} takes numbers from ${low} to ${high}.`;
    const number = Number(part);
    if (number < low || number > high) return `${name} takes numbers from ${low} to ${high}.`;
    out.push(number);
  }
  return [...new Set(out)].sort((a, b) => a - b);
}

function parseUntil(value: string): Date | string {
  const match = /^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?$/.exec(value);
  if (match === null) return 'UNTIL is YYYYMMDD or YYYYMMDDTHHMMSS(Z).';
  const [, y, mo, d, h = '23', mi = '59', s = '59', z] = match;
  const parts = [Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)] as const;
  const date = z === 'Z' ? new Date(Date.UTC(...parts)) : new Date(...parts);
  return Number.isNaN(date.getTime()) ? 'UNTIL is not a real date.' : date;
}

/** Parses a rule, or returns why it is refused. */
export function parseRRule(text: string): RRule | string {
  const body = text.trim().replace(/^RRULE:/i, '');
  if (body === '' || body.length > 300) return 'A rule is FREQ=...;... and at most 300 characters.';
  const fields = new Map<string, string>();
  for (const part of body.split(';')) {
    const [key, value, extra] = part.split('=');
    if (key === undefined || value === undefined || extra !== undefined || value === '') return `"${part}" is not KEY=VALUE.`;
    const name = key.toUpperCase();
    if (fields.has(name)) return `${name} is given twice.`;
    fields.set(name, value.toUpperCase());
  }
  for (const name of fields.keys()) {
    if (!['FREQ', 'INTERVAL', 'BYDAY', 'BYHOUR', 'BYMINUTE', 'COUNT', 'UNTIL'].includes(name)) return `${name} is not supported. Use FREQ, INTERVAL, BYDAY, BYHOUR, BYMINUTE, COUNT and UNTIL.`;
  }
  const freq = fields.get('FREQ');
  if (freq !== 'MINUTELY' && freq !== 'HOURLY' && freq !== 'DAILY' && freq !== 'WEEKLY') return 'FREQ is one of MINUTELY, HOURLY, DAILY, WEEKLY.';
  const rule: { -readonly [K in keyof RRule]: RRule[K] } = { freq, interval: 1 };
  const interval = fields.get('INTERVAL');
  if (interval !== undefined) {
    if (!/^\d{1,4}$/.test(interval) || Number(interval) < 1 || Number(interval) > 1000) return 'INTERVAL is a whole number from 1 to 1000.';
    rule.interval = Number(interval);
  }
  const byDay = fields.get('BYDAY');
  if (byDay !== undefined) {
    const days: number[] = [];
    for (const day of byDay.split(',')) {
      const index = (DAYS as readonly string[]).indexOf(day);
      if (index === -1) return 'BYDAY takes plain weekdays: MO,TU,WE,TH,FR,SA,SU.';
      days.push(index);
    }
    rule.byDay = [...new Set(days)].sort((a, b) => a - b);
  }
  for (const [name, low, high, key] of [['BYHOUR', 0, 23, 'byHour'], ['BYMINUTE', 0, 59, 'byMinute']] as const) {
    const value = fields.get(name);
    if (value === undefined) continue;
    const parsed = numbers(value, low, high, name);
    if (typeof parsed === 'string') return parsed;
    rule[key] = parsed;
  }
  const count = fields.get('COUNT');
  if (count !== undefined) {
    if (!/^\d{1,5}$/.test(count) || Number(count) < 1 || Number(count) > MAX_COUNT) return `COUNT is a whole number from 1 to ${MAX_COUNT}.`;
    rule.count = Number(count);
  }
  const until = fields.get('UNTIL');
  if (until !== undefined) {
    const parsed = parseUntil(until);
    if (typeof parsed === 'string') return parsed;
    rule.until = parsed;
  }
  if (rule.count !== undefined && rule.until !== undefined) return 'Give COUNT or UNTIL, not both.';
  return rule;
}

/** The start of period `k`, in local time. Weeks start on Monday. */
function periodStart(rule: RRule, start: Date, k: number): Date {
  const date = new Date(start.getTime());
  date.setSeconds(0, 0);
  const step = k * rule.interval;
  if (rule.freq === 'MINUTELY') date.setMinutes(date.getMinutes() + step);
  else if (rule.freq === 'HOURLY') date.setHours(date.getHours() + step, 0);
  else if (rule.freq === 'DAILY') {
    date.setHours(0, 0);
    date.setDate(date.getDate() + step);
  } else {
    date.setHours(0, 0);
    date.setDate(date.getDate() - ((date.getDay() + 6) % 7) + step * 7);
  }
  return date;
}

/** Every candidate time in one period, in order, before the start and filters are applied. */
function candidates(rule: RRule, start: Date, period: Date): Date[] {
  if (rule.freq === 'MINUTELY') return [period];
  const minutes = rule.byMinute ?? [start.getMinutes()];
  if (rule.freq === 'HOURLY') return minutes.map((minute) => new Date(period.getFullYear(), period.getMonth(), period.getDate(), period.getHours(), minute));
  const hours = rule.byHour ?? [start.getHours()];
  const days = rule.freq === 'DAILY' ? [0] : (rule.byDay ?? [start.getDay()]).map((day) => (day + 6) % 7).sort((a, b) => a - b);
  const out: Date[] = [];
  for (const offset of days) for (const hour of hours) for (const minute of minutes) out.push(new Date(period.getFullYear(), period.getMonth(), period.getDate() + offset, hour, minute));
  return out;
}

function matches(rule: RRule, date: Date): boolean {
  if (rule.byDay !== undefined && !rule.byDay.includes(date.getDay())) return false;
  if (rule.byHour !== undefined && !rule.byHour.includes(date.getHours())) return false;
  if (rule.byMinute !== undefined && !rule.byMinute.includes(date.getMinutes())) return false;
  return true;
}

/**
 * Occurrences after `after` (exclusive) up to `until` (inclusive), at most `limit`. COUNT is counted from the start, so a
 * rule with COUNT is walked from its first period; one without may jump close to `after`.
 */
export function occurrences(rule: RRule, start: Date, after: Date, until: Date, limit: number): Date[] {
  const out: Date[] = [];
  const first = new Date(start.getTime());
  first.setSeconds(0, 0);
  let k = rule.count !== undefined ? 0 : Math.max(0, Math.floor((after.getTime() - first.getTime()) / (PERIOD_MS[rule.freq] * rule.interval)) - 2);
  let seen = 0;
  for (let walked = 0; walked < MAX_PERIODS && out.length < limit; walked += 1, k += 1) {
    const period = periodStart(rule, first, k);
    if (period.getTime() > until.getTime() || (rule.until !== undefined && period.getTime() > rule.until.getTime())) break;
    for (const time of candidates(rule, first, period)) {
      if (time.getTime() < first.getTime() || !matches(rule, time)) continue;
      if (rule.until !== undefined && time.getTime() > rule.until.getTime()) return out;
      seen += 1;
      if (rule.count !== undefined && seen > rule.count) return out;
      if (time.getTime() > after.getTime() && time.getTime() <= until.getTime()) {
        out.push(time);
        if (out.length >= limit) return out;
      }
    }
  }
  return out;
}

/** The first occurrence after `after`, or null when the rule has ended (or none falls in the next ten years). */
export function nextOccurrence(rule: RRule, start: Date, after: Date): Date | null {
  return occurrences(rule, start, after, new Date(after.getTime() + 3_650 * 24 * 60 * MINUTE), 1)[0] ?? null;
}
