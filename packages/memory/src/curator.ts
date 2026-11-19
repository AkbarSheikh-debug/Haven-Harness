import { readdir, rename, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { parseSkill } from '@hn/context';
import { atomicWrite, readOrNull, withLock } from './disk.ts';

/** 10.7: runs on idleness, not on a clock. */
export const CURATOR = { intervalHours: 168, minIdleHours: 2, staleDays: 30, archiveDays: 90 } as const;

type SkillState = 'active' | 'stale' | 'archived';
interface UsageEntry {
  readonly lastUsed: string | null;
  readonly uses: number;
  readonly state: SkillState;
}
interface Usage {
  readonly v: 1;
  readonly lastRun: string | null;
  readonly skills: Readonly<Record<string, UsageEntry>>;
}

const usagePath = (root: string): string => join(root, '.usage.json');
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

async function readUsage(root: string): Promise<Usage> {
  try {
    const raw = JSON.parse((await readOrNull(usagePath(root))) ?? '') as Usage;
    if (raw.v !== 1 || typeof raw.skills !== 'object' || raw.skills === null) throw new Error('bad');
    const skills = Object.create(null) as Record<string, UsageEntry>;
    for (const [name, entry] of Object.entries(raw.skills)) {
      if (/^[a-z0-9][a-z0-9-]{0,63}$/.test(name) && typeof entry?.uses === 'number') skills[name] = entry;
    }
    return { v: 1, lastRun: typeof raw.lastRun === 'string' ? raw.lastRun : null, skills };
  } catch {
    return { v: 1, lastRun: null, skills: Object.create(null) as Record<string, UsageEntry> };
  }
}

/** Telemetry for the curator: one more use of a skill, written atomically under a lock. */
export async function recordSkillUse(root: string, name: string, now: Date): Promise<void> {
  await withLock(usagePath(root), async () => {
    const usage = await readUsage(root);
    const before = usage.skills[name];
    const skills = { ...usage.skills, [name]: { lastUsed: now.toISOString(), uses: (before?.uses ?? 0) + 1, state: 'active' as const } };
    await atomicWrite(usagePath(root), JSON.stringify({ ...usage, skills }, null, 1));
  });
}

export interface CuratorReport {
  readonly ran: boolean;
  readonly why: string;
  readonly stale: readonly string[];
  readonly archived: readonly string[];
}

export interface CuratorInput {
  /** `~/.hn/skills`. */
  readonly root: string;
  readonly now: Date;
  /** When the user last did anything: the newest session activity. */
  readonly lastActivity: Date | null;
}

/**
 * The curator (10.7). Only skills that say `created_by: agent` are touched, and never a pinned or locked
 * one. Unused for 30 days: marked stale. For 90: moved to `.archive/`, from where `restoreArchived`
 * brings it back. Nothing is ever deleted. "A learning loop without a curator is a hoarding loop."
 */
export async function runCurator(input: CuratorInput): Promise<CuratorReport> {
  const usage = await readUsage(input.root);
  const now = input.now.getTime();
  if (usage.lastRun !== null && now - Date.parse(usage.lastRun) < CURATOR.intervalHours * HOUR) return { ran: false, why: 'ran less than a week ago', stale: [], archived: [] };
  if (input.lastActivity !== null && now - input.lastActivity.getTime() < CURATOR.minIdleHours * HOUR) return { ran: false, why: 'not idle for two hours', stale: [], archived: [] };
  const stale: string[] = [];
  const archived: string[] = [];
  const skills: Record<string, UsageEntry> = { ...usage.skills };
  for (const entry of await readdir(input.root, { withFileTypes: true }).catch(() => [])) {
    if (!entry.isDirectory() || entry.isSymbolicLink() || entry.name.startsWith('.')) continue;
    const folder = join(input.root, entry.name);
    const text = await readOrNull(join(folder, 'SKILL.md'));
    if (text === null) continue;
    const meta = parseSkill(text).meta;
    if (meta === null || meta.createdBy !== 'agent' || meta.pinned || meta.locked) continue;
    const seen = skills[entry.name]?.lastUsed;
    const since = seen === null || seen === undefined ? (await stat(join(folder, 'SKILL.md'))).mtimeMs : Date.parse(seen);
    const idleDays = (now - since) / DAY;
    if (idleDays >= CURATOR.archiveDays) {
      await rename(folder, join(input.root, '.archive', entry.name)).catch(async (error: NodeJS.ErrnoException) => {
        if (error.code !== 'ENOENT') throw error;
        const { mkdir } = await import('node:fs/promises');
        await mkdir(join(input.root, '.archive'), { recursive: true, mode: 0o700 });
        await rename(folder, join(input.root, '.archive', entry.name));
      });
      skills[entry.name] = { lastUsed: seen ?? null, uses: skills[entry.name]?.uses ?? 0, state: 'archived' };
      archived.push(entry.name);
    } else if (idleDays >= CURATOR.staleDays) {
      skills[entry.name] = { lastUsed: seen ?? null, uses: skills[entry.name]?.uses ?? 0, state: 'stale' };
      stale.push(entry.name);
    }
  }
  await withLock(usagePath(input.root), () => atomicWrite(usagePath(input.root), JSON.stringify({ v: 1, lastRun: input.now.toISOString(), skills }, null, 1)));
  return { ran: true, why: 'idle, and a week since the last run', stale, archived };
}

/** Brings an archived skill back into use. */
export async function restoreArchived(root: string, name: string, now: Date): Promise<void> {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) throw new Error('The skill name is not valid.');
  if ((await readOrNull(join(root, name, 'SKILL.md'))) !== null) throw new Error(`A skill named ${name} is already in use.`);
  await rename(join(root, '.archive', name), join(root, name));
  await recordSkillUse(root, name, now);
}
