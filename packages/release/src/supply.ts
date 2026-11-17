/**
 * Supply-chain checks on the agent itself. The lockfile must pin every package by an
 * integrity hash, and a package version must have been public for a while before it is used (the release-age
 * delay pnpm also enforces at install), so a freshly hijacked release cannot reach a build the same day.
 */

export interface LockedPackage {
  readonly name: string;
  readonly version: string;
  readonly integrity: string | null;
}

/** The `packages:` section of a pnpm v9 lockfile: one entry per name@version, with its integrity. */
export function lockedPackages(lockfile: string): LockedPackage[] {
  const section = lockfile.split(/\r?\n(?=\S)/).find((block) => block.startsWith('packages:'));
  if (section === undefined) return [];
  const out: LockedPackage[] = [];
  for (const block of section.split(/\r?\n\r?\n/)) {
    const head = /^\s{2}'?((?:@[^/@'\s]+\/)?[^@'\s]+)@([^':\s]+)'?:/m.exec(block);
    if (head === null) continue;
    const integrity = /integrity: (sha\d+-[A-Za-z0-9+/=]+)/.exec(block)?.[1] ?? null;
    out.push({ name: head[1] as string, version: head[2] as string, integrity });
  }
  return out;
}

/** Packages whose integrity is missing or weaker than sha512. */
export const unpinned = (packages: readonly LockedPackage[]): LockedPackage[] => packages.filter((item) => item.integrity === null || !item.integrity.startsWith('sha512-'));

/** Packages published less than `days` before `now`, given each one's publish time; an unknown time counts as too young. */
export function tooYoung(packages: readonly LockedPackage[], published: ReadonlyMap<string, string>, now: number, days: number): LockedPackage[] {
  return packages.filter((item) => {
    const time = published.get(`${item.name}@${item.version}`);
    return time === undefined || Number.isNaN(Date.parse(time)) || now - Date.parse(time) < days * 86_400_000;
  });
}
