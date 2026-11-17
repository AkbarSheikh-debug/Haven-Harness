import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { lockedPackages, tooYoung, unpinned } from '@hn/release';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));

describe('the supply chain of hn itself', () => {
  it('keeps the install rules: no install scripts run, and new releases wait at least 7 days', async () => {
    const workspace = await readFile(`${ROOT}pnpm-workspace.yaml`, 'utf8');
    assert.match(workspace, /^onlyBuiltDependencies: \[\]$/m, 'no dependency may run install scripts');
    const age = Number(/^minimumReleaseAge: (\d+)$/m.exec(workspace)?.[1]);
    assert.ok(age >= 7 * 24 * 60, `minimumReleaseAge is ${age} minutes, less than 7 days`);
  });

  it('pins every locked package by a sha512 integrity hash', async () => {
    const packages = lockedPackages(await readFile(`${ROOT}pnpm-lock.yaml`, 'utf8'));
    assert.ok(packages.length >= 10, `only ${packages.length} packages were read from the lockfile`);
    assert.ok(packages.some((item) => item.name === '@anthropic-ai/sdk'));
    assert.deepEqual(unpinned(packages), []);
  });

  it('finds a package that is too young, one with no known publish time, and a weak or missing hash', () => {
    const lock = ["lockfileVersion: '9.0'", '', 'packages:', '', "  '@scope/old@1.0.0':", '    resolution: {integrity: sha512-AAAA}', '', '  fresh@2.0.0:', '    resolution: {integrity: sha512-BBBB}', '', '  weak@1.0.0:', '    resolution: {integrity: sha1-CCCC}', '', '  none@1.0.0:', '    resolution: {tarball: https://example.com/none.tgz}', ''].join('\n');
    const packages = lockedPackages(lock);
    assert.deepEqual(packages.map((item) => `${item.name}@${item.version}`), ['@scope/old@1.0.0', 'fresh@2.0.0', 'weak@1.0.0', 'none@1.0.0']);
    assert.deepEqual(unpinned(packages).map((item) => item.name), ['weak', 'none']);
    const now = Date.parse('2026-11-17T00:00:00Z');
    const published = new Map([['@scope/old@1.0.0', '2026-01-01T00:00:00Z'], ['fresh@2.0.0', '2026-11-15T00:00:00Z'], ['weak@1.0.0', '2025-01-01T00:00:00Z']]);
    assert.deepEqual(tooYoung(packages, published, now, 7).map((item) => item.name), ['fresh', 'none']);
  });
});
