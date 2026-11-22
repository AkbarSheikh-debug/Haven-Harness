import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import { RosterError, activeKeys, loadTrust, offerRoster } from '@hn/security';
import type { BrokerConfig } from './config.ts';

/**
 * The policy signing keys the broker trusts now (Phase 15). Without `policy.root` they are the ones in the config,
 * as before. With it, the root-signed roster file is applied on top (serial only up, a revoked key never back), the
 * result is kept in the state folder with an HMAC, and the same roster is what clients fetch to learn the keys.
 */

export interface PolicyTrust {
  readonly keys: Map<string, string>;
  readonly revoked: ReadonlySet<string>;
  /** The signed roster clients are given, or null when there is none yet. */
  readonly roster: unknown;
}

async function machineKey(state: string): Promise<Buffer> {
  const path = join(state, 'trust.key');
  try {
    return await readFile(path);
  } catch {
    await mkdir(state, { recursive: true });
    const key = randomBytes(32);
    await writeFile(path, key, { mode: 0o600, flag: 'wx' }).catch(() => undefined);
    return readFile(path);
  }
}

export async function brokerPolicyTrust(config: BrokerConfig): Promise<PolicyTrust> {
  const { root, roster: rosterPath } = config.policy;
  if (root === undefined) return { keys: new Map(Object.entries(config.policy.keys)), revoked: new Set(), roster: null };
  let shipped: unknown;
  try {
    shipped = JSON.parse(await readFile(rosterPath ?? join(config.state, 'policy-roster.json'), 'utf8')) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new HnError('POLICY_ROSTER_REFUSED', `The policy roster file could not be read as JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  // Strict on purpose: a roster file that is older than the one in force, or that is not signed by the root, stops the reload
  // instead of being skipped, so the operator hears about it and clients are never served a roster that would be refused.
  const folder = join(config.state, 'trust');
  const key = await machineKey(config.state);
  const source = { purpose: 'policy' as const, root, pins: config.policy.keys };
  let state = await loadTrust(folder, key, source);
  if (shipped !== undefined) {
    try {
      state = (await offerRoster(folder, key, source, shipped)).state;
    } catch (error) {
      if (error instanceof RosterError) throw new HnError('POLICY_ROSTER_REFUSED', `The policy roster file was refused: ${error.message}`);
      throw error;
    }
  }
  return { keys: activeKeys(state), revoked: new Set(Object.keys(state.revoked)), roster: shipped ?? null };
}
