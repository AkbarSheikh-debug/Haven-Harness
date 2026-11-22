import { HnError } from '@hn/core';
import { runAuditCommand } from './audit-cmd.ts';
import { startAuditServe } from './serve-audit.ts';

/**
 * The two ways in to the team audit from the command line, kept out of `main.ts`: `hn audit ...` and `hn serve --audit`.
 * Neither can be started from inside an hn session, whose own token could not read the audit anyway.
 */

export interface AuditDoorValues {
  readonly user?: string;
  readonly session?: string;
  readonly type?: string;
  readonly since?: string;
  readonly until?: string;
  readonly after?: string;
  readonly limit?: string;
  readonly from?: string;
  readonly to?: string;
  readonly out?: string;
  readonly pub?: string;
  readonly pins?: string;
  readonly root?: string;
  readonly trust?: string;
  readonly 'key-file'?: string;
  readonly state?: string;
  readonly json?: boolean;
}

/** `hn serve --audit`: the team's audit in a browser on this machine, read-only. */
export async function serveAuditDoor(values: AuditDoorValues, home: string, nested: boolean): Promise<number> {
  if (nested) throw new HnError('NESTED_HN', 'hn serve cannot be started from inside an hn session.');
  const served = await startAuditServe({ home, ...(values.pub === undefined ? {} : { publicKeyFile: values.pub }), ...(values['key-file'] === undefined ? {} : { hmacKeyFile: values['key-file'] }) });
  const unpinned = values.pub === undefined ? 'No --pub was given, so nothing it shows is checked against a key you trust. ' : '';
  process.stdout.write(`hn is showing the team's audit from your broker at ${served.url}audit\nThis page can only read: it changes nothing and starts nothing.\n${unpinned}Open it and paste this token (it is not in the address, on purpose):\n${served.token}\nCtrl+C to stop.\n`);
  await new Promise<void>((resolve) => process.once('SIGINT', () => resolve()));
  await served.close();
  return 0;
}

/** `hn audit search|approvals|sessions|anchors|tail|export|verify|pin|check-session`. */
export async function auditDoor(positionals: readonly string[], values: AuditDoorValues, home: string, nested: boolean): Promise<number> {
  if (nested) throw new HnError('NESTED_HN', 'hn audit cannot be run from inside an hn session.');
  const flags = Object.fromEntries(Object.entries({ ...values, keyFile: values['key-file'] }).filter(([name, value]) => value !== undefined && name !== 'key-file'));
  return (await runAuditCommand({ positionals, flags, home, out: (text) => process.stdout.write(text) })) ?? 1;
}
