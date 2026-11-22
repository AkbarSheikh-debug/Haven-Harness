import { createPublicKey, type KeyObject } from 'node:crypto';
import { appendFile, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { HnError } from '@hn/core';
import { auditWindows, checkpointFromValue, checkpointStanding, checkpointValid, verifyAudit, verifyBundle, type AuditEntry, type AuditKeyWindow, type Checkpoint } from '@hn/security';
import { auditWindowsFor, offerAuditRoster, pinAuditRoot, readAuditRoot } from './audit-trust.ts';
import { auditJson, auditRequest, openAuditLink, plain, queryOf, rowLine, streamLines, type AuditLink } from './audit-client.ts';

/**
 * `hn audit ...` (Phase 14): the team's audit, from the broker, for someone whose policy names them a reader.
 *
 *   search | approvals | sessions | anchors   what happened, by person, session, type and time
 *   tail                                       follow it live
 *   export --out <file>                        a verifiable bundle (a contiguous range plus a signed head)
 *   verify <bundle> --key-file --pub [--pins]  check a bundle offline; needs no login and no network
 *   pin <folder>                               keep the broker's public key and the checkpoints it has signed so far
 *   check-session <audit file> --user --key-file   compare one laptop's session audit with the head the broker anchored
 *
 * `verify` and `check-session`'s local half never trust the network: they say what they checked and what they did not.
 */

export interface AuditFlags {
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
  /** Phase 15: a root public key file (`pin`), and a folder `pin` made with one (`verify`). */
  readonly root?: string;
  readonly trust?: string;
  readonly keyFile?: string;
  readonly state?: string;
  readonly json?: boolean;
}

export interface AuditContext {
  readonly positionals: readonly string[];
  readonly flags: AuditFlags;
  readonly home: string;
  readonly out: (text: string) => void;
  readonly fetch?: typeof fetch;
  /** Stops `tail`. */
  readonly signal?: AbortSignal;
  /** Stops `tail` after this many rows (tests). */
  readonly maxRows?: number;
}

const USAGE = 'hn audit search|approvals|sessions|anchors|tail|export|verify|pin|check-session  (see docs/guide/team-audit.md)';
const MAX_BUNDLE_BYTES = 256 * 1024 * 1024;
const SESSION_ID = /^[A-Za-z0-9_-]{1,100}$/;

async function readBytesCapped(path: string, what: string): Promise<Buffer> {
  const size = (await stat(path).catch(() => null))?.size;
  if (size === undefined) throw new HnError('BAD_COMMAND', `${what} ${path} cannot be read.`);
  if (size > MAX_BUNDLE_BYTES) throw new HnError('BAD_COMMAND', `${what} is larger than hn will open.`);
  return readFile(path);
}

const need = (value: string | undefined, flag: string): string => {
  if (value === undefined) throw new HnError('BAD_COMMAND', `This needs --${flag}.`);
  return value;
};

/** Reads the checkpoints in a pin file: one JSON checkpoint a line. A line that is not one is an error, not skipped. */
async function readPins(path: string): Promise<Checkpoint[]> {
  const text = await readFile(path, 'utf8').catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return '';
    throw error;
  });
  return text.split('\n').filter((line) => line !== '').map((line, index) => {
    let parsed: Checkpoint | null = null;
    try {
      parsed = checkpointFromValue(JSON.parse(line));
    } catch {
      parsed = null;
    }
    if (parsed === null) throw new HnError('BAD_COMMAND', `${path} line ${index + 1} is not a checkpoint.`);
    return parsed;
  });
}

/**
 * Adds the checkpoints the broker gave now to the auditor's pin file. A checkpoint for a row the auditor has pinned with a
 * different MAC is the broker contradicting itself, and stops everything.
 */
async function keepPins(folder: string, listed: readonly Checkpoint[]): Promise<{ fresh: Checkpoint[]; total: number; pinsPath: string }> {
  const pinsPath = join(folder, 'pins.jsonl');
  const have = await readPins(pinsPath);
  const fresh = listed.filter((item) => !have.some((old) => old.n === item.n && old.mac === item.mac));
  for (const item of fresh) {
    const clash = have.find((old) => old.n === item.n && old.mac !== item.mac);
    if (clash !== undefined) throw new HnError('AUDIT_CONTRADICTION', `The broker has now signed a different head for row ${item.n} than the one you pinned. Nothing more was pinned.`);
  }
  if (fresh.length > 0) await appendFile(pinsPath, fresh.map((item) => `${JSON.stringify(item)}\n`).join(''));
  return { fresh, total: have.length + fresh.length, pinsPath };
}

async function tailRows(link: AuditLink, context: AuditContext): Promise<number> {
  const stop = new AbortController();
  context.signal?.addEventListener('abort', () => stop.abort(), { once: true });
  const response = await auditRequest(link, `/v1/audit/tail${queryOf({ from: context.flags.from }, ['from'])}`, stop.signal);
  if (!response.ok) throw new HnError(response.status === 403 ? 'AUDIT_NOT_A_READER' : 'BROKER_REFUSED', `The broker will not let you follow the audit (${response.status}).`);
  let seen = 0;
  try {
    for await (const line of streamLines(response)) {
      if (line['type'] === 'row') {
        const row = line['row'] as AuditEntry;
        context.out(context.flags.json === true ? `${JSON.stringify(row)}\n` : `${rowLine(row)}\n`);
        seen += 1;
        if (context.maxRows !== undefined && seen >= context.maxRows) break;
      } else if (line['type'] === 'dropped' || line['type'] === 'closed') {
        context.out(`The broker ended the stream: ${plain(line['reason'])}${typeof line['next'] === 'number' ? ` Resume with --from ${line['next']}.` : ''}\n`);
        return line['type'] === 'dropped' ? 1 : 0;
      }
    }
  } catch (error) {
    if (!stop.signal.aborted) throw error;
  } finally {
    stop.abort();
  }
  return 0;
}

export async function runAuditCommand(context: AuditContext): Promise<number | null> {
  const [command, verb, target] = context.positionals;
  if (command !== 'audit') return null;
  const { flags, out } = context;
  if (verb === undefined) throw new HnError('BAD_COMMAND', USAGE);

  if (verb === 'verify') {
    const bundlePath = target ?? '';
    if (bundlePath === '') throw new HnError('BAD_COMMAND', 'hn audit verify <bundle> --key-file <broker audit key> --pub <broker public key> [--pins <file>]');
    let bundle: unknown;
    try {
      bundle = JSON.parse((await readBytesCapped(bundlePath, 'The bundle')).toString('utf8'));
    } catch (error) {
      if (error instanceof HnError) throw error;
      throw new HnError('BAD_COMMAND', 'The bundle is not JSON.');
    }
    const hmacKey = await readBytesCapped(need(flags.keyFile, 'key-file'), 'The audit key');
    let keys: { publicKey?: KeyObject; windows?: AuditKeyWindow[] };
    if (flags.trust !== undefined) {
      // A folder from `hn audit pin --root`: the keys come from the roster the root signed, each with the rows it may sign for.
      const roster = typeof bundle === 'object' && bundle !== null ? (bundle as { roster?: unknown }).roster : undefined;
      keys = { windows: (await auditWindowsFor(flags.trust, roster)).windows };
    } else {
      try {
        keys = { publicKey: createPublicKey(await readBytesCapped(need(flags.pub, 'pub'), 'The public key')) };
      } catch {
        throw new HnError('BAD_COMMAND', 'The public key file is not a public key.');
      }
    }
    const pins = flags.pins !== undefined ? await readPins(flags.pins) : flags.trust !== undefined ? await readPins(join(flags.trust, 'pins.jsonl')) : [];
    const result = verifyBundle(bundle, { hmacKey, ...keys, pins });
    if (flags.json === true) out(`${JSON.stringify(result)}\n`);
    else if (result.ok) {
      out(`VERIFIED: rows ${result.from} to ${result.to} (${result.rows} rows) chain correctly, and the last row is covered by a checkpoint the broker signed with the key you pinned (${result.checkpointsChecked} checkpoint${result.checkpointsChecked === 1 ? '' : 's'} checked${pins.length === 0 ? '' : `, including ${pins.length} you pinned`}).\n`);
      out('This shows the rows are the ones the broker had when it signed. It does not show the broker was honest before that, or that rows outside this range are unchanged.\n');
    } else out(`NOT VERIFIED${result.brokenAt === null ? '' : ` (row ${result.brokenAt})`}: ${plain(result.reason, 500)}\n`);
    return result.ok ? 0 : 1;
  }

  if (verb === 'check-session') {
    const logPath = target ?? '';
    if (logPath === '') throw new HnError('BAD_COMMAND', 'hn audit check-session <session audit file> --user <person> --key-file <that person\'s log.key> [--session <id>]');
    const user = need(flags.user, 'user');
    const session = flags.session ?? basename(logPath).replace(/\.jsonl$/, '');
    if (!SESSION_ID.test(session)) throw new HnError('BAD_COMMAND', 'The session id must be letters, digits, - and _. Pass --session.');
    const local = verifyAudit((await readBytesCapped(logPath, 'The session audit file')).toString('utf8'), await readBytesCapped(need(flags.keyFile, 'key-file'), 'The key'));
    const link = await openAuditLink(context.home, context.fetch);
    const found = await auditJson<{ anchors: { n: number; mac: string }[] }>(link, `/v1/audit/anchors${queryOf({ user, session }, ['user', 'session'])}`);
    const verdict = anchorVerdict(local.ok, local.entries, local.head.n, found.anchors[0] ?? null);
    if (flags.json === true) out(`${JSON.stringify({ user, session, ...verdict, reason: local.ok ? null : local.reason })}\n`);
    else out(`${verdict.state.toUpperCase()}: ${verdict.message}${local.ok ? '' : ` (${plain(local.reason, 300)})`}\n`);
    return verdict.state === 'match' || verdict.state === 'ahead' ? 0 : 1;
  }

  const link = await openAuditLink(context.home, context.fetch);
  const json = flags.json === true;

  if (verb === 'search') {
    const names = ['user', 'session', 'type', 'since', 'until', 'after', 'limit'] as const;
    const page = await auditJson<{ rows: AuditEntry[]; next: number | null; head: { n: number } }>(link, `/v1/audit/rows${queryOf(flags as Record<string, string | undefined>, names)}`);
    if (json) out(`${JSON.stringify(page)}\n`);
    else {
      out(page.rows.length === 0 ? 'No rows match.\n' : page.rows.map((row) => `${rowLine(row)}\n`).join(''));
      if (page.next !== null) out(`More rows follow: add --after ${page.next}\n`);
    }
    return 0;
  }
  if (verb === 'approvals') {
    const list = await auditJson<{ approvals: { id: string; requester: string | null; action: string | null; state: string; decidedBy: string | null; requestedAt: string | null; refused: { approver: string }[] }[]; truncated: boolean }>(link, `/v1/audit/approvals${queryOf(flags as Record<string, string | undefined>, ['user'])}${flags.state === undefined ? '' : `${flags.user === undefined ? '?' : '&'}state=${encodeURIComponent(flags.state)}`}`);
    if (json) out(`${JSON.stringify(list)}\n`);
    else {
      out(list.approvals.length === 0 ? 'No approvals match.\n' : list.approvals.map((item) => `${plain(item.id, 24)}  ${plain(item.requestedAt ?? '', 30)}  ${plain(item.requester ?? '?', 60)} asked: ${plain(item.action ?? '?', 140)}  =>  ${item.state}${item.decidedBy === null ? '' : ` (decided by ${plain(item.decidedBy, 60)})`}${item.refused.length === 0 ? '' : `, ${item.refused.length} refused attempt${item.refused.length === 1 ? '' : 's'}`}\n`).join(''));
      if (list.truncated) out('Only the newest are shown.\n');
    }
    return 0;
  }
  if (verb === 'sessions') {
    const list = await auditJson<{ sessions: { user: string; session: string; firstAt: string; modelCalls: number; usd: number; anchor: { n: number } | null }[] }>(link, `/v1/audit/sessions${queryOf(flags as Record<string, string | undefined>, ['user'])}`);
    if (json) out(`${JSON.stringify(list)}\n`);
    else out(list.sessions.length === 0 ? 'No sessions.\n' : list.sessions.map((item) => `${plain(item.user, 60)}  ${plain(item.session, 60)}  ${item.firstAt}  ${item.modelCalls} model calls  $${item.usd.toFixed(4)}  ${item.anchor === null ? 'not anchored' : `anchored at row ${item.anchor.n}`}\n`).join(''));
    return 0;
  }
  if (verb === 'anchors') {
    const list = await auditJson<{ anchors: { user: string; session: string; n: number; mac: string; at: number }[] }>(link, `/v1/audit/anchors${queryOf(flags as Record<string, string | undefined>, ['user', 'session'])}`);
    if (json) out(`${JSON.stringify(list)}\n`);
    else out(list.anchors.length === 0 ? 'No anchors.\n' : list.anchors.map((item) => `${plain(item.user, 60)}  ${plain(item.session, 60)}  row ${item.n}  ${item.mac.slice(0, 16)}…  ${new Date(item.at).toISOString()}\n`).join(''));
    return 0;
  }
  if (verb === 'tail') return tailRows(link, context);
  if (verb === 'export') {
    const file = need(flags.out, 'out');
    const bundle = await auditJson<unknown>(link, `/v1/audit/export${queryOf(flags as Record<string, string | undefined>, ['from', 'to'])}`);
    await writeFile(file, JSON.stringify(bundle), { mode: 0o600 });
    const shape = bundle as { from: number; to: number; count: number };
    out(`Wrote rows ${shape.from} to ${shape.to} (${shape.count} rows) to ${file}. Check it with: hn audit verify ${file} --key-file <audit key> --pub <public key>\n`);
    return 0;
  }
  if (verb === 'pin') {
    const folder = target ?? '';
    if (folder === '') throw new HnError('BAD_COMMAND', 'hn audit pin <folder> [--pub <the public key the broker operator gave you>]');
    const listed = await auditJson<{ keyId: string; publicKey: string; checkpoints: Checkpoint[]; roster?: unknown }>(link, '/v1/audit/checkpoints');
    if (flags.root !== undefined || (await readAuditRoot(folder)) !== null) {
      // With a root (Phase 15) the keys come from the roster it signed, so a rotation needs no new hand-pinned key.
      if (flags.root !== undefined) await pinAuditRoot(folder, (await readBytesCapped(flags.root, 'The root key')).toString('utf8'));
      if (listed.roster === undefined || listed.roster === null) throw new HnError('AUDIT_ROSTER_REFUSED', 'The broker has no signed audit roster, so there is nothing to follow from the root you pinned. Ask the operator for one (hn trust sign), or pin the single key with --pub.');
      let state;
      try {
        state = await offerAuditRoster(folder, listed.roster);
      } catch (error) {
        if (error instanceof HnError) throw error;
        throw new HnError('AUDIT_ROSTER_REFUSED', `The broker's audit roster was refused: ${error instanceof Error ? error.message : String(error)}`);
      }
      const windows = auditWindows(state);
      // A forged or malformed checkpoint stops everything. One a key signed after its cut-off (a revoked key) is not kept, and said so.
      const accepted: Checkpoint[] = [];
      let setAside = 0;
      for (const item of listed.checkpoints) {
        const checkpoint = checkpointFromValue(item);
        if (checkpoint === null) throw new HnError('AUDIT_CONTRADICTION', 'The broker sent something that is not a checkpoint. Nothing was pinned.');
        const standing = checkpointStanding(checkpoint, windows).state;
        if (standing === 'forged') throw new HnError('AUDIT_CONTRADICTION', 'The broker sent a checkpoint that the key it names did not sign. Nothing was pinned.');
        if (standing === 'ok') accepted.push(checkpoint);
        else setAside += 1;
      }
      const kept = await keepPins(folder, accepted);
      out(`Following the roster signed by the root you pinned (serial ${state.serial}, ${windows.length} audit key${windows.length === 1 ? '' : 's'}).\nPinned ${kept.fresh.length} new checkpoint${kept.fresh.length === 1 ? '' : 's'} (${kept.total} in ${kept.pinsPath}).${setAside === 0 ? '' : ` Set aside ${setAside} signed by a key after its cut-off: not trusted.`} Check an export with: hn audit verify <bundle> --key-file <audit key> --trust ${folder}\n`);
      return 0;
    }
    const normalize = (pem: string): string => createPublicKey(pem).export({ type: 'spki', format: 'pem' }).toString();
    const brokerKey = normalize(listed.publicKey);
    await mkdir(folder, { recursive: true });
    const keyPath = join(folder, 'audit-public.pem');
    const given = flags.pub === undefined ? null : normalize((await readBytesCapped(flags.pub, 'The public key')).toString('utf8'));
    const kept = await readFile(keyPath, 'utf8').then(normalize).catch(() => null);
    if (given !== null && given !== brokerKey) throw new HnError('AUDIT_KEY_MISMATCH', 'The broker is using a different audit-signing key from the one you were given. Nothing was pinned.');
    if (kept !== null && kept !== brokerKey) throw new HnError('AUDIT_KEY_MISMATCH', `The broker's audit-signing key is not the one already pinned in ${keyPath}. Nothing was changed: either the broker's key was replaced or this is not the broker you pinned.`);
    if (kept === null) await writeFile(keyPath, brokerKey);
    const brokerPublic = createPublicKey(brokerKey);
    const unsigned = listed.checkpoints.find((item) => checkpointFromValue(item) === null || !checkpointValid(item, brokerPublic));
    if (unsigned !== undefined) throw new HnError('AUDIT_CONTRADICTION', 'The broker sent a checkpoint that its own key did not sign. Nothing was pinned.');
    const { fresh, total, pinsPath } = await keepPins(folder, listed.checkpoints);
    const have = { length: total - fresh.length };
    out(`${kept === null ? `Pinned the broker's audit-signing key (id ${listed.keyId}) in ${keyPath}${given === null ? ': compare this id with the one the broker operator gave you, because nothing else vouches for it' : ' (it matches the key you were given)'}.` : `The broker's key matches the one pinned in ${keyPath}.`}\nPinned ${fresh.length} new checkpoint${fresh.length === 1 ? '' : 's'} (${have.length + fresh.length} in ${pinsPath}).\n`);
    return 0;
  }
  throw new HnError('BAD_COMMAND', USAGE);
}

export interface AnchorVerdict {
  readonly state: 'match' | 'ahead' | 'behind' | 'differs' | 'unknown' | 'refused';
  readonly message: string;
  readonly localRows: number;
  readonly anchoredRows: number | null;
}

/** Compares a verified (or not) local session audit with the head the broker anchored for it. */
export function anchorVerdict(verified: boolean, entries: readonly AuditEntry[], localRows: number, anchor: { readonly n: number; readonly mac: string } | null): AnchorVerdict {
  if (!verified) return { state: 'refused', message: 'The file does not verify with that key, so nothing in it can be compared. It was edited, is from another machine, or the key is wrong.', localRows, anchoredRows: anchor?.n ?? null };
  if (anchor === null) return { state: 'unknown', message: 'The broker never saw this session, so there is nothing to compare with: a cut tail cannot be ruled out.', localRows, anchoredRows: null };
  if (localRows < anchor.n) return { state: 'behind', message: `The file ends at row ${localRows}, but the broker saw this session reach row ${anchor.n}: ${anchor.n - localRows} row${anchor.n - localRows === 1 ? ' was' : 's were'} removed from the end.`, localRows, anchoredRows: anchor.n };
  if ((entries[anchor.n - 1] as AuditEntry | undefined)?.mac !== anchor.mac) return { state: 'differs', message: `Row ${anchor.n} in the file is not the row the broker saw. The file was rewritten after the broker last heard from the session.`, localRows, anchoredRows: anchor.n };
  return localRows === anchor.n ? { state: 'match', message: `The file ends exactly where the broker last saw the session (row ${anchor.n}), and that row is the same.`, localRows, anchoredRows: anchor.n } : { state: 'ahead', message: `Row ${anchor.n}, the last one the broker saw, is the same. The file has ${localRows - anchor.n} more row${localRows - anchor.n === 1 ? '' : 's'}, written after the last anchor (anchoring is best effort, so the newest rows may not have been sent).`, localRows, anchoredRows: anchor.n };
}
