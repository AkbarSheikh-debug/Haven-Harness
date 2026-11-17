import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ORIGINS, type Origin } from '@hn/core';
import { scanThreat, type Identity } from '@hn/security';
import { readJson, refusal, sendJson } from './http.ts';
import type { BrokerContext, Route } from './server.ts';
import { writeAtomic } from './ledger.ts';

/**
 * Team memory with gates. It lives on the broker, so who may read an entry is decided where
 * a client cannot change it. Each entry is the usual memory record (who, when, source session, project, origin, taint,
 * expires, why) plus the person who wrote it and who may see it: only them, their OU (and every OU below it), a
 * role, or the whole organisation. Policy decides whether a person may write, how widely they may share, and how
 * long an entry may live. An entry learned from untrusted text can be shared with nobody but its writer, an expired
 * entry is never returned, text is threat-scanned before it is stored, and every write and delete is an audit row
 * naming the person.
 *
 * What the broker cannot know: whether the laptop told the truth about taint. A modified client can claim `clean`.
 */

export type Visibility = { readonly kind: 'user' } | { readonly kind: 'ou'; readonly value: string } | { readonly kind: 'role'; readonly value: string } | { readonly kind: 'org' };

export interface TeamEntry {
  readonly id: string;
  readonly text: string;
  readonly owner: Identity;
  readonly visibility: Visibility;
  readonly when: string;
  readonly expires: string | null;
  readonly why: string;
  readonly origin: Origin;
  readonly taint: 'clean' | 'untrusted';
  readonly sourceSession: string | null;
  readonly project: string | null;
}

const MAX_TEXT = 4_000;
const MAX_ENTRIES = 50_000;
const DAY = 86_400_000;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** Whether `reader` may see an entry with this visibility. An OU entry is seen by that OU and everything below it. */
export function canRead(reader: Identity, entry: TeamEntry): boolean {
  const visibility = entry.visibility;
  if (visibility.kind === 'user') return reader.user === entry.owner.user;
  if (visibility.kind === 'org') return true;
  if (visibility.kind === 'role') return reader.roles.includes(visibility.value);
  const path = visibility.value.split('/');
  return path.length <= reader.ou.length && path.every((part, index) => reader.ou[index] === part);
}

function parseVisibility(value: unknown, writer: Identity): Visibility | string {
  if (!isRecord(value)) return 'visibility must be an object.';
  const kind = value['kind'];
  if (kind === 'user' || kind === 'org') return { kind };
  if (kind !== 'ou' && kind !== 'role') return 'visibility.kind must be user, ou, role or org.';
  const target = value['value'];
  if (typeof target !== 'string' || target === '') return 'visibility.value is missing.';
  // A person can share only with a group they are in: their own OU or one above it, a role they hold.
  if (kind === 'role') return writer.roles.includes(target) ? { kind, value: target } : `${writer.user} does not hold the role ${target}.`;
  const path = target.split('/');
  return path.length <= writer.ou.length && path.every((part, index) => writer.ou[index] === part) ? { kind, value: target } : `${writer.user} is not in the OU ${target}.`;
}

export interface TeamMemory {
  readonly routes: readonly Route[];
}

export async function openTeamMemory(state: string): Promise<TeamMemory> {
  const dir = join(state, 'memory');
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const file = join(dir, 'entries.json');
  let entries: TeamEntry[] = [];
  try {
    entries = JSON.parse(await readFile(file, 'utf8')) as TeamEntry[];
  } catch {
    // An empty memory.
  }
  const save = async (): Promise<void> => {
    await writeAtomic(file, () => JSON.stringify(entries));
  };
  const live = (now: number): TeamEntry[] => entries.filter((entry) => entry.expires === null || Date.parse(entry.expires) > now);

  async function write(context: BrokerContext, writer: Identity, session: string, body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
    const policy = context.policyFor(writer);
    const refuse = (reason: string): { status: number; body: Record<string, unknown> } => {
      context.audit('broker/memory-refused', { user: writer.user, reason });
      return { status: 403, body: { error: reason } };
    };
    if (!policy.memoryWriteAllowed()) return refuse(`The policy does not let ${writer.user} write team memory.`);
    const text = body['text'];
    const why = body['why'];
    if (typeof text !== 'string' || text.trim() === '' || text.length > MAX_TEXT) return { status: 400, body: { error: `text must be 1 to ${MAX_TEXT} characters.` } };
    if (typeof why !== 'string' || why.length > 500) return { status: 400, body: { error: 'why must be a short string.' } };
    const visibility = parseVisibility(body['visibility'], writer);
    if (typeof visibility === 'string') return refuse(visibility);
    if (!policy.mayShareTo(visibility.kind)) return refuse(`The policy does not let ${writer.user} share memory with ${visibility.kind === 'org' ? 'the whole organisation' : `a ${visibility.kind}`}.`);
    const taint = body['taint'] === 'clean' ? 'clean' : 'untrusted';
    if (taint === 'untrusted' && visibility.kind !== 'user') return refuse('An entry written while the session held untrusted text can be kept only for its writer.');
    const origin = typeof body['origin'] === 'string' && (ORIGINS as readonly string[]).includes(body['origin']) ? (body['origin'] as Origin) : 'workspace';
    const now = context.now();
    const maxDays = policy.memoryMaxDays();
    let expires = typeof body['expires'] === 'string' && !Number.isNaN(Date.parse(body['expires'])) ? Date.parse(body['expires']) : null;
    if (expires !== null && expires <= now) return { status: 400, body: { error: 'expires is in the past.' } };
    if (maxDays !== undefined) {
      if (expires !== null && expires > now + maxDays * DAY) return refuse(`The policy keeps team memory for at most ${maxDays} days.`);
      expires ??= now + maxDays * DAY;
    }
    const scan = await scanThreat(text, 'strict');
    if (!scan.clean) return refuse(`The text was refused by the threat scan: ${scan.reason ?? scan.findings.map((finding) => finding.id).join(', ')}.`);
    if (entries.length >= MAX_ENTRIES) return { status: 507, body: { error: 'Team memory is full.' } };
    const entry: TeamEntry = { id: randomBytes(8).toString('hex'), text, owner: writer, visibility, when: new Date(now).toISOString(), expires: expires === null ? null : new Date(expires).toISOString(), why, origin, taint, sourceSession: session, project: typeof body['project'] === 'string' ? body['project'].slice(0, 200) : null };
    entries.push(entry);
    await save();
    context.audit('broker/memory-write', { user: writer.user, id: entry.id, visibility, expires: entry.expires, taint, origin });
    return { status: 200, body: { id: entry.id, expires: entry.expires } };
  }

  return {
    routes: [
      {
        method: 'GET',
        path: '/v1/memory',
        async handle(context, request, response) {
          const who = context.auth(request, response, 'session');
          if (who === null) return;
          const query = (new URL(request.url ?? '/', 'http://broker').searchParams.get('q') ?? '').toLowerCase().slice(0, 200);
          const found = live(context.now()).filter((entry) => canRead(who.identity, entry) && (query === '' || entry.text.toLowerCase().includes(query))).slice(-50);
          context.audit('broker/memory-read', { user: who.identity.user, query, returned: found.length });
          sendJson(response, 200, { entries: found.map((entry) => ({ id: entry.id, text: entry.text, by: entry.owner.user, visibility: entry.visibility, when: entry.when, expires: entry.expires, why: entry.why, taint: entry.taint, origin: entry.origin })) });
        },
      },
      {
        method: 'POST',
        path: '/v1/memory',
        async handle(context, request, response) {
          const who = context.auth(request, response, 'session');
          if (who === null) return;
          const body = await readJson(request, 64 * 1024);
          if (!isRecord(body)) return refusal(response, 400, 'Expected an object.');
          const result = await write(context, who.identity, who.sid, body);
          sendJson(response, result.status, result.body);
        },
      },
      {
        method: 'POST',
        path: '/v1/memory/delete',
        async handle(context, request, response) {
          const who = context.auth(request, response, 'session');
          if (who === null) return;
          const body = await readJson(request, 4096);
          const id = isRecord(body) ? body['id'] : undefined;
          const index = entries.findIndex((entry) => entry.id === id);
          if (index === -1) return refusal(response, 404, 'No such entry.');
          if (entries[index]?.owner.user !== who.identity.user) return refusal(response, 403, 'Only the person who wrote an entry can delete it.');
          entries.splice(index, 1);
          await save();
          context.audit('broker/memory-delete', { user: who.identity.user, id });
          sendJson(response, 200, { id });
        },
      },
    ],
  };
}
