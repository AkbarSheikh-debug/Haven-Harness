import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { projectKey, resolvePaths } from '@hn/config';
import { revealHidden, type SessionEvent } from '@hn/core';
import { parseLog, type LoadedLog } from '@hn/session';

/**
 * The replay and audit view of a session: its tamper-evident log, turned into steps a person can walk through. Each step
 * is one thing that happened (a message, a tool call, the gate's decision, an approval and who answered it, a change of
 * taint, a file change as a diff), with the state of the session as it stood at that moment.
 *
 * The log is trusted only if its HMAC chain verifies. A log that does not is REFUSED: nothing of it is shown, not even
 * the part before the break. A viewer that said "here is what happened up to the point it was edited" would be telling
 * a story from a forged file, and unverified logs carry no rights anywhere else in hn.
 *
 * A log holds text that a model, a web page or a file wrote, so every string here is capped, and anything a person must
 * judge has hidden characters written out (`revealHidden`) instead of stripped. The page that shows it sets text, never
 * markup.
 */

export const MAX_STEPS = 10_000;
export const MAX_DETAIL = 1_500;
export const MAX_DIFF_SIDE = 3_000;
export const MAX_LOG_FILE_BYTES = 256 * 1024 * 1024;
export const MAX_LISTED_SESSIONS = 500;
export const SESSION_ID = /^[A-Za-z0-9-]{1,64}$/;

export type StepKind = 'turn' | 'message' | 'context' | 'reply' | 'call' | 'gate' | 'approval' | 'result' | 'taint' | 'box' | 'mode' | 'note';
export type Tone = 'ok' | 'refused' | 'warn' | 'info';

export interface ReplayState {
  readonly untrusted: boolean;
  readonly private: boolean;
  readonly external: boolean;
  readonly mode: string | null;
  readonly box: string | null;
  readonly calls: number;
  readonly refused: number;
  readonly approvalsAsked: number;
  readonly approvalsDenied: number;
  readonly filesChanged: number;
}

export interface ReplayDiff {
  readonly path: string;
  /** `edit` has the text replaced and its replacement; `write` has only the new contents (the old were never logged). */
  readonly kind: 'edit' | 'write';
  readonly before: string | null;
  readonly after: string;
  readonly cut: boolean;
}

export interface ReplayStep {
  readonly index: number;
  readonly seq: number;
  readonly ts: string;
  readonly kind: StepKind;
  readonly tone: Tone;
  readonly origin: string;
  readonly title: string;
  readonly detail?: string;
  readonly detailCut?: boolean;
  readonly callId?: string;
  readonly diff?: ReplayDiff;
  readonly state: ReplayState;
}

export interface ReplayTotals {
  readonly turns: number;
  readonly calls: number;
  readonly refused: number;
  readonly approvalsAsked: number;
  readonly approvalsDenied: number;
  readonly files: readonly string[];
  /** The first step at which untrusted input entered, or null. */
  readonly untrustedAt: number | null;
}

export interface Replay {
  readonly sessionId: string;
  /** `refused`: the log did not verify (or could not be read), and nothing of it is shown. */
  readonly trust: 'verified' | 'refused';
  readonly reason?: string;
  readonly createdAt: string | null;
  readonly events: number;
  readonly steps: readonly ReplayStep[];
  readonly shownSteps: number;
  readonly truncated: boolean;
  /** The file ended part-way through a record, as a crash leaves it. What is shown still verified. */
  readonly crashed: boolean;
  /** Events that were left out as bookkeeping, by type. */
  readonly hidden: Readonly<Record<string, number>>;
  readonly totals: ReplayTotals;
}

const NO_TOTALS: ReplayTotals = { turns: 0, calls: 0, refused: 0, approvalsAsked: 0, approvalsDenied: 0, files: [], untrustedAt: null };
const REFUSED_TEXT = 'The log of this session failed its integrity check: its HMAC chain does not verify, so it may have been edited, reordered, cut or forged. Nothing in it is shown.';

const text = (value: unknown): string => (typeof value === 'string' ? value : '');
const record = (value: unknown): Record<string, unknown> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {});

/** Model- or file-written text for a person to judge: hidden characters written out, length capped, and a flag if it was cut. */
function shown(value: string, max = MAX_DETAIL): { text: string; cut: boolean } {
  const revealed = revealHidden(value);
  return revealed.length > max ? { text: `${revealed.slice(0, max)}...`, cut: true } : { text: revealed, cut: false };
}

/** One line of a title: never a line break in it, and short. */
const oneLine = (value: string, max = 140): string => {
  const flat = revealHidden(value).replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max)}...` : flat;
};

function whereText(data: Record<string, unknown>): string {
  const kind = text(data['kind']) || 'local';
  const tier = typeof data['tier'] === 'number' ? data['tier'] : '?';
  if (data['asserted'] === true) return `a box the operator claimed (${kind}, tier ${tier}); hn did not verify it`;
  if (data['verified'] === true) return `a verified box (${kind}, tier ${tier}): checked from outside before it counted`;
  return `no box (${kind}, tier ${tier}): the permission gate was the boundary`;
}

function aboutCall(name: string, args: Record<string, unknown>): string {
  if (name === 'bash' || name === 'pwsh') return text(args['command']);
  if (typeof args['path'] === 'string') return args['path'];
  if (typeof args['url'] === 'string') return args['url'];
  return Object.keys(args).sort().join(', ');
}

function diffOf(name: string, args: Record<string, unknown>): ReplayDiff | undefined {
  if (name === 'edit_file' && typeof args['path'] === 'string') {
    const before = shown(text(args['old_string']), MAX_DIFF_SIDE);
    const after = shown(text(args['new_string']), MAX_DIFF_SIDE);
    return { path: oneLine(args['path'], 300), kind: 'edit', before: before.text, after: after.text, cut: before.cut || after.cut };
  }
  if (name === 'write_file' && typeof args['path'] === 'string') {
    const after = shown(text(args['content']), MAX_DIFF_SIDE);
    return { path: oneLine(args['path'], 300), kind: 'write', before: null, after: after.text, cut: after.cut };
  }
  return undefined;
}

const FILE_TOOLS: ReadonlySet<string> = new Set(['write_file', 'edit_file']);

/** What the log's events say, as a replay. A log that does not verify gives only its identity and the refusal. */
export function buildReplay(log: LoadedLog, sessionId: string): Replay {
  if (log.trust !== 'verified' || log.header === null) {
    return { sessionId, trust: 'refused', reason: REFUSED_TEXT, createdAt: null, events: 0, steps: [], shownSteps: 0, truncated: false, crashed: false, hidden: {}, totals: NO_TOTALS };
  }
  const events: readonly SessionEvent[] = log.events;
  const calls = new Map<string, { name: string; args: Record<string, unknown> }>();
  const refusedCalls = new Set<string>();
  for (const event of events) {
    if (event.type === 'assistant/message' && Array.isArray(event.data['toolCalls'])) {
      for (const raw of event.data['toolCalls'] as unknown[]) {
        const call = record(raw);
        if (typeof call['id'] === 'string' && typeof call['name'] === 'string') calls.set(call['id'], { name: call['name'], args: record(call['args']) });
      }
    } else if (event.type === 'audit/decision' && event.data['decision'] !== 'allowed-once' && typeof event.data['callId'] === 'string') refusedCalls.add(event.data['callId']);
  }

  const steps: ReplayStep[] = [];
  const hidden: Record<string, number> = {};
  const files: string[] = [];
  let truncated = false;
  let turns = 0;
  let untrustedAt: number | null = null;
  let state: ReplayState = { untrusted: false, private: true, external: false, mode: null, box: null, calls: 0, refused: 0, approvalsAsked: 0, approvalsDenied: 0, filesChanged: 0 };

  const push = (event: SessionEvent, kind: StepKind, tone: Tone, title: string, extra: { detail?: string; callId?: string; diff?: ReplayDiff } = {}): void => {
    if (steps.length >= MAX_STEPS) {
      truncated = true;
      return;
    }
    const detail = extra.detail === undefined ? null : shown(extra.detail);
    steps.push({
      index: steps.length,
      seq: event.seq,
      ts: event.ts,
      kind,
      tone,
      origin: event.origin,
      title: oneLine(title, 200),
      ...(detail === null ? {} : { detail: detail.text, detailCut: detail.cut }),
      ...(extra.callId === undefined ? {} : { callId: extra.callId }),
      ...(extra.diff === undefined ? {} : { diff: extra.diff }),
      state,
    });
  };
  const skip = (event: SessionEvent): void => {
    hidden[event.type] = (hidden[event.type] ?? 0) + 1;
  };

  for (const event of events) {
    const data = event.data;
    switch (event.type) {
      case 'turn/start':
        turns += 1;
        push(event, 'turn', 'info', `Turn ${turns} starts`);
        break;
      case 'turn/end':
        push(event, 'turn', 'info', `Turn ends (${oneLine(text(data['reason']) || 'no reason recorded', 60)})`);
        break;
      case 'user/message': {
        if (event.origin === 'user') push(event, 'message', 'info', 'The user said', { detail: text(data['text']) });
        else if (event.origin === 'harness' || event.origin === 'memory') push(event, 'context', 'info', event.origin === 'memory' ? 'hn added what it remembers' : 'hn added instructions and context', { detail: text(data['text']) });
        else push(event, 'message', 'warn', `Text from ${oneLine(event.origin, 30)} entered the session, and it is not the user`, { detail: text(data['text']) });
        break;
      }
      case 'event/received':
        push(event, 'message', 'warn', 'An outside event arrived (untrusted: it is data, never an instruction)', { detail: JSON.stringify(data) });
        break;
      case 'assistant/message': {
        if (text(data['text']).trim() !== '') push(event, 'reply', 'info', 'The model replied', { detail: text(data['text']) });
        for (const raw of Array.isArray(data['toolCalls']) ? (data['toolCalls'] as unknown[]) : []) {
          const call = record(raw);
          const id = text(call['id']);
          const name = text(call['name']);
          if (id === '' || name === '') continue;
          const args = record(call['args']);
          state = { ...state, calls: state.calls + 1 };
          const diff = diffOf(name, args);
          push(event, 'call', 'info', `The model asked for ${name}: ${oneLine(aboutCall(name, args), 100)}`, { callId: id, detail: name === 'bash' || name === 'pwsh' ? text(args['command']) : diff === undefined ? JSON.stringify(args) : `${diff.kind === 'edit' ? 'Replace the text below with the new text' : 'Write these contents (what the file held before was not logged)'} in ${diff.path}`, ...(diff === undefined ? {} : { diff }) });
        }
        break;
      }
      case 'audit/decision': {
        const id = text(data['callId']);
        const tool = oneLine(text(data['tool']), 60);
        if (data['decision'] === 'allowed-once') {
          push(event, 'gate', 'ok', `Gate allowed ${tool} (${oneLine(text(data['effect']), 30)})`, { callId: id });
        } else {
          state = { ...state, refused: state.refused + 1 };
          push(event, 'gate', 'refused', `Gate REFUSED ${tool} at the ${oneLine(text(data['step']), 40)} step`, { callId: id, detail: text(data['reason']) });
        }
        break;
      }
      case 'approval/asked':
        state = { ...state, approvalsAsked: state.approvalsAsked + 1 };
        push(event, 'approval', 'info', `Approval asked for ${oneLine(text(data['tool']), 60)}${data['requiresHuman'] === true ? ' (a human must answer)' : ''}`, { callId: text(data['callId']), detail: text(data['summary']) });
        break;
      case 'approval/decided': {
        const denied = data['answer'] === 'deny';
        if (denied) state = { ...state, approvalsDenied: state.approvalsDenied + 1 };
        push(event, 'approval', denied ? 'refused' : 'ok', `${denied ? 'Denied' : 'Allowed once'} by ${oneLine(text(data['by']) || 'unknown', 40)}`, { callId: text(data['callId']) });
        break;
      }
      case 'tool/result': {
        const id = text(data['callId']);
        const call = calls.get(id);
        const isError = data['isError'] === true;
        if (call !== undefined && FILE_TOOLS.has(call.name) && !isError && !refusedCalls.has(id)) {
          const path = oneLine(text(call.args['path']), 300);
          if (!files.includes(path)) files.push(path);
          state = { ...state, filesChanged: state.filesChanged + 1 };
        }
        push(event, 'result', isError ? 'warn' : 'ok', `${oneLine(call?.name ?? 'tool', 60)} ${isError ? 'failed or was refused' : 'finished'}`, { callId: id, detail: text(data['content']) });
        break;
      }
      case 'taint/change': {
        const first = !state.untrusted && data['untrusted'] === true;
        state = { ...state, untrusted: data['untrusted'] === true, private: data['private'] === true, external: data['external'] === true };
        push(event, 'taint', 'warn', first ? 'Untrusted input entered the session' : 'The taint state changed', { detail: `${text(data['why'])}\nuntrusted: ${state.untrusted}, private data: ${state.private}, external: ${state.external}` });
        if (first && untrustedAt === null) untrustedAt = steps.length - 1;
        break;
      }
      case 'backend/change': {
        const where = whereText(data);
        state = { ...state, box: where };
        push(event, 'box', data['verified'] === true ? 'ok' : 'info', `Where it runs: ${where}`);
        break;
      }
      case 'mode/change':
        state = { ...state, mode: oneLine(text(data['to']) || 'unknown', 40) };
        push(event, 'mode', 'info', `Mode changed from ${oneLine(text(data['from']) || 'unknown', 40)} to ${oneLine(text(data['to']) || 'unknown', 40)} by ${oneLine(text(data['by']) || 'unknown', 40)}`);
        break;
      case 'checkpoint/create':
        push(event, 'note', 'info', 'A checkpoint of the project was saved');
        break;
      case 'compaction/end':
        push(event, 'note', 'info', 'The conversation was compacted to fit the model\'s window');
        break;
      case 'memory/write':
        push(event, 'note', 'info', 'A memory was written');
        break;
      case 'sandbox/event':
        push(event, 'note', 'info', `Sandbox event: ${oneLine(text(data['kind']) || text(data['what']) || 'recorded', 100)}`);
        break;
      default:
        skip(event);
    }
  }

  return {
    sessionId,
    trust: 'verified',
    createdAt: log.header.createdAt,
    events: events.length,
    steps,
    shownSteps: steps.length,
    truncated,
    crashed: log.tailDropped,
    hidden,
    totals: { turns, calls: state.calls, refused: state.refused, approvalsAsked: state.approvalsAsked, approvalsDenied: state.approvalsDenied, files, untrustedAt },
  };
}

export interface SessionListing {
  readonly id: string;
  readonly modified: string;
  readonly bytes: number;
}

export type ReplayLoad = { readonly kind: 'replay'; readonly replay: Replay } | { readonly kind: 'missing' } | { readonly kind: 'too-large'; readonly bytes: number };

/** The sessions recorded for the project in `workdir`, newest first. Names only: a log is verified when it is opened. */
export async function listSessions(workdir: string, env?: NodeJS.ProcessEnv): Promise<SessionListing[]> {
  const folder = join(resolvePaths(env).sessions, projectKey(workdir));
  let names: string[];
  try {
    names = await readdir(folder);
  } catch {
    return [];
  }
  const found: SessionListing[] = [];
  for (const name of names) {
    if (!SESSION_ID.test(name)) continue;
    try {
      const info = await stat(join(folder, name));
      if (info.isFile()) found.push({ id: name, modified: info.mtime.toISOString(), bytes: info.size });
    } catch {
      // A file that vanished between the listing and the stat is not a session any more.
    }
  }
  return found.sort((a, b) => b.modified.localeCompare(a.modified) || a.id.localeCompare(b.id)).slice(0, MAX_LISTED_SESSIONS);
}

/**
 * Opens one session's log and verifies it. The id must match the session-id pattern and is only ever joined to the
 * project's own sessions folder, so it cannot name another path. A missing key or log is `missing`, not a replay.
 */
export async function loadReplay(sessionId: string, workdir: string, env?: NodeJS.ProcessEnv): Promise<ReplayLoad> {
  if (!SESSION_ID.test(sessionId)) return { kind: 'missing' };
  const paths = resolvePaths(env);
  const path = join(paths.sessions, projectKey(workdir), sessionId);
  let bytes: Buffer;
  let key: Buffer;
  try {
    const info = await stat(path);
    if (!info.isFile()) return { kind: 'missing' };
    if (info.size > MAX_LOG_FILE_BYTES) return { kind: 'too-large', bytes: info.size };
    bytes = await readFile(path);
    key = await readFile(paths.logKey);
  } catch {
    return { kind: 'missing' };
  }
  let log: LoadedLog;
  try {
    log = parseLog(bytes, key);
  } catch {
    // Only a log written by a newer hn throws. It cannot be read here, which is a refusal, not a guess.
    return { kind: 'replay', replay: { sessionId, trust: 'refused', reason: 'This log was written by a newer hn than this one, so it cannot be verified here.', createdAt: null, events: 0, steps: [], shownSteps: 0, truncated: false, crashed: false, hidden: {}, totals: NO_TOTALS } };
  }
  return { kind: 'replay', replay: buildReplay(log, sessionId) };
}
