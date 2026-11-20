import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { projectKey, resolvePaths } from '@hn/config';
import { sanitizeForDisplay, type SessionEvent } from '@hn/core';
import { costReport } from '@hn/delegate';
import { parseLog, type LoadedLog } from '@hn/session';

/**
 * `hn report <session>`: what a session did, as markdown, from its tamper-evident log and nothing else. It is meant to be
 * pasted into a pull request, so it is written for a reviewer who was not there: where the work ran, every file it
 * changed, every command and its result, every call the gate refused and why, every approval asked and who answered.
 *
 * The log is trusted only if its HMAC chain verifies. A log that does not is refused, never summarised: a report that
 * sounds sure about a forged log is worse than none.
 *
 * Everything in a log that a model or a file wrote (commands, paths, reasons) ends up in a PR on someone else's
 * screen. It is shown only inside inline code, with backticks and line breaks neutralized and a length cap, so it can
 * never become a link, an image, HTML, a heading, or an `@name` that notifies a real person.
 */

export const MAX_ROWS = 40;
export const MAX_REPORT_CHARS = 60_000;
const MAX_CELL = 160;

export interface CallRecord {
  readonly callId: string;
  readonly tool: string;
  /** What it was about: a command, a path, or the tool's own arguments' keys. Model-written, so shown as code only. */
  readonly about: string;
  readonly decision: 'allowed' | 'refused' | 'unknown';
  readonly step?: string;
  readonly reason?: string;
  readonly effect?: string;
  readonly approvals: readonly { readonly answer: string; readonly by: string }[];
  readonly outcome: 'ok' | 'error' | 'none';
  readonly exitCode?: number;
}

export interface SessionReport {
  readonly sessionId: string;
  readonly createdAt: string | null;
  readonly trust: 'verified' | 'unverified';
  readonly box: { readonly kind: string; readonly tier: number | null; readonly verified: boolean; readonly asserted: boolean } | null;
  readonly turns: number;
  readonly calls: readonly CallRecord[];
  readonly filesChanged: readonly { readonly path: string; readonly tool: string }[];
  readonly commands: readonly (CallRecord & { readonly isCheck: boolean })[];
  readonly refused: readonly CallRecord[];
  readonly approvalsAsked: number;
  readonly approvalsAllowed: number;
  readonly taint: readonly string[];
  readonly cost: { readonly dollars: number | null; readonly tokens: number } | null;
}

const CHECK = /\b(test|tests|pytest|jest|vitest|mocha|cargo test|go test|npm test|pnpm test|yarn test|mvn|gradle|tsc|typecheck|lint|eslint|ruff|mypy|make check|ctest)\b/i;
const FILE_TOOLS: ReadonlySet<string> = new Set(['write_file', 'edit_file']);

const text = (value: unknown): string => (typeof value === 'string' ? value : '');

/** What a call was about, from its arguments. */
function aboutCall(name: string, args: unknown): string {
  const record = typeof args === 'object' && args !== null ? (args as Record<string, unknown>) : {};
  if (name === 'bash') return text(record['command']);
  if (typeof record['path'] === 'string') return record['path'];
  if (typeof record['url'] === 'string') return record['url'];
  return Object.keys(record).sort().join(', ');
}

/** The structured report. A log that does not verify gives only its identity and `unverified`. */
export function buildReport(log: LoadedLog, sessionId: string): SessionReport {
  const empty = { turns: 0, calls: [], filesChanged: [], commands: [], refused: [], approvalsAsked: 0, approvalsAllowed: 0, taint: [], cost: null, box: null };
  if (log.trust !== 'verified') return { sessionId, createdAt: log.header?.createdAt ?? null, trust: 'unverified', ...empty };
  const events: readonly SessionEvent[] = log.events;
  const wanted = new Map<string, { name: string; args: unknown }>();
  const decisions = new Map<string, Record<string, unknown>>();
  const asked = new Map<string, string>();
  const answers = new Map<string, { answer: string; by: string }[]>();
  const results = new Map<string, { isError: boolean; content: string }>();
  const order: string[] = [];
  let box: SessionReport['box'] = null;
  let turns = 0;
  const taint: string[] = [];
  for (const event of events) {
    const data = event.data;
    if (event.type === 'turn/start') turns += 1;
    else if (event.type === 'assistant/message') {
      const calls = Array.isArray(data['toolCalls']) ? (data['toolCalls'] as unknown[]) : [];
      for (const call of calls) {
        const record = (typeof call === 'object' && call !== null ? call : {}) as Record<string, unknown>;
        if (typeof record['id'] === 'string' && typeof record['name'] === 'string') {
          wanted.set(record['id'], { name: record['name'], args: record['args'] });
          order.push(record['id']);
        }
      }
    } else if (event.type === 'audit/decision' && typeof data['callId'] === 'string') decisions.set(data['callId'], data);
    else if (event.type === 'approval/asked' && typeof data['approvalId'] === 'string') asked.set(data['approvalId'], text(data['callId']));
    else if (event.type === 'approval/decided' && typeof data['approvalId'] === 'string') {
      const callId = asked.get(data['approvalId']) ?? text(data['callId']);
      answers.set(callId, [...(answers.get(callId) ?? []), { answer: text(data['answer']), by: text(data['by']) }]);
    } else if (event.type === 'tool/result' && typeof data['callId'] === 'string') results.set(data['callId'], { isError: data['isError'] === true, content: text(data['content']) });
    else if (event.type === 'backend/change') {
      box = { kind: text(data['kind']) || 'local', tier: typeof data['tier'] === 'number' ? data['tier'] : null, verified: data['verified'] === true, asserted: data['asserted'] === true };
    } else if (event.type === 'taint/change' && typeof data['why'] === 'string' && !taint.includes(data['why'])) taint.push(data['why']);
  }

  const calls: CallRecord[] = [];
  for (const callId of [...new Set(order)]) {
    const call = wanted.get(callId);
    if (call === undefined) continue;
    const decision = decisions.get(callId);
    const result = results.get(callId);
    const exit = result === undefined ? undefined : /Exit code (\d+)\.\s*$/.exec(result.content);
    const kind = decision === undefined ? 'unknown' : decision['decision'] === 'allowed-once' ? 'allowed' : 'refused';
    calls.push({
      callId,
      tool: call.name,
      about: aboutCall(call.name, call.args),
      decision: kind,
      ...(kind === 'refused' ? { step: text(decision?.['step']), reason: text(decision?.['reason']) } : {}),
      ...(decision === undefined ? {} : { effect: text(decision['effect']) }),
      approvals: answers.get(callId) ?? [],
      outcome: result === undefined ? 'none' : result.isError ? 'error' : 'ok',
      ...(call.name === 'bash' && result !== undefined && kind === 'allowed' ? { exitCode: exit?.[1] !== undefined ? Number(exit[1]) : result.isError ? 1 : 0 } : {}),
    });
  }

  const cost = costReport(events);
  const all = [...answers.values()].flat();
  return {
    sessionId,
    createdAt: log.header?.createdAt ?? null,
    trust: 'verified',
    box,
    turns,
    calls,
    filesChanged: calls.filter((call) => FILE_TOOLS.has(call.tool) && call.decision === 'allowed' && call.outcome === 'ok').map((call) => ({ path: call.about, tool: call.tool })),
    commands: calls.filter((call) => call.tool === 'bash').map((call) => ({ ...call, isCheck: CHECK.test(call.about) })),
    refused: calls.filter((call) => call.decision === 'refused'),
    approvalsAsked: all.length,
    approvalsAllowed: all.filter((entry) => entry.answer !== 'deny').length,
    taint,
    cost: { dollars: cost.total.dollars, tokens: cost.total.input + cost.total.output + cost.total.cacheRead + cost.total.cacheWrite },
  };
}

/** Model-written text, as inline code that cannot become anything else in markdown. */
export function code(value: string, max = MAX_CELL): string {
  const flat = sanitizeForDisplay(value).replace(/\s+/g, ' ').replace(/[`|]/g, "'").trim();
  const cut = flat.length > max ? `${flat.slice(0, max)}...` : flat;
  return `\`${cut === '' ? ' ' : cut}\``;
}

function where(box: SessionReport['box']): string {
  if (box === null) return 'not recorded';
  if (box.asserted) return `a box the operator claimed (${box.kind}, tier ${box.tier ?? '?'}); hn did not verify it`;
  if (box.verified) return `a verified box (${box.kind}, tier ${box.tier ?? '?'}): checked from outside before it counted`;
  return `no box (${box.kind}, tier ${box.tier ?? '?'}): the permission gate was the boundary`;
}

function table(head: readonly string[], rows: readonly (readonly string[])[]): string[] {
  if (rows.length === 0) return ['_None._'];
  const shown = rows.slice(0, MAX_ROWS);
  const lines = [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...shown.map((row) => `| ${row.join(' | ')} |`)];
  if (rows.length > shown.length) lines.push('', `_... and ${rows.length - shown.length} more._`);
  return lines;
}

const exitText = (call: CallRecord): string => (call.decision === 'refused' ? 'not run: refused' : call.outcome === 'none' ? 'no result' : call.exitCode === undefined || call.exitCode === 0 ? (call.outcome === 'ok' ? 'ok' : 'failed') : `failed (exit ${call.exitCode})`);

/** The report as markdown. */
export function renderReport(report: SessionReport): string {
  const id = code(report.sessionId, 80);
  if (report.trust !== 'verified') {
    return [
      '## hn session report',
      '',
      `**REFUSED.** The log of session ${id} failed its integrity check (its HMAC chain does not verify), so it may have been edited or damaged. Nothing in it is reported.`,
      '',
    ].join('\n');
  }
  const refused = report.refused.length;
  const dollars = report.cost?.dollars;
  const lines: string[] = [
    '## hn session report',
    '',
    `Session ${id}${report.createdAt === null ? '' : `, started ${code(report.createdAt, 40)}`}. Log integrity: **verified** (HMAC chain).`,
    '',
    `- **Where it ran:** ${where(report.box)}.`,
    `- **Turns:** ${report.turns}. **Tool calls:** ${report.calls.length}${refused === 0 ? '' : `, **${refused} refused by the gate**`}.`,
    `- **Approvals asked of a person or guardian:** ${report.approvalsAsked} (${report.approvalsAllowed} allowed, ${report.approvalsAsked - report.approvalsAllowed} denied).`,
    `- **Cost:** ${dollars === null || dollars === undefined ? `not priced (${report.cost?.tokens ?? 0} tokens)` : `$${dollars.toFixed(4)} (${report.cost?.tokens ?? 0} tokens)`}.`,
    report.taint.length === 0
      ? '- **Untrusted input:** none recorded.'
      : `- **Untrusted input entered the session:** ${report.taint.slice(0, 8).map((why) => code(why, 60)).join(', ')}.`,
    '',
    '### Files changed',
    '',
    ...table(['File', 'How'], report.filesChanged.map((file) => [code(file.path), file.tool])),
    '',
    '### Commands and checks',
    '',
    ...table(['Command', 'Result', 'Check'], report.commands.map((call) => [code(call.about), exitText(call), call.isCheck ? 'yes' : ''])),
    '',
    '### Refused by the gate',
    '',
    ...table(['Tool', 'About', 'Why'], report.refused.map((call) => [call.tool, code(call.about, 80), code(`${call.step ?? ''}: ${call.reason ?? ''}`)])),
    '',
    '### Approvals',
    '',
    ...table(
      ['Tool', 'About', 'Answer', 'By'],
      report.calls.flatMap((call) => call.approvals.map((entry) => [call.tool, code(call.about, 80), entry.answer === 'deny' ? 'denied' : 'allowed', entry.by])),
    ),
    '',
    '_Generated by `hn report` from the session log. Every value above that the model or a file wrote is shown as code and was not interpreted._',
    '',
  ];
  const out = lines.join('\n');
  return out.length > MAX_REPORT_CHARS ? `${out.slice(0, MAX_REPORT_CHARS)}\n\n_(The report was cut at ${MAX_REPORT_CHARS} characters.)_\n` : out;
}

export interface ReportCommandOptions {
  readonly sessionId: string;
  readonly workdir: string;
  readonly json: boolean;
  readonly env?: NodeJS.ProcessEnv;
  readonly out: (text: string) => void;
}

/** `hn report <session id>`. Exit 0 for a verified log, 2 for one that does not verify, 1 for anything else. */
export async function runReportCommand(options: ReportCommandOptions): Promise<number> {
  if (!/^[A-Za-z0-9-]{1,64}$/.test(options.sessionId)) {
    options.out('That is not a session id. Usage: hn report <session id> [--json]\n');
    return 1;
  }
  const paths = resolvePaths(options.env);
  let bytes: Buffer;
  let key: Buffer;
  try {
    bytes = await readFile(join(paths.sessions, projectKey(options.workdir), options.sessionId));
    key = await readFile(paths.logKey);
  } catch {
    options.out(`There is no readable log for session ${sanitizeForDisplay(options.sessionId)} in this folder's project, or the log key is missing.\n`);
    return 1;
  }
  const report = buildReport(parseLog(bytes, key), options.sessionId);
  options.out(options.json ? `${JSON.stringify(report)}\n` : renderReport(report));
  return report.trust === 'verified' ? 0 : 2;
}
