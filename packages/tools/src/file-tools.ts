import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join } from 'node:path';
import { MAX_CHANGE_CHARS, checkSyntax, introducedProblems, sentinelWriteProblem, syntaxNote, type ProposedChange } from '@hn/security';
import { decodeText, encodeText, type DecodedText } from './text.ts';
import { ToolProblem, stringArg, type ToolArgs, type ToolContext, type ToolDefinition, type ToolResult } from './types.ts';

export const DEFAULT_READ_LINES = 2_000;
export const MAX_READ_LINES = 4_000;

const digest = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const absolute = (workdir: string, path: string): string => (isAbsolute(path) ? path : join(workdir, path));

function isMissing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === 'ENOENT';
}

/**
 * What the model has actually seen. A write to a file it never read, or one that
 * changed since it read it, is refused, so it cannot overwrite work it knows nothing about.
 */
class Observations {
  readonly #seen = new Map<string, string>();
  readonly #queues = new Map<string, Promise<unknown>>();

  record(path: string, bytes: Buffer): void {
    this.#seen.set(path, digest(bytes));
  }

  check(path: string, current: Buffer): void {
    const seen = this.#seen.get(path);
    if (seen === undefined) throw new ToolProblem('FS_NOT_OBSERVED', 'Read this file first, then change it.');
    if (seen !== digest(current)) {
      throw new ToolProblem('FS_STALE_VERSION', 'This file changed since you read it. Read it again, then retry.');
    }
  }

  /** Writes to one file run one at a time, whatever order they arrive in. */
  serialize<T>(path: string, work: () => Promise<T>): Promise<T> {
    const previous = this.#queues.get(path) ?? Promise.resolve();
    const next = previous.then(work, work);
    this.#queues.set(path, next.catch(() => undefined));
    return next;
  }
}

function decodeOrRefuse(bytes: Buffer, path: string): DecodedText {
  const decoded = decodeText(bytes);
  if (decoded === null) throw new ToolProblem('FS_BINARY', `${path} is a binary file, so it cannot be read as text.`);
  return decoded;
}

function readTool(observations: Observations): ToolDefinition {
  return {
    name: 'read_file',
    description: 'Read a text file. Returns numbered lines. Use offset and limit for long files.',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'File path, relative to the project.' },
        offset: { type: 'integer', description: 'First line to return, starting at 1.' },
        limit: { type: 'integer', description: `Lines to return, at most ${MAX_READ_LINES}.` },
      },
      required: ['path'],
      additionalProperties: false,
    },
    effect: 'observe',
    concurrencySafe: true,
    paths: (args) => [{ path: stringArg(args, 'path'), write: false }],
    summary: (args) => `read ${stringArg(args, 'path')}`,
    async execute(args, { workdir, ops, taint }) {
      const path = absolute(workdir, stringArg(args, 'path'));
      const bytes = await ops.read.readFile(path);
      const { text } = decodeOrRefuse(bytes, stringArg(args, 'path'));
      observations.record(path, bytes);
      const origin = taint?.originOfRead(bytes) ?? 'workspace';

      const lines = text.split(/\r?\n/);
      if (lines.at(-1) === '') lines.pop();
      if (lines.length === 0) return { content: '(empty file)', origin };
      const offset = Math.max(1, (args['offset'] as number | undefined) ?? 1);
      const limit = Math.min(MAX_READ_LINES, (args['limit'] as number | undefined) ?? DEFAULT_READ_LINES);
      const page = lines.slice(offset - 1, offset - 1 + limit);
      if (page.length === 0) throw new ToolProblem('FS_RANGE', `The file has ${lines.length} lines. Use a smaller offset.`);
      const body = page.map((line, index) => `${offset + index}\t${line}`).join('\n');
      const last = offset + page.length - 1;
      const note = last < lines.length ? `\n\n(Lines ${offset}-${last} of ${lines.length}. Use offset ${last + 1} to continue.)` : '';
      return { content: body + note, origin };
    },
  };
}

async function readExisting(path: string, context: ToolContext): Promise<Buffer | null> {
  try {
    return await context.ops.read.readFile(path);
  } catch (error) {
    if (isMissing(error)) return null;
    throw error;
  }
}

/**
 * Tells the model when its edit broke a file that parsed before. Advisory: the edit is already made, and a check that
 * cannot run (no grammar, too large, a grammar that is not trusted) says nothing rather than guessing.
 */
async function syntaxWarning(path: string, before: string | null, after: string): Promise<string> {
  try {
    const was = before === null ? null : await checkSyntax(path, before);
    return syntaxNote(path, introducedProblems(was, await checkSyntax(path, after)));
  } catch {
    return '';
  }
}

const cut = (text: string): { text: string; truncated: boolean } => (text.length > MAX_CHANGE_CHARS ? { text: text.slice(0, MAX_CHANGE_CHARS), truncated: true } : { text, truncated: false });

/** The change a write would make: the file before (null when new) and the text that will be in it. */
async function previewWrite(args: ToolArgs, context: Pick<ToolContext, 'workdir' | 'ops'>): Promise<ProposedChange | null> {
  const path = stringArg(args, 'path');
  const existing = await readExisting(absolute(context.workdir, path), context as ToolContext);
  const decoded = existing === null ? null : decodeText(existing);
  if (existing !== null && decoded === null) return null;
  const before = decoded === null ? null : cut(decoded.text);
  const after = cut(stringArg(args, 'content'));
  return { path, oldText: before === null ? null : before.text, newText: after.text, partial: false, truncated: after.truncated || before?.truncated === true };
}

/** The change an edit would make: the whole file before and after when it fits, else just the replaced fragment. */
async function previewEdit(args: ToolArgs, context: Pick<ToolContext, 'workdir' | 'ops'>): Promise<ProposedChange | null> {
  const path = stringArg(args, 'path');
  const existing = await readExisting(absolute(context.workdir, path), context as ToolContext);
  const decoded = existing === null ? null : decodeText(existing);
  if (decoded === null || stringArg(args, 'old_string') === '') return null;
  let after: string;
  try {
    after = applyEdit(decoded, stringArg(args, 'old_string'), stringArg(args, 'new_string'), args['replace_all'] === true);
  } catch {
    // The edit will be refused when it runs; there is no change to show.
    return null;
  }
  if (decoded.text.length <= MAX_CHANGE_CHARS && after.length <= MAX_CHANGE_CHARS) return { path, oldText: decoded.text, newText: after, partial: false, truncated: false };
  const oldPart = cut(stringArg(args, 'old_string'));
  const newPart = cut(stringArg(args, 'new_string'));
  return { path, oldText: oldPart.text, newText: newPart.text, partial: true, truncated: oldPart.truncated || newPart.truncated };
}

function writeTool(observations: Observations): ToolDefinition {
  return {
    name: 'write_file',
    description: 'Create a file or replace one you have already read. Prefer edit_file for changes.',
    parameters: {
      type: 'object',
      properties: { path: { type: 'string' }, content: { type: 'string' } },
      required: ['path', 'content'],
      additionalProperties: false,
    },
    effect: 'reversible',
    concurrencySafe: true,
    paths: (args) => [{ path: stringArg(args, 'path'), write: true }],
    summary: (args) => `write ${stringArg(args, 'path')} (${Buffer.byteLength(stringArg(args, 'content'))} bytes)`,
    preview: previewWrite,
    execute: (args, context) => {
      const path = absolute(context.workdir, stringArg(args, 'path'));
      return observations.serialize(path, async () => {
        const existing = await readExisting(path, context);
        const decoded = existing === null ? null : decodeOrRefuse(existing, stringArg(args, 'path'));
        const encoding = decoded === null ? 'utf8' : decoded.encoding;
        const sentinel = sentinelWriteProblem(decoded?.text ?? null, stringArg(args, 'content'));
        if (sentinel !== null) throw new ToolProblem('REDACTED_WRITE', sentinel);
        if (existing !== null) observations.check(path, existing);
        else await context.ops.write.mkdir(dirname(path));
        const bytes = encodeText(stringArg(args, 'content'), encoding);
        await context.ops.write.writeFile(path, bytes);
        observations.record(path, bytes);
        context.taint?.recordWrite(bytes, context.taint.worst);
        const warning = await syntaxWarning(stringArg(args, 'path'), decoded?.text ?? null, stringArg(args, 'content'));
        return { content: `${existing === null ? 'Created' : 'Replaced'} ${stringArg(args, 'path')}.${warning}`, origin: 'harness' };
      });
    },
  };
}

function countMatches(text: string, needle: string): number {
  let count = 0;
  for (let at = text.indexOf(needle); at !== -1; at = text.indexOf(needle, at + needle.length)) count += 1;
  return count;
}

function applyEdit(decoded: DecodedText, oldText: string, newText: string, replaceAll: boolean): string {
  // The model writes \n. A CRLF file must still match, and must stay CRLF.
  const toFile = (value: string): string => (decoded.eol === '\r\n' ? value.replace(/\r?\n/g, '\r\n') : value);
  const needle = toFile(oldText);
  const matches = countMatches(decoded.text, needle);
  if (matches === 0) {
    throw new ToolProblem('EDIT_NOT_FOUND', 'old_string is not in the file. Read the file again and copy the text exactly.');
  }
  if (matches > 1 && !replaceAll) {
    throw new ToolProblem('EDIT_NOT_UNIQUE', `old_string appears ${matches} times. Add surrounding lines, or set replace_all.`);
  }
  return decoded.text.split(needle).join(toFile(newText));
}

function editTool(observations: Observations): ToolDefinition {
  return {
    name: 'edit_file',
    description: 'Replace exact text in a file. old_string must appear exactly once unless replace_all is set.',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        old_string: { type: 'string' },
        new_string: { type: 'string' },
        replace_all: { type: 'boolean' },
      },
      required: ['path', 'old_string', 'new_string'],
      additionalProperties: false,
    },
    effect: 'reversible',
    concurrencySafe: true,
    paths: (args) => [{ path: stringArg(args, 'path'), write: true }],
    preview: previewEdit,
    summary: (args: ToolArgs) =>
      `edit ${stringArg(args, 'path')}\n--- old\n${stringArg(args, 'old_string')}\n+++ new\n${stringArg(args, 'new_string')}`,
    execute: (args, context): Promise<ToolResult> => {
      const path = absolute(context.workdir, stringArg(args, 'path'));
      return observations.serialize(path, async () => {
        const existing = await readExisting(path, context);
        if (existing === null) throw new ToolProblem('FS_NOT_FOUND', 'This file does not exist. Use write_file to create it.');
        const decoded = decodeOrRefuse(existing, stringArg(args, 'path'));
        observations.check(path, existing);
        if (stringArg(args, 'old_string') === '') throw new ToolProblem('EDIT_EMPTY', 'old_string cannot be empty.');
        const sentinel = sentinelWriteProblem(stringArg(args, 'old_string'), stringArg(args, 'new_string'));
        if (sentinel !== null) throw new ToolProblem('REDACTED_WRITE', sentinel);
        const text = applyEdit(decoded, stringArg(args, 'old_string'), stringArg(args, 'new_string'), args['replace_all'] === true);
        const bytes = encodeText(text, decoded.encoding);
        await context.ops.write.writeFile(path, bytes);
        observations.record(path, bytes);
        context.taint?.recordWrite(bytes, context.taint.worst);
        const warning = await syntaxWarning(stringArg(args, 'path'), decoded.text, text);
        return { content: `Edited ${stringArg(args, 'path')}.${warning}`, origin: 'harness' };
      });
    },
  };
}

export function createFileTools(): ToolDefinition[] {
  const observations = new Observations();
  return [readTool(observations), writeTool(observations), editTool(observations)];
}
