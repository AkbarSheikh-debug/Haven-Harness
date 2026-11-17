import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import type { Node, Parser } from '@vscode/tree-sitter-wasm';
import { HnError } from '@hn/core';
import type { Effect } from './gate.ts';
import { deniedCommandReason, hardlineReason, isSecretPath } from './rules.ts';

/**
 * Bash is parsed, not grepped. The real grammar gives the real command list, including pipes,
 * subshells, substitutions and `bash -c` payloads, after quotes and escapes are undone, so
 * `r''m -rf /` is `rm`. This is still a seatbelt: `python -c`, `find -delete` and base64 get
 * past any parser, which is why the sandbox is the boundary.
 */

/** The grammar and runtime are pinned by hash. A swapped file means no parser, and no parser means every command is execution. */
const PINNED: Readonly<Record<string, string>> = {
  'tree-sitter.wasm': '3a31af706ffdf4a7116b064cdd4988df6791823298615009fc5b6bccbd42909b',
  'tree-sitter-bash.wasm': 'a14e9ed880b2c3f16cd00c796c38d237a3e9b028bdec5b4315c76976e67b01ca',
};

export class BashParserError extends HnError {
  constructor(message: string) {
    super('BASH_PARSER_UNAVAILABLE', message);
  }
}

export interface Redirect {
  readonly op: string;
  readonly target: string;
  readonly dynamic: boolean;
}

export interface ParsedCommand {
  /** Lowercase, without directory or `.exe`. Empty when it is computed at run time. */
  readonly name: string;
  readonly args: readonly string[];
  readonly assignments: readonly string[];
  readonly redirects: readonly Redirect[];
  /** The name or an argument is computed at run time, so what really runs cannot be known. */
  readonly dynamic: boolean;
  /** Found inside a wrapper or a payload such as `bash -c` rather than written directly. */
  readonly derived: boolean;
}

export interface BashParse {
  readonly ok: boolean;
  readonly reason: string | null;
  readonly commands: readonly ParsedCommand[];
  /** The names in each pipeline, in order. */
  readonly pipelines: readonly (readonly string[])[];
}

export interface BashParser {
  parse(command: string): BashParse;
}

let loaded: Promise<BashParser> | undefined;

/** Loads the parser once. Rejects with `BashParserError` if the files are missing or do not match their pinned hashes. */
export function loadBashParser(): Promise<BashParser> {
  loaded ??= load().catch((error: unknown) => {
    loaded = undefined;
    throw error instanceof BashParserError ? error : new BashParserError(`The bash parser could not be loaded: ${error instanceof Error ? error.message : String(error)}`);
  });
  return loaded;
}

async function load(): Promise<BashParser> {
  const require = createRequire(import.meta.url);
  const dir = dirname(require.resolve('@vscode/tree-sitter-wasm'));
  const files = new Map<string, Buffer>();
  for (const [name, hash] of Object.entries(PINNED)) {
    const bytes = await readFile(join(dir, name));
    if (createHash('sha256').update(bytes).digest('hex') !== hash) throw new BashParserError(`${name} does not match its pinned hash.`);
    files.set(name, bytes);
  }
  const lib = require('@vscode/tree-sitter-wasm') as typeof import('@vscode/tree-sitter-wasm');
  // The verified bytes are the ones the runtime uses, so the file cannot change between the check and the load.
  await lib.Parser.init({ wasmBinary: files.get('tree-sitter.wasm'), locateFile: (file: string) => join(dir, file) } as Parameters<typeof lib.Parser.init>[0]);
  const language = await lib.Language.load(files.get('tree-sitter-bash.wasm') as Buffer);
  const parser = new lib.Parser();
  parser.setLanguage(language);
  return { parse: (command) => parseWith(parser, command) };
}

const MAX_COMMAND_CHARS = 65_536;
const MAX_PAYLOAD_DEPTH = 3;

interface Literal {
  readonly value: string;
  readonly dynamic: boolean;
}

const EXPANSIONS = new Set(['simple_expansion', 'expansion', 'command_substitution', 'process_substitution', 'arithmetic_expansion']);

function unescapeDouble(text: string): string {
  return text.replace(/\\([\\"$`\n])/g, '$1');
}

function decodeAnsiC(text: string): string {
  return text.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|.)/gs, (_whole, code: string) => {
    if (code[0] === 'x' && code.length > 1) return String.fromCharCode(Number.parseInt(code.slice(1), 16));
    if (code[0] === 'u' || code[0] === 'U') return String.fromCodePoint(Number.parseInt(code.slice(1), 16));
    if (/^[0-7]+$/.test(code)) return String.fromCharCode(Number.parseInt(code, 8));
    return ({ n: '\n', t: '\t', r: '\r', a: '\u0007', b: '\b', e: '\u001b', f: '\f', v: '\v' } as Record<string, string>)[code] ?? code;
  });
}

function literal(node: Node): Literal {
  switch (node.type) {
    case 'word':
    case 'number':
      return { value: node.text.replace(/\\(.)/gs, '$1'), dynamic: false };
    case 'raw_string':
      return { value: node.text.slice(1, -1), dynamic: false };
    case 'ansi_c_string':
      return { value: decodeAnsiC(node.text.slice(2, -1)), dynamic: false };
    case 'string':
    case 'translated_string': {
      const inner = node.text.replace(/^\$?"/, '').replace(/"$/, '');
      const dynamic = node.namedChildren.some((child) => child !== null && EXPANSIONS.has(child.type));
      return { value: dynamic ? inner : unescapeDouble(inner), dynamic };
    }
    case 'concatenation': {
      let value = '';
      let dynamic = false;
      for (const child of node.namedChildren) {
        if (child === null) continue;
        const part = literal(child);
        value += part.value;
        dynamic ||= part.dynamic;
      }
      return { value, dynamic };
    }
    default:
      return { value: node.text, dynamic: true };
  }
}

export const WRITE_OPS = new Set(['>', '>>', '>|', '&>', '&>>', '<>', '>&']);

function redirectOf(node: Node): Redirect | null {
  const destination = node.childForFieldName('destination');
  if (destination === null) return null;
  const op = node.children.find((child) => child !== null && !child.isNamed && /^[<>&|]+$/.test(child.type))?.type ?? '>';
  const target = literal(destination);
  return { op, target: target.value, dynamic: target.dynamic };
}

const baseName = (value: string): string =>
  value
    .replaceAll('\\', '/')
    .split('/')
    .at(-1)!
    .toLowerCase()
    .replace(/\.(exe|cmd|bat|com)$/, '');

export const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish']);
const PASS_THROUGH = new Set(['env', 'command', 'builtin', 'exec', 'nohup', 'time', 'nice', 'ionice', 'timeout', 'stdbuf', 'setsid', 'xargs', 'chroot', 'unbuffer']);

function makeCommand(name: string, args: readonly string[], base: Partial<ParsedCommand>, derived: boolean, dynamic = false): ParsedCommand {
  return { name, args, assignments: base.assignments ?? [], redirects: base.redirects ?? [], dynamic: dynamic || (base.dynamic ?? false), derived };
}

/** What a wrapper really runs: skip its own options and assignments. */
function unwrap(command: ParsedCommand): ParsedCommand | null {
  const { name, args } = command;
  if (!PASS_THROUGH.has(name)) return null;
  const rest = [...args];
  while (rest.length > 0) {
    const head = rest[0] as string;
    if (head === '--') {
      rest.shift();
      break;
    }
    if (head.startsWith('-') || (name === 'env' && head.includes('=')) || ((name === 'timeout' || name === 'nice' || name === 'ionice') && /^[\d.]+[smhd]?$/.test(head))) rest.shift();
    else break;
  }
  const next = rest.shift();
  return next === undefined ? null : makeCommand(baseName(next), rest, command, true, command.dynamic);
}

function shellPayload(command: ParsedCommand): string | null {
  if (!SHELLS.has(command.name) && command.name !== 'eval') return null;
  if (command.name === 'eval') return command.args.join(' ');
  const flagAt = command.args.findIndex((arg) => /^-[a-z]*c[a-z]*$/i.test(arg));
  return flagAt === -1 ? null : (command.args[flagAt + 1] ?? null);
}

function parseWith(parser: Parser, command: string, depth = 0, derived = false): BashParse {
  if (command.length > MAX_COMMAND_CHARS) return { ok: false, reason: 'The command is too long to analyse.', commands: [], pipelines: [] };
  const tree = parser.parse(command);
  if (tree === null) return { ok: false, reason: 'The command could not be parsed.', commands: [], pipelines: [] };
  const commands: ParsedCommand[] = [];
  const pipelines: string[][] = [];
  let ok = true;
  let reason: string | null = null;

  const fail = (why: string): void => {
    ok = false;
    reason ??= why;
  };

  const add = (parsed: ParsedCommand): void => {
    commands.push(parsed);
    const inner = unwrap(parsed);
    if (inner !== null) add(inner);
    const payload = shellPayload(parsed);
    if (payload !== null) {
      if (depth >= MAX_PAYLOAD_DEPTH) return fail('Shell commands are nested too deeply to analyse.');
      const nested = parseWith(parser, payload, depth + 1, true);
      if (!nested.ok) fail(nested.reason ?? 'A nested shell command could not be parsed.');
      commands.push(...nested.commands);
      pipelines.push(...nested.pipelines.map((names) => [...names]));
    }
    if (parsed.name === 'find') {
      const at = parsed.args.findIndex((arg) => ['-exec', '-execdir', '-ok', '-okdir'].includes(arg));
      if (at !== -1) {
        const [head, ...rest] = parsed.args.slice(at + 1).filter((arg) => arg !== ';' && arg !== '+' && arg !== '{}');
        if (head !== undefined) add(makeCommand(baseName(head), rest, parsed, true, true));
      }
    }
  };

  const visit = (node: Node, redirects: readonly Redirect[]): void => {
    if (node.type === 'ERROR' || node.isMissing) fail('The command is not valid shell syntax.');
    if (node.type === 'redirected_statement') {
      const own = node.childrenForFieldName('redirect').flatMap((child) => (child === null ? [] : [redirectOf(child)]));
      const extra = own.filter((entry): entry is Redirect => entry !== null);
      for (const child of node.namedChildren) if (child !== null) visit(child, [...redirects, ...extra]);
      return;
    }
    if (node.type === 'pipeline') {
      pipelines.push(
        node.namedChildren.flatMap((child) => {
          if (child === null) return [];
          const target = child.type === 'redirected_statement' ? child.childForFieldName('body') : child;
          const name = target?.type === 'command' ? target.childForFieldName('name') : null;
          return name === null || name === undefined ? [] : [baseName(literal(name.namedChildren[0] ?? name).value)];
        }),
      );
    }
    if (node.type === 'command') {
      const nameNode = node.childForFieldName('name');
      const assignments = node.namedChildren.flatMap((child) => (child !== null && child.type === 'variable_assignment' ? [child.text] : []));
      const own = node.namedChildren.flatMap((child) => (child !== null && child.type === 'file_redirect' ? [redirectOf(child)] : [])).filter((entry): entry is Redirect => entry !== null);
      if (nameNode !== null) {
        const name = literal(nameNode.namedChildren[0] ?? nameNode);
        const args = node.childrenForFieldName('argument').flatMap((child) => (child === null ? [] : [literal(child)]));
        add({
          name: name.dynamic ? '' : baseName(name.value),
          args: args.map((arg) => arg.value),
          assignments,
          redirects: [...redirects, ...own],
          dynamic: name.dynamic || args.some((arg) => arg.dynamic),
          derived,
        });
      }
    }
    for (const child of node.namedChildren) if (child !== null) visit(child, redirects);
  };

  visit(tree.rootNode, []);
  if (tree.rootNode.hasError && ok) fail('The command is not valid shell syntax.');
  tree.delete();
  return { ok, reason, commands, pipelines };
}

