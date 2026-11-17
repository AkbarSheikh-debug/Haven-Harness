import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, extname, join } from 'node:path';
import type { Language, Node, Parser } from '@vscode/tree-sitter-wasm';
import { sanitizeForDisplay } from '@hn/core';

/**
 * A syntax check after an edit. It parses the file with the real grammar and reports errors that the edit
 * introduced, so the model learns at once that it broke a file, not three steps later. It is advisory: it never
 * blocks an edit. Each grammar is pinned by hash, and one that does not match is not used.
 */

/** SHA-256 of each grammar file in `@vscode/tree-sitter-wasm` 0.3.1. */
const GRAMMAR_HASH: Readonly<Record<string, string>> = {
  typescript: '778025db5a8be0e70f8ccc3671e486dfeddd048c25d9e8a70c26de2e1bf6f97d',
  tsx: '79e5da75ea62855a0cd67177685f0164eac87d5f630b3cbe1e0a099751ad30f8',
  javascript: '5fb488d0cabb4775a594bab85682de5ad6ce83c0d6ac997a9f82dd084d571240',
  python: '16108b50df4ee9a30168794252ab55e7c93bfc5765d7fa0aa3e335752c515f47',
  go: '9504573f352b20be7f2f1911754d710622aedc15afff16d5ed8fb5645681aee7',
  rust: '0dac14947cb04d94466e3df659f80a4e264c216a60b3eda175eae4cf12ed7a8d',
  java: '4fdeac4ca6ca089f06c6f7e562abcac1733cd465728cc7031ebb73c2019122c4',
  ruby: '09a96427d7c72f0613ed470cd9812223fc4a91d6a9c025c0235cc6bd59ff96f4',
  css: '8a23977fe271357cce6f254ef88c9bebf3854602d8046605aef6a45c02135c59',
  php: 'd4df6a6ff08c87c3ec4f9cbb785fe09998a0cb570e03f57d7b19b3acfb146aa7',
  cpp: '77a65bd42f43c2dcd69af40c12a6c32d6ed81d360c025e9feb28911f8339fd69',
  'c-sharp': 'd12d85996c25957b4c1b71e26db2d7cc8a294997b60642e9c2a3b031b2c66dd3',
  bash: 'a14e9ed880b2c3f16cd00c796c38d237a3e9b028bdec5b4315c76976e67b01ca',
};
const RUNTIME_HASH = '3a31af706ffdf4a7116b064cdd4988df6791823298615009fc5b6bccbd42909b';

const BY_EXTENSION: Readonly<Record<string, string>> = {
  '.ts': 'typescript', '.mts': 'typescript', '.cts': 'typescript', '.tsx': 'tsx',
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
  '.py': 'python', '.go': 'go', '.rs': 'rust', '.java': 'java', '.rb': 'ruby', '.php': 'php',
  '.cs': 'c-sharp', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.css': 'css',
  '.sh': 'bash', '.bash': 'bash',
};

const MAX_TEXT_CHARS = 1_000_000;
const MAX_PROBLEMS = 20;

export interface SyntaxProblem {
  readonly line: number;
  readonly column: number;
  readonly kind: 'error' | 'missing';
  /** The source line, shortened and cleaned for display. */
  readonly snippet: string;
}

export interface SyntaxReport {
  readonly language: string;
  readonly problems: readonly SyntaxProblem[];
}

export const languageOf = (path: string): string | null => BY_EXTENSION[extname(path).toLowerCase()] ?? null;

interface Loaded {
  readonly lib: typeof import('@vscode/tree-sitter-wasm');
  readonly dir: string;
  readonly runtime: Buffer;
}

let runtime: Promise<Loaded> | undefined;
const parsers = new Map<string, Promise<Parser | null>>();

function loadRuntime(): Promise<Loaded> {
  runtime ??= (async () => {
    const require = createRequire(import.meta.url);
    const dir = dirname(require.resolve('@vscode/tree-sitter-wasm'));
    const bytes = await readFile(join(dir, 'tree-sitter.wasm'));
    if (createHash('sha256').update(bytes).digest('hex') !== RUNTIME_HASH) throw new Error('tree-sitter.wasm does not match its pinned hash.');
    const lib = require('@vscode/tree-sitter-wasm') as typeof import('@vscode/tree-sitter-wasm');
    await lib.Parser.init({ wasmBinary: bytes, locateFile: (file: string) => join(dir, file) } as Parameters<typeof lib.Parser.init>[0]);
    return { lib, dir, runtime: bytes };
  })().catch((error: unknown) => {
    runtime = undefined;
    throw error;
  });
  return runtime;
}

/** A parser for one language, or null if its grammar is missing or does not match its pinned hash. */
async function parserFor(language: string): Promise<Parser | null> {
  const pinned = GRAMMAR_HASH[language];
  if (pinned === undefined) return null;
  let entry = parsers.get(language);
  if (entry === undefined) {
    entry = (async () => {
      try {
        const { lib, dir } = await loadRuntime();
        const bytes = await readFile(join(dir, `tree-sitter-${language}.wasm`));
        if (createHash('sha256').update(bytes).digest('hex') !== pinned) return null;
        const parser = new lib.Parser();
        parser.setLanguage((await lib.Language.load(bytes)) as Language);
        return parser;
      } catch {
        return null;
      }
    })();
    parsers.set(language, entry);
  }
  return entry;
}

/** Every grammar that cannot be used, with the reason, for `hn doctor`. */
export async function unusableGrammars(): Promise<{ language: string; reason: string }[]> {
  const bad: { language: string; reason: string }[] = [];
  try {
    await loadRuntime();
  } catch (error) {
    return [{ language: 'runtime', reason: error instanceof Error ? error.message : String(error) }];
  }
  for (const language of Object.keys(GRAMMAR_HASH)) if ((await parserFor(language)) === null) bad.push({ language, reason: 'missing, or does not match its pinned hash' });
  return bad;
}

function collect(root: Node, lines: readonly string[]): SyntaxProblem[] {
  const found: SyntaxProblem[] = [];
  const visit = (node: Node): void => {
    if (found.length >= MAX_PROBLEMS) return;
    if (node.type === 'ERROR' || node.isMissing) {
      const line = node.startPosition.row;
      const raw = (lines[line] ?? '').trim();
      found.push({ line: line + 1, column: node.startPosition.column + 1, kind: node.isMissing ? 'missing' : 'error', snippet: sanitizeForDisplay(raw.length > 80 ? `${raw.slice(0, 80)}...` : raw) });
      // An error node's children are noise, so the walk does not go into it.
      if (node.type === 'ERROR') return;
    }
    if (!node.hasError) return;
    for (const child of node.children) if (child !== null) visit(child);
  };
  visit(root);
  return found;
}

/** Parses `text` as the language the extension names. Null means not checked: no grammar, too large, or the grammar is not trusted. */
export async function checkSyntax(path: string, text: string): Promise<SyntaxReport | null> {
  const language = languageOf(path);
  if (language === null || text.length > MAX_TEXT_CHARS) return null;
  const parser = await parserFor(language);
  if (parser === null) return null;
  const tree = parser.parse(text);
  if (tree === null) return null;
  try {
    return { language, problems: tree.rootNode.hasError ? collect(tree.rootNode, text.split('\n')) : [] };
  } finally {
    tree.delete();
  }
}

/** The problems an edit introduced: all of them if the file was fine before, or only the extra ones if it was already broken. */
export function introducedProblems(before: SyntaxReport | null, after: SyntaxReport | null): SyntaxProblem[] {
  if (after === null || after.problems.length === 0) return [];
  if (before === null) return [...after.problems];
  return after.problems.length > before.problems.length ? [...after.problems] : [];
}

/** The note added to a tool result, or an empty string. */
export function syntaxNote(path: string, introduced: readonly SyntaxProblem[]): string {
  if (introduced.length === 0) return '';
  const shown = introduced.slice(0, 3).map((problem) => `- line ${problem.line}, column ${problem.column}${problem.kind === 'missing' ? ' (something is missing)' : ''}: ${problem.snippet}`);
  const more = introduced.length > 3 ? `\n- and ${introduced.length - 3} more` : '';
  return `\n\nWarning: ${path} no longer parses cleanly. This edit left ${introduced.length} syntax problem(s) that were not there before:\n${shown.join('\n')}${more}\nFix them before going on, or tell the user if this is intentional.`;
}

/** A name a file defines, for the repo map. */
export interface SymbolDef {
  readonly name: string;
  readonly kind: string;
  /** One-based. */
  readonly line: number;
}

export interface FileSymbols {
  readonly defs: readonly SymbolDef[];
  /** Every identifier the file uses, with how often. */
  readonly refs: ReadonlyMap<string, number>;
}

const DEF_TYPES = /^(function_declaration|generator_function_declaration|function_definition|function_item|method_definition|method_declaration|method|class_declaration|abstract_class_declaration|class_definition|class|class_specifier|interface_declaration|type_alias_declaration|enum_declaration|enum_item|struct_item|struct_specifier|struct_declaration|trait_item|record_declaration|type_spec|type_item|mod_item|module)$/;
const REF_TYPES = new Set(['identifier', 'type_identifier', 'property_identifier', 'field_identifier', 'constant']);
const FUNCTION_VALUES = new Set(['arrow_function', 'function_expression', 'function', 'generator_function']);
const MAX_REFS = 5_000;

function kindOf(type: string): string {
  const match = /(function|method|class|interface|enum|struct|trait|record|module|mod|type)/.exec(type);
  const kind = match?.[1] ?? 'symbol';
  return kind === 'mod' ? 'module' : type === 'type_spec' || type === 'type_alias_declaration' || type === 'type_item' ? 'type' : kind;
}

/** Definitions and identifiers in one file, from the real grammar. Null for a language without a pinned grammar. */
export async function fileSymbols(path: string, text: string): Promise<FileSymbols | null> {
  const language = languageOf(path);
  if (language === null || text.length > MAX_TEXT_CHARS) return null;
  const parser = await parserFor(language);
  const tree = parser?.parse(text);
  if (tree === null || tree === undefined) return null;
  try {
    const defs: SymbolDef[] = [];
    const refs = new Map<string, number>();
    const stack: Node[] = [tree.rootNode];
    while (stack.length > 0) {
      const node = stack.pop() as Node;
      if (DEF_TYPES.test(node.type)) {
        const name = node.childForFieldName('name');
        if (name !== null && /^[\p{L}_$][\p{L}\p{N}_$]{0,80}$/u.test(name.text)) defs.push({ name: name.text, kind: kindOf(node.type), line: node.startPosition.row + 1 });
      } else if (node.type === 'variable_declarator') {
        const name = node.childForFieldName('name');
        const value = node.childForFieldName('value');
        if (name !== null && value !== null && FUNCTION_VALUES.has(value.type) && /^[\p{L}_$][\p{L}\p{N}_$]{0,80}$/u.test(name.text)) defs.push({ name: name.text, kind: 'function', line: node.startPosition.row + 1 });
      } else if (REF_TYPES.has(node.type) && refs.size < MAX_REFS) {
        refs.set(node.text, (refs.get(node.text) ?? 0) + 1);
      }
      for (let i = node.namedChildCount - 1; i >= 0; i -= 1) {
        const child = node.namedChild(i);
        if (child !== null) stack.push(child);
      }
    }
    defs.sort((a, b) => a.line - b.line);
    return { defs, refs };
  } finally {
    tree.delete();
  }
}
