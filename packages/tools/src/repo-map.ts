import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { fileSymbols, isSecretPath, languageOf, type FileSymbols } from '@hn/security';
import { SECRET_GLOBS } from './shell-tools.ts';
import { wrapUntrusted } from './web-tools.ts';
import type { ToolArgs, ToolContext, ToolDefinition } from './types.ts';

/**
 * The repo map: definitions from the real grammars, files ranked by PageRank over "this file
 * uses a name that file defines", personalised on the files the session edited or the caller named. It is cut to a
 * token budget and comes back as project data. On demand only, so it never grows the prompt by itself.
 */

export const DEFAULT_MAP_TOKENS = 1_000;
const MAX_MAP_TOKENS = 8_000;
const MAX_FILES = 2_000;
const MAX_FILE_BYTES = 512 * 1024;
const DAMPING = 0.85;
const ITERATIONS = 40;
/** Names so common that using one says nothing about which file you depend on. */
const NOISE = new Set(['constructor', 'toString', 'length', 'push', 'map', 'get', 'set', 'then', 'value', 'name', 'id', 'type', 'data', 'error', 'self', 'this', 'new', 'init', 'main', 'test', 'run', 'default', 'exports', 'module', 'require']);

export interface RankInput {
  readonly symbols: ReadonlyMap<string, FileSymbols>;
  /** File to weight. Files not named here get none; with no weights at all, every file gets the same. */
  readonly personal: ReadonlyMap<string, number>;
}

/** PageRank over the dependency graph. A file that uses a name another file defines gives that file some of its rank. */
export function rankFiles({ symbols, personal }: RankInput): Map<string, number> {
  const files = [...symbols.keys()].sort();
  const definers = new Map<string, string[]>();
  for (const file of files) {
    for (const def of symbols.get(file)?.defs ?? []) {
      if (NOISE.has(def.name)) continue;
      const list = definers.get(def.name) ?? [];
      if (!list.includes(file)) list.push(file);
      definers.set(def.name, list);
    }
  }
  // Edge weights: uses of a name count with diminishing returns, and a name defined in many files is split between them.
  const edges = new Map<string, Map<string, number>>();
  for (const file of files) {
    const out = new Map<string, number>();
    for (const [name, count] of symbols.get(file)?.refs ?? []) {
      const targets = definers.get(name);
      if (targets === undefined) continue;
      for (const target of targets) {
        if (target === file) continue;
        out.set(target, (out.get(target) ?? 0) + Math.sqrt(count) / targets.length);
      }
    }
    edges.set(file, out);
  }
  const total = [...personal.values()].reduce((sum, weight) => sum + weight, 0);
  const restart = new Map(files.map((file) => [file, total > 0 ? (personal.get(file) ?? 0) / total : 1 / files.length] as const));
  let rank = new Map(restart);
  for (let i = 0; i < ITERATIONS; i += 1) {
    const next = new Map(files.map((file) => [file, (1 - DAMPING) * (restart.get(file) ?? 0)] as const));
    let dangling = 0;
    for (const file of files) {
      const out = edges.get(file) as Map<string, number>;
      const weight = [...out.values()].reduce((sum, value) => sum + value, 0);
      const mine = rank.get(file) ?? 0;
      if (weight === 0) {
        dangling += mine;
        continue;
      }
      for (const [target, value] of out) next.set(target, (next.get(target) ?? 0) + (DAMPING * mine * value) / weight);
    }
    // A file that uses nothing hands its rank back along the restart, so rank is never lost.
    for (const file of files) next.set(file, (next.get(file) ?? 0) + DAMPING * dangling * (restart.get(file) ?? 0));
    rank = next;
  }
  return rank;
}

/** The map as text, best files first, cut at the budget (about four characters a token). */
export function renderMap(symbols: ReadonlyMap<string, FileSymbols>, rank: ReadonlyMap<string, number>, maxTokens: number, anchors: readonly string[]): string {
  const budget = maxTokens * 4;
  const ordered = [...rank.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const header = `Repo map: ${symbols.size} files ranked${anchors.length > 0 ? `, anchored on ${anchors.slice(0, 8).join(', ')}` : ''}. Best first; each line is a definition and its line.\n`;
  let text = header;
  let shown = 0;
  for (const [file] of ordered) {
    const defs = symbols.get(file)?.defs ?? [];
    const block = `${file}\n${defs.slice(0, 30).map((def) => `  ${def.kind} ${def.name} (${def.line})`).join('\n')}${defs.length > 30 ? `\n  ... ${defs.length - 30} more` : ''}\n`;
    if (text.length + block.length > budget) {
      if (shown === 0) text += block.slice(0, Math.max(0, budget - text.length));
      break;
    }
    text += block;
    shown += 1;
  }
  if (shown < ordered.length) text += `[${ordered.length - shown} more files not shown; raise max_tokens or name a file in focus]\n`;
  return text;
}

export interface RepoMapToolOptions {
  /** Files the session edited, to anchor the ranking. */
  readonly anchors?: () => readonly string[];
}

/** Parsed files by content hash, so a second map does not parse what has not changed. */
const cache = new Map<string, FileSymbols>();

export function createRepoMapTool(options: RepoMapToolOptions = {}): ToolDefinition {
  return {
    name: 'repo_map',
    deferred: true,
    description: 'A ranked map of the project: the most connected files and the classes, functions and types each defines, cut to a token budget. Name files or symbols in focus to rank what relates to them first.',
    parameters: {
      type: 'object',
      properties: {
        focus: { type: 'array', items: { type: 'string' }, description: 'Files (relative paths) or symbol names to rank around.' },
        max_tokens: { type: 'integer', description: `About how long the map may be. Default ${DEFAULT_MAP_TOKENS}, at most ${MAX_MAP_TOKENS}.` },
      },
      additionalProperties: false,
    },
    effect: 'observe',
    concurrencySafe: true,
    paths: () => [],
    summary: (args) => `repo map${Array.isArray(args['focus']) && args['focus'].length > 0 ? ` around ${(args['focus'] as string[]).join(', ')}` : ''}`,
    async execute(args: ToolArgs, context: ToolContext) {
      const focus = (Array.isArray(args['focus']) ? (args['focus'] as unknown[]) : []).filter((item): item is string => typeof item === 'string').slice(0, 50);
      const maxTokens = Math.min(MAX_MAP_TOKENS, Math.max(200, (args['max_tokens'] as number | undefined) ?? DEFAULT_MAP_TOKENS));
      const listed = await context.ops.search.listFiles({ root: context.workdir, limit: MAX_FILES * 4, excludeGlobs: SECRET_GLOBS });
      const files = listed.map((file) => file.replaceAll('\\', '/').replace(/^\.\//, '')).filter((file) => !isSecretPath(file) && languageOf(file) !== null).sort().slice(0, MAX_FILES);
      const symbols = new Map<string, FileSymbols>();
      for (const file of files) {
        if (context.signal.aborted) break;
        const bytes = await context.ops.read.readFile(join(context.workdir, file)).catch(() => null);
        if (bytes === null || bytes.length > MAX_FILE_BYTES || bytes.includes(0)) continue;
        const key = createHash('sha256').update(file).update('\0').update(bytes).digest('hex');
        const parsed = cache.get(key) ?? (await fileSymbols(file, bytes.toString('utf8')));
        if (parsed === null) continue;
        cache.set(key, parsed);
        symbols.set(file, parsed);
      }
      if (symbols.size === 0) return { content: 'No source files in a language the repo map can read (TypeScript, JavaScript, Python, Go, Rust, Java, Ruby, PHP, C#, C++, CSS, shell).', origin: 'workspace' };
      const anchors = [...new Set([...(options.anchors?.() ?? []), ...focus])];
      const personal = new Map<string, number>();
      for (const anchor of anchors) {
        const path = anchor.replaceAll('\\', '/').replace(/^\.\//, '');
        if (symbols.has(path)) personal.set(path, (personal.get(path) ?? 0) + 10);
        // A symbol name anchors the files that define it.
        for (const [file, parsed] of symbols) if (parsed.defs.some((def) => def.name === anchor)) personal.set(file, (personal.get(file) ?? 0) + 10);
      }
      const text = renderMap(symbols, rankFiles({ symbols, personal }), maxTokens, anchors);
      return { content: wrapUntrusted('workspace', 'repo map', text), origin: 'workspace' };
    },
  };
}
