import { extname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LspClient, fileUri, type LspDiagnostic, type Operations } from '@hn/operations';
import { isSecretPath } from '@hn/security';
import type { HarnessExec } from './harness-exec.ts';
import { ToolProblem, stringArg, type ToolArgs, type ToolDefinition } from './types.ts';
import { wrapUntrusted } from './web-tools.ts';

/**
 * Language servers (decision 6). Servers come only from the user's `~/.hn/lsp.json`. A server runs project code, so
 * starting one is a gated `lsp` call (a person approves it below tier 3), and it is started by the session's own process
 * operations, so in a box it runs in the box. What it says is derived from project files: `workspace` data.
 */

export interface LspServerConfig {
  readonly name: string;
  /** Absolute path. */
  readonly command: string;
  readonly args: readonly string[];
  /** File extensions it serves, such as `.ts`. */
  readonly extensions: readonly string[];
}

const FIELDS = new Set(['name', 'command', 'args', 'extensions']);

/** `{ "servers": [{ "name", "command", "args", "extensions" }] }`, refusing anything else. */
export function parseLspConfig(text: string): LspServerConfig[] {
  const parsed = JSON.parse(text) as unknown;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed) || !Array.isArray((parsed as Record<string, unknown>)['servers'])) throw new ToolProblem('BAD_LSP_CONFIG', 'lsp.json needs a "servers" list.');
  for (const key of Object.keys(parsed)) if (key !== 'servers') throw new ToolProblem('BAD_LSP_CONFIG', `lsp.json has an unknown field "${key}".`);
  return ((parsed as Record<string, unknown>)['servers'] as unknown[]).map((entry) => {
    const item = (typeof entry === 'object' && entry !== null && !Array.isArray(entry) ? entry : {}) as Record<string, unknown>;
    for (const key of Object.keys(item)) if (!FIELDS.has(key)) throw new ToolProblem('BAD_LSP_CONFIG', `A server has an unknown field "${key}".`);
    const name = item['name'];
    const command = item['command'];
    const args = item['args'] ?? [];
    const extensions = item['extensions'];
    if (typeof name !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(name)) throw new ToolProblem('BAD_LSP_CONFIG', 'A server name is 1 to 32 lowercase letters, digits or dashes.');
    if (typeof command !== 'string' || !isAbsolute(command)) throw new ToolProblem('BAD_LSP_CONFIG', `Server ${name}: "command" must be an absolute path.`);
    if (!Array.isArray(args) || !args.every((arg) => typeof arg === 'string')) throw new ToolProblem('BAD_LSP_CONFIG', `Server ${name}: "args" must be strings.`);
    if (!Array.isArray(extensions) || !extensions.every((ext) => typeof ext === 'string' && /^\.[a-z0-9]+$/i.test(ext))) throw new ToolProblem('BAD_LSP_CONFIG', `Server ${name}: "extensions" must look like ".ts".`);
    return { name, command, args: args as string[], extensions: (extensions as string[]).map((ext) => ext.toLowerCase()) };
  });
}

/** The shell line that starts a server, quoted for the shell the session's commands really run in. */
export function serverCommand(server: LspServerConfig, shell: 'bash' | 'powershell' | 'posix'): string {
  if (shell === 'powershell') return `& ${[server.command, ...server.args].map((part) => `'${part.replaceAll("'", "''")}'`).join(' ')}`;
  return [server.command, ...server.args].map((part) => `'${part.replaceAll("'", `'\\''`)}'`).join(' ');
}

const LANGUAGE_IDS: Readonly<Record<string, string>> = {
  '.ts': 'typescript', '.mts': 'typescript', '.cts': 'typescript', '.tsx': 'typescriptreact', '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.jsx': 'javascriptreact', '.py': 'python', '.go': 'go', '.rs': 'rust', '.java': 'java', '.rb': 'ruby', '.php': 'php', '.cs': 'csharp', '.cpp': 'cpp', '.c': 'c', '.h': 'c',
};
const SEVERITY = ['', 'error', 'warning', 'info', 'hint'];
const OPS = ['definition', 'references', 'implementation', 'hover', 'diagnostics', 'symbols'] as const;
type LspOp = (typeof OPS)[number];
const MAX_ITEMS = 50;

interface Location {
  readonly uri: string;
  readonly line: number;
  readonly character: number;
}

function locations(result: unknown): Location[] {
  const list = Array.isArray(result) ? result : result === null || result === undefined ? [] : [result];
  return list.flatMap((item: unknown) => {
    const value = item as { uri?: unknown; range?: { start?: { line?: unknown; character?: unknown } }; targetUri?: unknown; targetSelectionRange?: { start?: { line?: unknown; character?: unknown } } };
    const uri = typeof value.uri === 'string' ? value.uri : typeof value.targetUri === 'string' ? value.targetUri : null;
    const start = value.range?.start ?? value.targetSelectionRange?.start;
    if (uri === null || typeof start?.line !== 'number') return [];
    return [{ uri, line: start.line, character: typeof start.character === 'number' ? start.character : 0 }];
  });
}

function hoverText(result: unknown): string {
  const contents = (result as { contents?: unknown } | null)?.contents;
  const one = (part: unknown): string => (typeof part === 'string' ? part : typeof (part as { value?: unknown })?.value === 'string' ? (part as { value: string }).value : '');
  const text = Array.isArray(contents) ? contents.map(one).join('\n') : one(contents);
  return text.length > 4_000 ? `${text.slice(0, 4_000)}\n[cut]` : text;
}

function symbolLines(result: unknown, depth = 0, out: string[] = []): string[] {
  for (const item of Array.isArray(result) ? result : []) {
    if (out.length >= 200) break;
    const value = item as { name?: unknown; kind?: unknown; range?: { start?: { line?: number } }; location?: { range?: { start?: { line?: number } } }; children?: unknown };
    const line = (value.range?.start?.line ?? value.location?.range?.start?.line ?? 0) + 1;
    if (typeof value.name === 'string') out.push(`${'  '.repeat(depth)}${value.name} (line ${line})`);
    if (Array.isArray(value.children)) symbolLines(value.children, depth + 1, out);
  }
  return out;
}

const diagnosticLines = (list: readonly LspDiagnostic[]): string[] =>
  list.slice(0, MAX_ITEMS).map((d) => `${d.range.start.line + 1}:${d.range.start.character + 1} ${SEVERITY[d.severity ?? 1] ?? 'error'} ${d.message.replace(/\s+/g, ' ').slice(0, 300)}`);

export interface LspManagerOptions {
  readonly servers: readonly LspServerConfig[];
  readonly exec: HarnessExec;
  readonly ops: Operations;
  readonly root: string;
  readonly shell: 'bash' | 'powershell' | 'posix';
}

/** The session's language servers: started on first use, after the gate allows it; stopped when the session ends. */
export class LspManager {
  readonly #options: LspManagerOptions;
  readonly #clients = new Map<string, Promise<LspClient>>();
  readonly #documents = new Map<string, { version: number; text: string }>();

  constructor(options: LspManagerOptions) {
    this.#options = options;
  }

  serverFor(path: string): LspServerConfig | null {
    const ext = extname(path).toLowerCase();
    return this.#options.servers.find((server) => server.extensions.includes(ext)) ?? null;
  }

  /** The running client for a file, starting its server if the gate allows. Throws with the reason when it cannot. */
  async client(path: string): Promise<LspClient> {
    const server = this.serverFor(path);
    if (server === null) throw new ToolProblem('LSP_NO_SERVER', `No language server is set up for ${extname(path) || 'this file'} files. Add one to ~/.hn/lsp.json.`);
    const existing = this.#clients.get(server.name);
    if (existing !== undefined) {
      const client = await existing;
      if (!client.closed) return client;
      this.#clients.delete(server.name);
    }
    const starting = (async () => {
      const processes = this.#options.ops.processes;
      if (processes === undefined) throw new ToolProblem('LSP_UNAVAILABLE', 'This backend cannot keep a language server running.');
      const command = serverCommand(server, this.#options.shell);
      const allowed = await this.#options.exec.allow({ purpose: 'lsp', command });
      if (!allowed.ok) throw new ToolProblem('LSP_NOT_ALLOWED', `The language server ${server.name} was not started: ${allowed.reason}`);
      const client = new LspClient(processes.start(command, { cwd: this.#options.root, input: true }));
      await client.initialize(this.#options.root);
      return client;
    })();
    this.#clients.set(server.name, starting);
    starting.catch(() => this.#clients.delete(server.name));
    return starting;
  }

  /** Tells the server what the file holds now. */
  async #sync(client: LspClient, absolute: string): Promise<string> {
    const text = (await this.#options.ops.read.readFile(absolute)).toString('utf8');
    const uri = fileUri(absolute);
    const open = this.#documents.get(uri);
    if (open === undefined) {
      client.notify('textDocument/didOpen', { textDocument: { uri, languageId: LANGUAGE_IDS[extname(absolute).toLowerCase()] ?? 'plaintext', version: 1, text } });
      this.#documents.set(uri, { version: 1, text });
    } else if (open.text !== text) {
      const version = open.version + 1;
      client.notify('textDocument/didChange', { textDocument: { uri, version }, contentChanges: [{ text }] });
      this.#documents.set(uri, { version, text });
    }
    return uri;
  }

  async #where(location: Location): Promise<string> {
    let path: string;
    try {
      path = fileURLToPath(location.uri);
    } catch {
      return `${location.uri} (not a file)`;
    }
    const rel = relative(this.#options.root, path).replaceAll('\\', '/');
    if (rel.startsWith('..') || isAbsolute(rel)) return `(a file outside the project, line ${location.line + 1})`;
    if (isSecretPath(rel)) return `${rel}:${location.line + 1} (a secret file; not shown)`;
    const line = await this.#options.ops.read.readFile(path).then((bytes) => bytes.toString('utf8').split(/\r?\n/)[location.line] ?? '', () => '');
    return `${rel}:${location.line + 1}:${location.character + 1}  ${line.trim().slice(0, 200)}`;
  }

  async query(op: LspOp, path: string, line: number, column: number): Promise<string> {
    const absolute = resolve(this.#options.root, path);
    const client = await this.client(absolute);
    const uri = await this.#sync(client, absolute);
    const position = { textDocument: { uri }, position: { line: Math.max(0, line - 1), character: Math.max(0, column - 1) } };
    if (op === 'diagnostics') {
      await client.settle(300, 1_500);
      const lines = diagnosticLines(client.diagnostics(uri));
      return lines.length === 0 ? `No problems reported in ${path}.` : lines.join('\n');
    }
    if (op === 'symbols') {
      const lines = symbolLines(await client.request('textDocument/documentSymbol', { textDocument: { uri } }));
      return lines.length === 0 ? 'No symbols.' : lines.join('\n');
    }
    if (op === 'hover') return hoverText(await client.request('textDocument/hover', position)) || 'Nothing to show here.';
    const method = op === 'references' ? 'textDocument/references' : op === 'implementation' ? 'textDocument/implementation' : 'textDocument/definition';
    const found = locations(await client.request(method, op === 'references' ? { ...position, context: { includeDeclaration: true } } : position));
    if (found.length === 0) return `No ${op} found.`;
    const shown = await Promise.all(found.slice(0, MAX_ITEMS).map((location) => this.#where(location)));
    return `${shown.join('\n')}${found.length > MAX_ITEMS ? `\n[${found.length - MAX_ITEMS} more]` : ''}`;
  }

  /** After a change: diagnostics for each written file whose server is already running. Never starts a server. */
  async afterEdit(paths: readonly string[]): Promise<string> {
    const notes: string[] = [];
    for (const path of paths.slice(0, 5)) {
      const server = this.serverFor(path);
      const running = server === null ? undefined : this.#clients.get(server.name);
      if (running === undefined) continue;
      const client = await running.catch(() => null);
      if (client === null || client.closed) continue;
      const absolute = resolve(this.#options.root, path);
      const uri = await this.#sync(client, absolute).catch(() => null);
      if (uri === null) continue;
      await client.settle(300, 1_500);
      const errors = client.diagnostics(uri).filter((d) => (d.severity ?? 1) === 1);
      if (errors.length > 0) notes.push(`${path}:\n${diagnosticLines(errors).join('\n')}`);
    }
    return notes.length === 0 ? '' : `\n\nThe language server reports errors after this change:\n${wrapUntrusted('workspace', 'lsp diagnostics', notes.join('\n'))}`;
  }

  close(): void {
    for (const client of this.#clients.values()) void client.then((c) => c.close(), () => undefined);
    this.#clients.clear();
  }
}

export function createLspTool(manager: LspManager): ToolDefinition {
  return {
    name: 'lsp',
    deferred: true,
    description: 'Ask the language server about code: definition, references, implementation, hover (type and docs), diagnostics (errors in a file), symbols (outline of a file). Lines and columns start at 1.',
    parameters: {
      type: 'object',
      properties: {
        op: { type: 'string', enum: [...OPS] },
        path: { type: 'string', description: 'File, relative to the project.' },
        line: { type: 'integer', description: 'For definition, references, implementation and hover.' },
        column: { type: 'integer', description: 'For definition, references, implementation and hover.' },
      },
      required: ['op', 'path'],
      additionalProperties: false,
    },
    effect: 'observe',
    concurrencySafe: true,
    paths: (args) => [{ path: stringArg(args, 'path'), write: false }],
    summary: (args) => `lsp ${stringArg(args, 'op')} ${stringArg(args, 'path')}${typeof args['line'] === 'number' ? `:${args['line']}` : ''}`,
    async execute(args: ToolArgs) {
      const op = stringArg(args, 'op') as LspOp;
      if (!OPS.includes(op)) throw new ToolProblem('LSP_BAD_OP', `op must be one of: ${OPS.join(', ')}.`);
      const needsPosition = op !== 'diagnostics' && op !== 'symbols';
      if (needsPosition && (typeof args['line'] !== 'number' || typeof args['column'] !== 'number')) throw new ToolProblem('LSP_NO_POSITION', `${op} needs a line and a column.`);
      const text = await manager.query(op, stringArg(args, 'path'), (args['line'] as number | undefined) ?? 1, (args['column'] as number | undefined) ?? 1);
      return { content: wrapUntrusted('workspace', `lsp ${op}`, text), origin: 'workspace' };
    },
  };
}

/** `~/.hn/lsp.json` under a home folder, for the session. */
export const lspConfigPath = (home: string): string => join(home, 'lsp.json');
