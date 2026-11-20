import type { SessionEvent } from '@hn/core';
import type { CallCheck, ToolCallRequest, ToolDispatcher, ToolOutcome } from '@hn/loop';
import type { Operations } from '@hn/operations';
import type { ToolSpec } from '@hn/provider';
import { Redactor, type Gate, type PathUse, type TaintTracker } from '@hn/security';
import { createFileTools } from './file-tools.ts';
import { createShellTools } from './shell-tools.ts';
import { createJobTools } from './job-tools.ts';
import { createReadImageTool } from './read-image.ts';
import type { JobManager } from './jobs.ts';
import { ToolProblem, type ToolArgs, type ToolDefinition } from './types.ts';

export const MAX_INLINE_CHARS = 100_000;
export const SPILL_PREVIEW_CHARS = 1_500;
export const MAX_STEP_CHARS = 200_000;

const TOOL_SEARCH: ToolSpec = {
  name: 'tool_search',
  description: 'Find more tools by keyword. Returns their names and argument schemas, to use with call_tool.',
  parameters: {
    type: 'object',
    properties: { query: { type: 'string' } },
    required: ['query'],
    additionalProperties: false,
  },
};

/**
 * The harness's own deferred tools, by name. Without a list a model told to use, say, `read_image` sees no such
 * tool and gives up (found live with qwen3:14b). The list goes in the pinned reminder row, never in the tools
 * array, so the cached prefix stays the same whatever deferred tools a session has. Names from an MCP server
 * are text from outside and stay out.
 */
function deferredNamesOf(tools: readonly ToolDefinition[]): readonly string[] {
  return tools
    .filter((tool) => tool.deferred === true && tool.origin === undefined)
    .map((tool) => tool.name)
    .sort();
}

/** A dispatcher, and the names a reminder row may list for `tool_search`. */
export type HarnessDispatcher = ToolDispatcher & { readonly deferredNames: readonly string[] };

const CALL_TOOL: ToolSpec = {
  name: 'call_tool',
  description: 'Run a tool that tool_search found.',
  parameters: {
    type: 'object',
    properties: { name: { type: 'string' }, args: { type: 'object' } },
    required: ['name', 'args'],
    additionalProperties: false,
  },
};

function asSpec(tool: ToolDefinition): ToolSpec {
  return { name: tool.name, description: tool.description, parameters: tool.parameters };
}

function typeMatches(value: unknown, type: unknown): boolean {
  switch (type) {
    case 'string':
      return typeof value === 'string';
    case 'integer':
      return Number.isSafeInteger(value);
    case 'number':
      return typeof value === 'number';
    case 'boolean':
      return typeof value === 'boolean';
    case 'object':
      return typeof value === 'object' && value !== null && !Array.isArray(value);
    default:
      return true;
  }
}

/** Parsed tool input can be silently truncated, so it is checked here rather than trusted. */
function schemaProblem(args: unknown, parameters: Readonly<Record<string, unknown>>): string | null {
  if (!typeMatches(args, 'object')) return 'Arguments must be a JSON object.';
  const record = args as Record<string, unknown>;
  if ('INVALID_JSON' in record) return `Arguments were not valid JSON: ${JSON.stringify(record['INVALID_JSON'])}`;
  const properties = (parameters['properties'] ?? {}) as Record<string, { type?: unknown }>;
  for (const name of (parameters['required'] ?? []) as string[]) {
    if (!(name in record)) return `Missing required argument "${name}".`;
  }
  for (const [name, value] of Object.entries(record)) {
    const property = properties[name];
    if (property === undefined) return `Unknown argument "${name}". Allowed: ${Object.keys(properties).join(', ')}.`;
    if (!typeMatches(value, property.type)) return `Argument "${name}" must be of type ${String(property.type)}.`;
  }
  return null;
}

export interface DispatcherOptions {
  readonly gate: Gate;
  readonly ops: Operations;
  readonly workdir: string;
  /** Extra definitions. Built-in names cannot be replaced. */
  readonly extraTools?: readonly ToolDefinition[];
  /** Applied to every result before it is bounded, spilled or shown. Defaults to the shape-based redactor. */
  readonly redact?: (text: string) => string;
  /** Told the origin of every result, and given to tools so they can keep written files tainted. */
  readonly taint?: TaintTracker;
  /**
   * Runs after the gate allows a call that changes things and before it executes, bash included. If it
   * throws, the tool does not run: a change that cannot be undone is not made.
   */
  readonly beforeMutation?: (call: { readonly tool: string; readonly writes: readonly string[] }) => Promise<void>;
  /** A note added to a successful change's result, such as a language server's diagnostics. It is project-derived data. */
  readonly afterMutation?: (call: { readonly tool: string; readonly writes: readonly string[] }, signal: AbortSignal) => Promise<string>;
  /** Jobs and terminals. With them, a bash that runs past its timeout keeps going as a background job. */
  readonly jobs?: JobManager;
  /** The session log, so `job_list` can name jobs a crash closed as lost. */
  readonly history?: () => readonly SessionEvent[];
  /** A child's grant: only these tools are registered at all, so nothing else can be found or called. */
  readonly only?: ReadonlySet<string>;
}

const DEFAULT_REDACTOR = new Redactor();

class Dispatcher implements ToolDispatcher {
  readonly specs: readonly ToolSpec[];
  readonly deferredNames: readonly string[];
  readonly #tools = new Map<string, ToolDefinition>();
  readonly #options: DispatcherOptions;
  #stepChars = 0;

  constructor(options: DispatcherOptions) {
    this.#options = options;
    const jobTools = options.jobs === undefined ? [] : createJobTools(options.history ?? (() => []));
    for (const tool of [...createFileTools(), ...createShellTools(options.ops.bash.shell), createReadImageTool(), ...jobTools, ...(options.extraTools ?? [])]) {
      if (this.#tools.has(tool.name)) throw new Error(`Tool ${tool.name} cannot be replaced.`);
      if (options.only !== undefined && !options.only.has(tool.name)) continue;
      this.#tools.set(tool.name, tool);
    }
    // Fixed for the whole session and never varies by mode, because it sits in the cached prefix.
    this.specs = [
      ...[...this.#tools.values()]
        .filter((tool) => tool.deferred !== true)
        .sort((a, b) => a.name.localeCompare(b.name))
        .map(asSpec),
      TOOL_SEARCH,
      CALL_TOOL,
    ];
    this.deferredNames = deferredNamesOf([...this.#tools.values()]);
  }

  beginStep(): void {
    this.#stepChars = 0;
  }

  #find(name: string): ToolDefinition | undefined {
    return this.#tools.get(name) ?? this.#tools.get(name.toLowerCase().replaceAll('-', '_'));
  }

  check(call: ToolCallRequest): CallCheck {
    if (call.name === TOOL_SEARCH.name) {
      const problem = schemaProblem(call.args, TOOL_SEARCH.parameters);
      return problem === null ? { kind: 'ok', name: call.name, args: call.args } : { kind: 'invalid', message: problem };
    }

    let { name, args } = call;
    if (name === CALL_TOOL.name) {
      const problem = schemaProblem(args, CALL_TOOL.parameters);
      if (problem !== null) return { kind: 'invalid', message: problem };
      ({ name, args } = args as { name: string; args: unknown });
      if (name === CALL_TOOL.name) return { kind: 'invalid', message: 'call_tool cannot call itself.' };
      if (name === TOOL_SEARCH.name) return { kind: 'ok', name, args };
    }

    const tool = this.#find(name);
    if (tool === undefined) {
      return { kind: 'unknown', message: `There is no tool called "${name}". Available: ${this.specs.map((spec) => spec.name).join(', ')}.` };
    }
    const problem = schemaProblem(args, tool.parameters);
    return problem === null ? { kind: 'ok', name: tool.name, args } : { kind: 'invalid', message: `${tool.name}: ${problem}` };
  }

  isConcurrencySafe(name: string): boolean {
    return name === TOOL_SEARCH.name || this.#tools.get(name)?.concurrencySafe === true;
  }

  touches(name: string, args: unknown): { reads: string[]; writes: string[] } {
    const uses: readonly PathUse[] = this.#tools.get(name)?.paths(args as ToolArgs) ?? [];
    return {
      reads: uses.filter((use) => !use.write).map((use) => use.path),
      writes: uses.filter((use) => use.write).map((use) => use.path),
    };
  }

  #search(args: ToolArgs): ToolOutcome {
    const terms = String(args['query']).toLowerCase().split(/\s+/).filter(Boolean);
    const hits = [...this.#tools.values()].filter(
      (tool) => tool.deferred === true && terms.some((term) => `${tool.name} ${tool.description}`.toLowerCase().includes(term)),
    );
    const content = hits.length === 0 ? 'No tools matched.' : JSON.stringify(hits.map(asSpec), null, 2);
    // A description written by an MCP server is text from outside, so a search that returns one carries that origin.
    const outside = hits.find((tool) => tool.origin !== undefined);
    return { content, isError: false, origin: outside?.origin ?? 'harness' };
  }

  async #bounded(content: string, callId: string): Promise<string> {
    const over = content.length > MAX_INLINE_CHARS || this.#stepChars + content.length > MAX_STEP_CHARS;
    if (!over) {
      this.#stepChars += content.length;
      return content;
    }
    const path = await this.#options.ops.spill.spill(`${callId}.txt`, Buffer.from(content, 'utf8'));
    const half = SPILL_PREVIEW_CHARS / 2;
    this.#stepChars += SPILL_PREVIEW_CHARS;
    return `${content.slice(0, half)}\n... ${content.length - SPILL_PREVIEW_CHARS} characters omitted. Full output: ${path} ...\n${content.slice(-half)}`;
  }

  /** The one route to a tool body: gate first, and a failure becomes a message, never a throw. */
  async run(call: ToolCallRequest, signal: AbortSignal): Promise<ToolOutcome> {
    if (call.name === TOOL_SEARCH.name) return this.#search(call.args as ToolArgs);
    const tool = this.#tools.get(call.name);
    if (tool === undefined) return { content: `There is no tool called "${call.name}".`, isError: true, origin: 'harness' };

    const args = call.args as ToolArgs;
    try {
      // A tool that can never run in this session says so before any card is drawn.
      const refusal = tool.refuse?.(args) ?? null;
      if (refusal !== null) return { content: refusal, isError: true, origin: 'harness' };
      const command = tool.command?.(args);
      // For showing only. The gate builds it after its own checks, when it is about to ask; a preview that fails is no preview.
      const preview = tool.preview;
      const decision = await this.#options.gate.check({
        id: call.id,
        tool: tool.name,
        args,
        effect: tool.effect,
        paths: tool.paths(args),
        summary: tool.summary(args),
        ...(tool.target === undefined ? {} : { target: tool.target(args) }),
        ...(command === undefined ? {} : { command }),
        ...(preview === undefined ? {} : { preview: () => preview.call(tool, args, { workdir: this.#options.workdir, ops: this.#options.ops }) }),
        ...(tool.requiresHuman?.(args) === true ? { requiresHuman: true } : {}),
      });
      if (decision.kind !== 'allowed-once') return { content: decision.reason, isError: true, origin: 'harness' };

      if (tool.effect !== 'observe' && this.#options.beforeMutation !== undefined) {
        try {
          await this.#options.beforeMutation({ tool: tool.name, writes: tool.paths(args).filter((use) => use.write).map((use) => use.path) });
        } catch (error) {
          return { content: error instanceof Error ? error.message : String(error), isError: true, origin: 'harness' };
        }
      }

      const result = await tool.execute(args, {
        workdir: this.#options.workdir,
        ops: this.#options.ops,
        signal,
        callId: call.id,
        ...(this.#options.taint === undefined ? {} : { taint: this.#options.taint }),
        ...(this.#options.jobs === undefined ? {} : { jobs: this.#options.jobs }),
      });
      this.#options.taint?.observe(result.origin ?? 'tool-output');
      const writes = tool.paths(args).filter((use) => use.write).map((use) => use.path);
      const note = tool.effect === 'observe' || result.isError === true || this.#options.afterMutation === undefined ? '' : await this.#options.afterMutation({ tool: tool.name, writes }, signal).catch(() => '');
      if (note !== '') this.#options.taint?.observe('workspace');
      const text = result.content === '' && note === '' ? '(no output)' : `${result.content}${note}`;
      return {
        // Redacted before it is bounded, so a spill file never holds a secret the model was not shown.
        content: await this.#bounded((this.#options.redact ?? ((value) => DEFAULT_REDACTOR.redact(value)))(text), call.id),
        isError: result.isError === true,
        origin: result.origin ?? 'tool-output',
        ...(result.cancelled === true ? { cancelled: true } : {}),
        ...(result.records === undefined || result.isError === true ? {} : { records: result.records }),
        ...(result.images === undefined || result.isError === true ? {} : { images: result.images }),
      };
    } catch (error) {
      const message = error instanceof ToolProblem ? error.message : `${tool.name} failed: ${error instanceof Error ? error.message : String(error)}`;
      return { content: message, isError: true, origin: 'harness' };
    }
  }
}

export function createDispatcher(options: DispatcherOptions): HarnessDispatcher {
  return new Dispatcher(options);
}
