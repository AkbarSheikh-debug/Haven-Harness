import type { EventType, SessionEvent } from '@hn/core';
import type { MemoryHooks } from '@hn/loop';
import { join } from 'node:path';
import { MemoryIndex, OllamaEmbedder, SessionIndex, buildRecall, buildSnapshot, memoryPaths, runDream, runFlush, type Complete, type DreamReport, type MemoryPaths } from '@hn/memory';
import type { ModelProvider } from '@hn/provider';
import type { TaintTracker } from '@hn/security';
import { createMemorySearchTools, createMemoryTool, createSessionTools, type ToolDefinition } from '@hn/tools';

export interface MemoryWiring {
  readonly hooks: MemoryHooks;
  readonly paths: MemoryPaths;
  readonly notes: readonly string[];
  readonly tools: readonly ToolDefinition[];
  /** One dream sweep for this project. A dry run asks no model and writes nothing. */
  dream(dryRun: boolean): Promise<DreamReport>;
  /** Releases the search index. */
  close(): void;
}

export interface OpenMemoryOptions {
  readonly home: string;
  readonly workdir: string;
  readonly taint: TaintTracker;
  readonly sessionId: string;
  /** A person is at a door to approve a card. */
  readonly attended: boolean;
  /** The person's name, recorded when they approve a long-term write. */
  readonly approver: string;
  /** The session's log as it is now. */
  readonly events: () => readonly SessionEvent[];
  /** This project's folder of session logs, and the key that verifies them. */
  readonly sessionLogs: string;
  readonly logKey: Buffer;
  /** `HN_EMBED_MODEL` names an Ollama embedding model; `HN_OLLAMA_URL` where Ollama is. Unset: keyword-only. */
  readonly env?: NodeJS.ProcessEnv;
  /** Adds a log-only row to the session, such as `memory/search` for a recall. */
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  /** The model the compaction flush and background review use: the summary route. Without one there is no flush. */
  readonly model?: { readonly provider: ModelProvider; readonly model: string; readonly maxOutput: number };
  readonly now?: () => Date;
}

/** A plain model call with no tools, for memory's own small jobs. Thinking models get room to think first. */
export function completeWith(provider: ModelProvider, model: string, maxOutput: number): Complete {
  return async (system, prompt, signal) => {
    const reply = await provider.complete({
      model,
      system,
      tools: [],
      messages: [{ role: 'user', parts: [{ type: 'text', text: prompt }] }],
      maxOutputTokens: Math.min(8_000, maxOutput),
      signal: AbortSignal.any([signal, AbortSignal.timeout(120_000)]),
    });
    return reply.parts.flatMap((part) => (part.type === 'text' ? [part.text] : [])).join('');
  };
}

/** What the user typed to start the current turn. Rows the harness added in between are not the user. */
export function turnRequest(events: readonly SessionEvent[]): string | null {
  const start = events.findLastIndex((event) => event.type === 'turn/start');
  if (start === -1) return null;
  const typed = events.slice(start + 1).find((event) => event.type === 'user/message' && event.origin === 'user');
  return typeof typed?.data['text'] === 'string' ? typed.data['text'] : null;
}

/**
 * Memory for one session. The snapshot is built once, here, and is the same frame for the whole
 * process (frozen, 10.2). Lines that load as quoted data mark the session untrusted before any turn.
 */
export async function openMemory(options: OpenMemoryOptions): Promise<MemoryWiring> {
  const paths = memoryPaths(options.home, options.workdir);
  const now = options.now ?? (() => new Date());
  const snapshot = await buildSnapshot({ paths, now: now() });
  for (const origin of snapshot.untrusted) options.taint.observe(origin);
  const frame = { text: snapshot.text, digest: snapshot.digest, origin: 'memory' as const };
  const memoryTool = createMemoryTool({
    paths,
    sessionId: options.sessionId,
    attended: options.attended,
    tainted: () => options.taint.flags.untrusted,
    worst: () => options.taint.worst,
    turnRequest: () => turnRequest(options.events()),
    approver: options.approver,
    now,
  });
  let index: SessionIndex | null = null;
  const sessionIndex = async (): Promise<SessionIndex> => {
    index ??= SessionIndex.open({ db: join(options.home, 'index', `sessions-${paths.projectKey}.db`), logs: options.sessionLogs, key: options.logKey });
    return index;
  };
  const env = options.env ?? process.env;
  const embedModel = env['HN_EMBED_MODEL'];
  let memoryIndex: MemoryIndex | null = null;
  const searchIndex = async (): Promise<MemoryIndex> => {
    memoryIndex ??= MemoryIndex.open({
      db: join(options.home, 'index', `memory-${paths.projectKey}.db`),
      paths,
      embedder: embedModel === undefined || embedModel === '' ? null : new OllamaEmbedder(embedModel, env['HN_OLLAMA_URL']),
      now,
    });
    return memoryIndex;
  };
  // A query counts toward the dream gates only in a user's turn of a session with nothing untrusted in it.
  const counts = (): boolean => !options.taint.flags.untrusted && turnRequest(options.events()) !== null;
  return {
    paths,
    notes: snapshot.notes,
    tools: [memoryTool, ...createMemorySearchTools({ index: searchIndex, paths, counts }), ...createSessionTools({ index: sessionIndex })],
    dream: (dryRun) =>
      runDream({
        paths,
        sessionLogs: options.sessionLogs,
        key: options.logKey,
        now: now(),
        complete: options.model === undefined ? null : completeWith(options.model.provider, options.model.model, options.model.maxOutput),
        dryRun,
      }),
    close: () => {
      index?.close();
      memoryIndex?.close();
    },
    hooks: {
      snapshot: async () => frame,
      recall: async (query, visible, signal) => {
        const seen = visible.map((row) => (typeof row.data['text'] === 'string' ? row.data['text'] : typeof row.data['content'] === 'string' ? row.data['content'] : '')).join('\n');
        const recall = await buildRecall({ index: await searchIndex(), query, visible: seen, signal });
        // The query is the user's own words, so it always counts toward the dream gates.
        options.record('memory/search', { query: query.slice(0, 500), counts: true, hits: recall?.hits ?? [], keywordOnly: embedModel === undefined || embedModel === '', by: 'recall' });
        if (recall === null) return null;
        for (const origin of recall.untrusted) options.taint.observe(origin);
        return { text: recall.text, digest: recall.digest, origin: 'memory' };
      },
      ...(options.model === undefined
        ? {}
        : {
            flush: async (rows, signal) => {
              const model = options.model as NonNullable<OpenMemoryOptions['model']>;
              await runFlush({
                rows,
                complete: completeWith(model.provider, model.model, model.maxOutput),
                paths,
                sessionId: options.sessionId,
                signal,
                record: (data) => options.record('memory/write', { ...data }),
                now: now(),
              });
            },
          }),
    },
  };
}
