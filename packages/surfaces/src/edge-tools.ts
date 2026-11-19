import { readFile } from 'node:fs/promises';
import { toolCallsOf, type SessionEvent } from '@hn/core';
import type { Operations } from '@hn/operations';
import type { EgressPolicy } from '@hn/security';
import { createTeamTools } from './team-tools.ts';
import type { TeamLogin } from './team.ts';
import { LspManager, createBrowserTool, createLspTool, createRepoMapTool, lspConfigPath, parseLspConfig, type HarnessExec, type ToolDefinition } from '@hn/tools';

/**
 * Phase 7's tools for a session, in one place so `session.ts` stays a list of sockets: the repo map, and (as their tasks
 * land) the LSP and browser tools. Each is deferred, so the prompt's `tools` array does not change.
 */

export interface EdgeToolOptions {
  readonly events: () => readonly SessionEvent[];
  readonly exec: HarnessExec;
  readonly ops: Operations;
  readonly root: string;
  readonly home: string;
  readonly tier: number;
  readonly egress: EgressPolicy;
  /** True once all three legs of the Rule of Two hold. */
  readonly tainted: () => boolean;
  /** The shell the session's commands really run in, so a server's command line is quoted for it. */
  readonly shell: 'bash' | 'powershell' | 'posix';
  /** The session's notes for the person, such as a config file that was not used. */
  readonly notes?: string[];
  /** Team mode: the broker's server-side tools for this person (Phase 8). */
  readonly team?: { readonly login: TeamLogin; readonly session: string };
}

export interface EdgeTools {
  readonly tools: readonly ToolDefinition[];
  /** Language-server diagnostics after a change, when a server for the file is running. */
  readonly afterMutation: (call: { readonly tool: string; readonly writes: readonly string[] }) => Promise<string>;
  readonly notes: readonly string[];
  close(): void;
}

const EDITING_TOOLS = new Set(['write_file', 'edit_file', 'apply_patch']);

/** Files the session wrote or edited, newest last, for anchoring the repo map. */
export function editedFiles(events: readonly SessionEvent[]): string[] {
  const seen = new Set<string>();
  for (const event of events) {
    for (const call of toolCallsOf(event)) {
      const path = (call.args as { path?: unknown } | null)?.path;
      if (EDITING_TOOLS.has(call.name) && typeof path === 'string') {
        seen.delete(path);
        seen.add(path);
      }
    }
  }
  return [...seen].slice(-20);
}

export async function createEdgeTools(options: EdgeToolOptions): Promise<EdgeTools> {
  const notes: string[] = options.notes ?? [];
  const text = await readFile(lspConfigPath(options.home), 'utf8').catch(() => null);
  let servers: ReturnType<typeof parseLspConfig> = [];
  try {
    servers = text === null ? [] : parseLspConfig(text);
  } catch (error) {
    notes.push(`~/.hn/lsp.json was not used: ${error instanceof Error ? error.message : String(error)}`);
  }
  const browser = createBrowserTool({ policy: options.egress, tainted: options.tainted });
  const lsp = servers.length === 0 ? null : new LspManager({ servers, exec: options.exec, ops: options.ops, root: options.root, shell: options.shell });
  return {
    tools: [createRepoMapTool({ anchors: () => editedFiles(options.events()) }), browser.tool, ...(lsp === null ? [] : [createLspTool(lsp)]), ...(options.team === undefined ? [] : await createTeamTools(options.team.login, options.team.session, options.root, notes))],
    afterMutation: async (call) => (lsp === null ? '' : lsp.afterEdit(call.writes)),
    notes,
    close: () => {
      lsp?.close();
      void browser.close();
    },
  };
}
