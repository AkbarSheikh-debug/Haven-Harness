import { join } from 'node:path';
import { projectKey } from '@hn/config';
import { ORIGINS, type EventType, type Origin, type SessionEvent } from '@hn/core';
import type { SubagentManager } from '@hn/delegate';
import { Workspaces } from '@hn/operations';
import { MAX_MEMBERS, Team, createLeadTools } from '@hn/orchestrate';
import type { ToolDefinition } from '@hn/tools';

/** Where team members' requests and inbox routes go: set once the team exists. */
export interface TeamHub {
  current: Team | null;
}

export interface TeamSetup {
  readonly workdir: string;
  readonly home: string;
  readonly sessionId: string;
  readonly manager: SubagentManager;
  readonly hub: TeamHub;
  readonly record: (type: EventType, data: Record<string, unknown>) => void;
  readonly events: () => readonly SessionEvent[];
  readonly notify: (text: string, origin: Exclude<Origin, 'user' | 'human-selected'>) => void;
}

/**
 * The Lead's side of an agent team (11.5, experimental). Members are workers started through the manager's leased
 * path (they do not use the eight subagent slots), each in a private clone under `refs/hn/team`; the hub routes their
 * channel requests and inbox to this team.
 */
export function createTeam(setup: TeamSetup): { readonly team: Team; readonly tools: readonly ToolDefinition[] } {
  const workspaces = new Workspaces({ repo: setup.workdir, folder: join(setup.home, 'worktrees', projectKey(setup.workdir), `${setup.sessionId}-team`), namespace: 'refs/hn/team' });
  const team = new Team({
    workspaces,
    record: setup.record,
    events: setup.events,
    notify: setup.notify,
    launch: async ({ name, brief, workdir }, signal) => {
      const result = await setup.manager.leased({ agent: 'worker', task: brief }, { start: 'spawn', workdir, team: name }, signal, undefined, MAX_MEMBERS);
      return { ok: result.ok, text: result.report?.text ?? result.content };
    },
  });
  setup.hub.current = team;
  return { team, tools: createLeadTools(team) };
}

/** An inbox line's origin as the member's loop will log it: never a person, whatever the pipe says. */
export function inboxOrigin(origin: string): Exclude<Origin, 'user' | 'human-selected'> {
  if (!(ORIGINS as readonly string[]).includes(origin) || origin === 'user' || origin === 'human-selected' || origin === 'harness') return 'child';
  return origin as Exclude<Origin, 'user' | 'human-selected'>;
}
