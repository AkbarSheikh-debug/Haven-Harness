import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sanitizeForDisplay } from '@hn/core';
import { git } from '@hn/operations';
import { wrapUntrusted, type ToolDefinition } from '@hn/tools';
import { teamToken, type TeamLogin } from './team.ts';

/**
 * The broker's server-side tools in a team session. Each is a deferred tool of the session, so the
 * local gate sees it like any other (all are `external`: a person approves them below dont-ask), and the broker
 * decides again on every call, so a client that skips its gate still gets only what policy allows. MCP results are
 * `mcp` data in the untrusted wrapper. `git_push` sends a bundle of the project's HEAD; the broker pushes it.
 */

interface Listing {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

async function brokerCall(login: TeamLogin, session: string, path: string, body?: unknown): Promise<Record<string, unknown>> {
  const response = await fetch(`${login.url}${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    redirect: 'error',
    headers: { authorization: `Bearer ${await teamToken(login, session)}`, 'x-hn-session': session, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const parsed = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  if (!response.ok) return { ok: false, text: `The broker refused: ${String(parsed['error'] ?? response.status)}` };
  return parsed;
}

/** HEAD of the project, as a git bundle, base64. Made with the harness's hardened git, so the project's config runs nothing. */
async function bundleHead(root: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'hn-bundle-'));
  try {
    await git(['bundle', 'create', '--quiet', join(dir, 'head.bundle'), 'HEAD'], { cwd: root });
    return (await readFile(join(dir, 'head.bundle'))).toString('base64');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * Team memory. Searching returns only what the broker lets this person read, as untrusted data: another
 * person's words are not instructions. Saving always needs a person's yes, and the session's taint
 * goes with it, so the broker keeps anything learned from untrusted text to its writer alone.
 */
function teamMemoryTools(login: TeamLogin, session: string): ToolDefinition[] {
  const search: ToolDefinition = {
    name: 'team_memory_search',
    description: 'Searches the team memory you are allowed to read (your own entries, your OU, your roles, the organisation).',
    parameters: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] },
    deferred: true,
    effect: 'observe',
    concurrencySafe: true,
    paths: () => [],
    summary: (args) => `search team memory for ${String(args['query'])}`,
    async execute(args) {
      const found = await brokerCall(login, session, `/v1/memory?q=${encodeURIComponent(String(args['query'] ?? ''))}`);
      if (!Array.isArray(found['entries'])) return { content: String(found['text'] ?? 'The broker gave no answer.'), isError: true };
      const entries = found['entries'] as { text: string; by: string; when: string; why: string }[];
      const text = entries.length === 0 ? 'Nothing found.' : entries.map((entry) => `- ${entry.text} (by ${entry.by}, ${entry.when.slice(0, 10)}; ${entry.why})`).join('\n');
      return { content: wrapUntrusted('team memory', String(args['query'] ?? ''), sanitizeForDisplay(text)), origin: 'memory' };
    },
  };
  const save: ToolDefinition = {
    name: 'team_memory_save',
    description: 'Saves one fact to team memory. share: user (only you), ou, role or org, as the policy allows; for ou or role give value.',
    parameters: { type: 'object', properties: { text: { type: 'string' }, why: { type: 'string' }, share: { type: 'string', enum: ['user', 'ou', 'role', 'org'] }, value: { type: 'string' }, expires: { type: 'string' } }, required: ['text', 'why', 'share'] },
    deferred: true,
    effect: 'external',
    concurrencySafe: false,
    paths: () => [],
    requiresHuman: () => true,
    summary: (args) => `save to team memory (${String(args['share'])}): ${String(args['text']).slice(0, 200)}`,
    target: (args) => `team memory, shared with ${String(args['share'])}${args['value'] === undefined ? '' : ` ${String(args['value'])}`}`,
    async execute(args, context) {
      const share = String(args['share'] ?? 'user');
      const body = {
        text: args['text'],
        why: args['why'],
        visibility: share === 'ou' || share === 'role' ? { kind: share, value: args['value'] } : { kind: share },
        // Fails closed: with no tracker the text counts as untrusted.
        taint: context.taint === undefined || context.taint.flags.untrusted ? 'untrusted' : 'clean',
        origin: 'user',
        ...(typeof args['expires'] === 'string' ? { expires: args['expires'] } : {}),
      };
      const saved = await brokerCall(login, session, '/v1/memory', body);
      return typeof saved['id'] === 'string' ? { content: `Saved as ${saved['id']}${saved['expires'] === null || saved['expires'] === undefined ? '' : `, until ${String(saved['expires'])}`}.` } : { content: sanitizeForDisplay(String(saved['text'] ?? saved['error'] ?? 'Refused.')), isError: true };
    },
  };
  return [search, save];
}

export async function createTeamTools(login: TeamLogin, session: string, root: string, notes: string[]): Promise<ToolDefinition[]> {
  let listings: Listing[];
  try {
    const listed = await brokerCall(login, session, '/v1/tools');
    listings = Array.isArray(listed['tools']) ? (listed['tools'] as Listing[]) : [];
  } catch (error) {
    notes.push(`The broker's server-side tools are not available: ${error instanceof Error ? error.message : String(error)}`);
    return [];
  }
  const fromBroker = listings
    .filter((listing) => typeof listing.name === 'string' && /^(mcp__[a-z0-9_-]+__[A-Za-z0-9_-]+|git_push)$/.test(listing.name))
    .map((listing): ToolDefinition => {
      const push = listing.name === 'git_push';
      return {
        name: listing.name,
        description: `${push ? '' : '[server-side, from the broker] '}${String(listing.description).slice(0, 2000)}`,
        parameters: push ? { type: 'object', properties: { repo: { type: 'string' }, branch: { type: 'string' } }, required: ['repo', 'branch'] } : listing.inputSchema,
        deferred: true,
        effect: 'external',
        concurrencySafe: false,
        ...(push ? {} : { origin: 'mcp' as const }),
        paths: () => [],
        summary: (args) => (push ? `push HEAD to ${String(args['repo'])} ${String(args['branch'])}` : `${listing.name} on the broker`),
        target: (args) => (push ? `${String(args['repo'])} branch ${String(args['branch'])}` : `${login.url} (${listing.name})`),
        async execute(args) {
          const sent = push ? { repo: args['repo'], branch: args['branch'], bundle: await bundleHead(root) } : args;
          const result = await brokerCall(login, session, '/v1/tools/call', { name: listing.name, args: sent });
          const text = sanitizeForDisplay(String(result['text'] ?? ''));
          if (push) return { content: text, ...(result['ok'] === true ? {} : { isError: true }) };
          return { content: wrapUntrusted('mcp', listing.name, text), origin: 'mcp', ...(result['ok'] === true ? {} : { isError: true }) };
        },
      };
    });
  return [...fromBroker, ...teamMemoryTools(login, session)];
}
