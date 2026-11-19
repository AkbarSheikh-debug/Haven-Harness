import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HnError, sanitizeForDisplay } from '@hn/core';

/**
 * Which model each role runs on (Phase 10, decision 6). A role file can already name a model; this is the person's
 * own say over it, in `<home>/routing.json`, so a cheap or local model can do the reading while a strong one plans
 * and reviews:
 *
 *     { "cheap": "ollama/qwen3:4b", "roles": { "planner": "claude-opus-5-5", "worker": "main" } }
 *
 * `cheap` is the model the `cheap` slot means (the built-in scout uses it). `roles` names a model for a role by name,
 * or `main` (the session's own) or `cheap`. It is read from the person's home only: a repository cannot re-route a
 * person's models, any more than it can set their prices.
 *
 * It is checked when the session opens, and a file with any problem stops the session with every problem listed:
 * nothing is silently ignored and no role silently falls back to another model. Routing changes only which model
 * answers. A role keeps the tools and mode it was given, and a child never holds more than its parent.
 */

export const ROUTING_FILE = 'routing.json';
const MAX_ROUTING_BYTES = 64 * 1024;
const KEYWORDS = ['main', 'cheap'] as const;

export interface Routing {
  /** The concrete model the `cheap` slot means, or null for the built-in choice. */
  readonly cheap: string | null;
  /** Role name to `main`, `cheap` or a model name. */
  readonly roles: ReadonlyMap<string, string>;
}

export const NO_ROUTING: Routing = { cheap: null, roles: new Map() };

/** What the session is, so a route that cannot work is refused when it opens and not on the first call. */
export interface RoutingContext {
  /** The model the session was started with, as given (`ollama/qwen3:14b`, `claude-opus-5-5`). */
  readonly model: string;
  /** Set when the session talks to an OpenAI-compatible address instead of Anthropic; children inherit it. */
  readonly baseUrl?: string;
  /** The laptop holds no key and every call goes through the broker. */
  readonly team: boolean;
  /** The team or local policy's answer for a model name. */
  readonly allowed: (model: string) => boolean;
}

const badName = (name: string): boolean => name === '' || name.length > 200 || /[\u0000-\u001f\u007f\s]/.test(name);
const isKeyword = (name: string): boolean => (KEYWORDS as readonly string[]).includes(name);

export interface ParsedRouting {
  readonly routing: Routing;
  readonly problems: readonly string[];
}

/** The shape of the file only. Whether the roles exist and the models can be used is `checkRouting`. */
export function parseRouting(text: string): ParsedRouting {
  const problems: string[] = [];
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { routing: NO_ROUTING, problems: ['the file is not JSON'] };
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { routing: NO_ROUTING, problems: ['the file is not an object'] };
  const file = raw as Record<string, unknown>;
  for (const key of Object.keys(file)) if (key !== 'cheap' && key !== 'roles') problems.push(`"${sanitizeForDisplay(key)}" is not a setting (only "cheap" and "roles")`);
  let cheap: string | null = null;
  if (file['cheap'] !== undefined) {
    const value = file['cheap'];
    if (typeof value !== 'string' || badName(value)) problems.push('"cheap" must be a model name');
    else if (isKeyword(value)) problems.push('"cheap" must be a real model name, not "main" or "cheap"');
    else cheap = value;
  }
  const roles = new Map<string, string>();
  if (file['roles'] !== undefined) {
    const table = file['roles'];
    if (typeof table !== 'object' || table === null || Array.isArray(table)) problems.push('"roles" must be an object of role names');
    else {
      for (const [role, value] of Object.entries(table)) {
        if (typeof value !== 'string' || badName(value)) problems.push(`role ${sanitizeForDisplay(role)}: the model must be a model name, "main" or "cheap"`);
        else roles.set(role, value);
      }
    }
  }
  return { routing: { cheap, roles }, problems };
}

type Route = 'anthropic' | 'ollama' | 'openai-compatible' | 'team';

function routeOf(context: RoutingContext): Route {
  if (context.team) return 'team';
  if (context.model.startsWith('ollama/')) return 'ollama';
  return context.baseUrl === undefined ? 'anthropic' : 'openai-compatible';
}

/** Why a model cannot be reached from this session, or null. A child inherits its parent's address, so the route is the parent's. */
function unreachable(model: string, route: Route): string | null {
  if (route === 'anthropic' || route === 'team') return null;
  if (route === 'ollama') return model.startsWith('claude-') ? `${model} is an Anthropic model, but this session runs on a local Ollama model and its children use the same route` : null;
  return model.startsWith('claude-') || model.startsWith('ollama/') ? `${model} is not served by the address this session talks to, which its children inherit` : null;
}

/**
 * Everything wrong with a routing, each as a line: a role that does not exist (a typo would otherwise do nothing and
 * say nothing), a model the policy does not allow, and a model this session cannot reach.
 */
export function checkRouting(routing: Routing, knownRoles: readonly string[], context: RoutingContext): string[] {
  const problems: string[] = [];
  const route = routeOf(context);
  const models = new Set<string>();
  if (routing.cheap !== null) models.add(routing.cheap);
  for (const [role, model] of routing.roles) {
    if (!knownRoles.includes(role)) problems.push(`role ${sanitizeForDisplay(role)} does not exist (there are: ${knownRoles.map((name) => sanitizeForDisplay(name)).join(', ')})`);
    if (!isKeyword(model)) models.add(model);
  }
  for (const model of models) {
    if (!context.allowed(model)) problems.push(`the policy does not allow the model ${sanitizeForDisplay(model)}`);
    const why = unreachable(model, route);
    if (why !== null) problems.push(sanitizeForDisplay(why));
  }
  return problems;
}

export interface LoadedRouting {
  readonly routing: Routing;
  /** One line for the person at the start of the session saying what is routed, or none. */
  readonly notes: readonly string[];
}

/** Reads and checks `<home>/routing.json`. No file means the built-in routing. A bad file stops the session. */
export async function loadRouting(home: string, knownRoles: readonly string[], context: RoutingContext): Promise<LoadedRouting> {
  let text: string;
  try {
    text = await readFile(join(home, ROUTING_FILE), 'utf8');
  } catch {
    return { routing: NO_ROUTING, notes: [] };
  }
  const refuse = (problems: readonly string[]): never => {
    throw new HnError('ROUTING_REFUSED', `${ROUTING_FILE} was not used, and the session did not start:\n${problems.map((problem) => `  - ${problem}`).join('\n')}\nFix or remove ${join(home, ROUTING_FILE)}.`);
  };
  if (text.length > MAX_ROUTING_BYTES) return refuse([`the file is larger than ${MAX_ROUTING_BYTES} bytes`]);
  const parsed = parseRouting(text);
  const problems = [...parsed.problems, ...(parsed.problems.length === 0 ? checkRouting(parsed.routing, knownRoles, context) : [])];
  if (problems.length > 0) return refuse(problems);
  const parts = [...(parsed.routing.cheap === null ? [] : [`cheap = ${parsed.routing.cheap}`]), ...[...parsed.routing.roles].map(([role, model]) => `${role} = ${model}`)];
  return { routing: parsed.routing, notes: parts.length === 0 ? [] : [`Model routing from ${ROUTING_FILE}: ${parts.map((part) => sanitizeForDisplay(part)).join(', ')}.`] };
}
