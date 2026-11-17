import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { HnError } from '@hn/core';
import type { Effect } from '@hn/security';
import type { McpServerConfig } from '@hn/tools';

/**
 * MCP servers come from the user's own file, `<home>/mcp.json`, and nowhere else. A project's `.mcp.json` is a
 * control file the project controls, so it is never read here: project-level servers are off by default.
 */

const MAX_BYTES = 64 * 1024;
const MAX_SERVERS = 20;
const EFFECTS: readonly string[] = ['observe', 'reversible', 'execution', 'external', 'irreversible'];
const SERVER_KEYS = new Set(['name', 'command', 'args', 'env', 'version', 'effects']);

const bad = (message: string): never => {
  throw new HnError('MCP_CONFIG_INVALID', `mcp.json: ${message}`);
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

function stringRecord(value: unknown, where: string): Record<string, string> {
  if (!isRecord(value)) return bad(`${where} must be an object of strings.`);
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== 'string') return bad(`${where}.${key} must be a string.`);
    out[key] = item;
  }
  return out;
}

/** Reads and checks the user's MCP configuration. A missing file means no servers. Anything odd in it is an error, never ignored. */
export async function loadMcpConfig(home: string): Promise<McpServerConfig[]> {
  let text: string;
  try {
    text = await readFile(join(home, 'mcp.json'), 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  if (Buffer.byteLength(text) > MAX_BYTES) return bad(`the file is larger than ${MAX_BYTES} bytes.`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return bad('the file is not valid JSON.');
  }
  if (!isRecord(parsed) || Object.keys(parsed).some((key) => key !== 'servers') || !Array.isArray(parsed['servers'])) return bad('expected {"servers": [...]} and nothing else.');
  if (parsed['servers'].length > MAX_SERVERS) return bad(`more than ${MAX_SERVERS} servers.`);

  const seen = new Set<string>();
  return parsed['servers'].map((entry: unknown, index): McpServerConfig => {
    const where = `servers[${index}]`;
    if (!isRecord(entry)) return bad(`${where} must be an object.`);
    for (const key of Object.keys(entry)) if (!SERVER_KEYS.has(key)) return bad(`${where} has an unknown field "${key}".`);
    const { name, command, args, env, version, effects } = entry;
    if (typeof name !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(name)) return bad(`${where}.name must be lowercase letters, digits, "_" or "-".`);
    if (seen.has(name)) return bad(`${where}.name "${name}" is used twice.`);
    seen.add(name);
    if (typeof command !== 'string' || !isAbsolute(command)) return bad(`${where}.command must be an absolute path.`);
    if (typeof version !== 'string' || version === '') return bad(`${where}.version is required: it pins the one version that is approved.`);
    if (args !== undefined && (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string'))) return bad(`${where}.args must be a list of strings.`);
    const effectMap = effects === undefined ? undefined : stringRecord(effects, `${where}.effects`);
    for (const [tool, effect] of Object.entries(effectMap ?? {})) if (!EFFECTS.includes(effect)) return bad(`${where}.effects.${tool} must be one of ${EFFECTS.join(', ')}.`);
    return {
      name,
      version,
      process: { command, ...(args === undefined ? {} : { args: args as string[] }), ...(env === undefined ? {} : { env: stringRecord(env, `${where}.env`) }) },
      ...(effectMap === undefined ? {} : { effects: effectMap as Record<string, Effect> }),
    };
  });
}
