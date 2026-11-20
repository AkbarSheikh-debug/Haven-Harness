import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Guard } from './serve-guard.ts';
import { REPLAY_CSS, REPLAY_JS, REPLAY_PAGE } from './replay-client.ts';
import { SESSION_ID, listSessions, loadReplay } from './replay.ts';

/**
 * The routes of the replay and audit screen. Read-only by construction: only GET is answered, nothing here starts a model
 * session, runs a tool or writes a file, and a session id from the address is matched against the session-id pattern
 * before it is used for anything, then only ever joined to this project's own sessions folder. Every response goes through the
 * guard's `reply`, so it carries the same strict security headers as the rest of `hn serve`.
 */

export interface ReplayRoutes {
  readonly cwd: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly guard: Guard;
}

export const isReplayPath = (path: string): boolean => path === '/replay' || path.startsWith('/replay.') || path.startsWith('/replay/');

/** Answers a request for a replay path, after the guard has checked the host, origin and cookie. */
export async function handleReplay(routes: ReplayRoutes, req: IncomingMessage, res: ServerResponse, path: string): Promise<void> {
  const { guard } = routes;
  if (req.method !== 'GET') return guard.reply(res, 405, 'text/plain; charset=utf-8', 'The replay screen is read-only.', { allow: 'GET' });
  if (path === '/replay') return guard.reply(res, 200, 'text/html; charset=utf-8', REPLAY_PAGE);
  if (path === '/replay.js') return guard.reply(res, 200, 'text/javascript; charset=utf-8', REPLAY_JS);
  if (path === '/replay.css') return guard.reply(res, 200, 'text/css; charset=utf-8', REPLAY_CSS);
  if (path === '/replay/api/sessions') return guard.reply(res, 200, 'application/json', JSON.stringify({ sessions: await listSessions(routes.cwd, routes.env) }));
  const prefix = '/replay/api/session/';
  if (path.startsWith(prefix)) {
    let id: string;
    try {
      id = decodeURIComponent(path.slice(prefix.length));
    } catch {
      return guard.reply(res, 400, 'text/plain; charset=utf-8', 'That is not a session id.');
    }
    if (!SESSION_ID.test(id)) return guard.reply(res, 400, 'text/plain; charset=utf-8', 'That is not a session id.');
    const loaded = await loadReplay(id, routes.cwd, routes.env);
    if (loaded.kind === 'missing') return guard.reply(res, 404, 'text/plain; charset=utf-8', 'There is no log for that session in this project.');
    if (loaded.kind === 'too-large') return guard.reply(res, 413, 'text/plain; charset=utf-8', 'That log is too large to show here.');
    return guard.reply(res, 200, 'application/json', JSON.stringify(loaded.replay));
  }
  return guard.reply(res, 404, 'text/plain; charset=utf-8', 'Not found.');
}
