import { HnError, revealHidden } from '@hn/core';
import type { AuditEntry } from '@hn/security';
import { loadTeamLogin, type TeamLogin } from './team.ts';

/**
 * A reader's link to the broker's audit: the person's own LOGIN token (never a session's), the same one `hn login` saved.
 * Everything that comes back is the broker's text about what people did, some of it chosen by those people, so it is only
 * shown through `plain`, which writes hidden characters out and keeps each value on one line.
 */

export interface AuditLink {
  readonly login: TeamLogin;
  readonly fetcher: typeof fetch;
}

export async function openAuditLink(home: string, fetcher: typeof fetch = fetch): Promise<AuditLink> {
  return { login: await loadTeamLogin(home), fetcher };
}

/** One line of text: hidden characters written out, line breaks and tabs turned into spaces, and a length cap. */
export const plain = (value: unknown, max = 200): string => {
  const text = revealHidden(typeof value === 'string' ? value : JSON.stringify(value) ?? '').replace(/[\r\n\t]+/g, ' ');
  return text.length > max ? `${text.slice(0, max)}…` : text;
};

export function auditRequest(link: AuditLink, path: string, signal?: AbortSignal): Promise<Response> {
  return link.fetcher(`${link.login.url}${path}`, { method: 'GET', redirect: 'error', headers: { authorization: `Bearer ${link.login.loginToken}`, 'x-hn-session': link.login.sid }, ...(signal === undefined ? {} : { signal }) });
}

async function refused(response: Response): Promise<HnError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  const why = plain(String(body['error'] ?? response.status));
  return new HnError(response.status === 403 ? 'AUDIT_NOT_A_READER' : 'BROKER_REFUSED', response.status === 403 ? `The broker will not show you the audit: ${why}` : `The broker refused: ${why}`);
}

export async function auditJson<T>(link: AuditLink, path: string): Promise<T> {
  const response = await auditRequest(link, path);
  if (!response.ok) throw await refused(response);
  return (await response.json()) as T;
}

/** A query string from the options that were given, in the order of `names`. */
export function queryOf(values: Readonly<Record<string, string | undefined>>, names: readonly string[]): string {
  const query = new URLSearchParams();
  for (const name of names) if (values[name] !== undefined) query.set(name, values[name] as string);
  const text = query.toString();
  return text === '' ? '' : `?${text}`;
}

/** The lines of a streamed response, parsed, until it ends or `signal` aborts. */
export async function* streamLines(response: Response): AsyncGenerator<Record<string, unknown>> {
  if (response.body === null) return;
  const decoder = new TextDecoder();
  let pending = '';
  for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
    pending += decoder.decode(chunk, { stream: true });
    if (pending.length > 8 * 1024 * 1024) throw new HnError('BROKER_REFUSED', 'The broker sent a line that is far too long.');
    let at = pending.indexOf('\n');
    while (at !== -1) {
      const line = pending.slice(0, at);
      pending = pending.slice(at + 1);
      if (line !== '') yield JSON.parse(line) as Record<string, unknown>;
      at = pending.indexOf('\n');
    }
  }
}

export const rowLine = (row: AuditEntry): string => `#${row.n}  ${row.ts}  ${plain(row.type, 60)}  ${plain(row.data, 240)}`;
