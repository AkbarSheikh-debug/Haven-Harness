import { ProviderError, classifyStatus } from './errors.ts';
import type { ModelProvider, ModelReply, StreamEvent } from './types.ts';

/**
 * The client's end of team mode: the laptop sends its request to the broker and holds no
 * model key at all. The broker answers with one JSON line per stream event and a last line holding the reply or
 * an error. A refusal (no such model for this person, budget spent, a bad token) is an error the loop shows.
 */

export interface BrokerProviderOptions {
  readonly url: string;
  /** The session token, fetched per call so a refreshed one is used at once. */
  readonly token: () => string | Promise<string>;
  readonly session: string;
  readonly fetch?: typeof fetch;
}

const MAX_LINE = 64 * 1024 * 1024;

export function createBrokerProvider(options: BrokerProviderOptions): ModelProvider {
  const send = options.fetch ?? fetch;
  return {
    route: 'broker',
    async complete(request) {
      const { signal, onEvent, ...wire } = request;
      let response: Response;
      try {
        response = await send(`${options.url}/v1/model`, {
          method: 'POST',
          redirect: 'error',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${await options.token()}`, 'x-hn-session': options.session },
          body: JSON.stringify(wire),
          ...(signal === undefined ? {} : { signal }),
        });
      } catch (error) {
        if (signal?.aborted === true) throw new ProviderError('aborted', 'The request was cancelled.');
        throw new ProviderError('connection', `The broker could not be reached: ${error instanceof Error ? error.message : String(error)}`);
      }
      if (!response.ok) {
        let message = `The broker answered ${response.status}.`;
        const text = await response.text().catch(() => '');
        try {
          const body = JSON.parse(text) as { error?: unknown };
          if (typeof body.error === 'string') message = `The broker refused: ${body.error}`;
        } catch {
          // Keep the status line.
        }
        // A policy refusal (403) is permission, never something to retry or fall back from.
        throw new ProviderError(response.status === 403 ? 'permission' : classifyStatus(response.status, text), message);
      }
      if (response.body === null) throw new ProviderError('stream_cut', 'The broker sent no body.');
      const decoder = new TextDecoder();
      let buffer = '';
      let reply: ModelReply | null = null;
      const handle = (text: string): void => {
        if (text.trim() === '') return;
        const line = JSON.parse(text) as { type: string; event?: StreamEvent; reply?: ModelReply; error?: { kind: string; message: string } };
        if (line.type === 'event' && line.event !== undefined) onEvent?.(line.event);
        else if (line.type === 'reply' && line.reply !== undefined) reply = line.reply;
        else if (line.type === 'error') throw new ProviderError((line.error?.kind ?? 'server_error') as never, `Upstream, through the broker: ${line.error?.message ?? 'failed'}`);
      };
      for await (const chunk of response.body) {
        buffer += decoder.decode(chunk as Uint8Array, { stream: true });
        if (buffer.length > MAX_LINE) throw new ProviderError('bad_request', 'The broker sent a line that is too long.');
        let newline: number;
        while ((newline = buffer.indexOf('\n')) >= 0) {
          handle(buffer.slice(0, newline));
          buffer = buffer.slice(newline + 1);
        }
      }
      handle(buffer);
      if (reply === null) throw new ProviderError('stream_cut', 'The broker stream ended without a reply.');
      return reply;
    },
  };
}
