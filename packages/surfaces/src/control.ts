import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { connect, createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import type { OpenSession } from './session-types.ts';

/** One control message, one line. Anything bigger is not a steer. */
export const MAX_CONTROL_LINE = 16 * 1024;
export const MAX_STEER_CHARS = 8_000;
const MAX_CONNECTIONS = 8;
const SESSION_ID = /^[A-Za-z0-9-]{1,64}$/;

/** What the channel can reach in a session. Nothing else crosses it. */
export interface ControlTarget {
  readonly sessionId: string;
  /** A steer from another process: an `ipc` notice at the next step boundary, never `user`. */
  steer(text: string): void;
  stop(): void;
  state(): Readonly<Record<string, unknown>>;
  /** Told about every refused connection, so a forged message is in the log. */
  refused(why: string): void;
}

/** Where a session's channel is and the token it wants. Lives only in a 0600 file under `~/.hn/control/`, never in an environment. */
export interface ControlEndpoint {
  readonly sessionId: string;
  readonly path: string;
  readonly token: string;
  readonly pid: number;
}

export interface ControlChannel {
  readonly endpoint: ControlEndpoint;
  readonly file: string;
  close(): Promise<void>;
}

const digest = (text: string): Buffer => createHash('sha256').update(text).digest();
/** Compared in constant time over fixed-length digests, so neither the length nor a prefix leaks. */
export const tokenMatches = (given: unknown, token: string): boolean => typeof given === 'string' && timingSafeEqual(digest(given), digest(token));

export const controlFolder = (home: string): string => join(home, 'control');

async function privateFolder(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') await chmod(path, 0o700);
}

/**
 * The control channel: how another process steers, stops or asks about a running session. Separate from
 * the session lock. A Windows named pipe or a Unix socket in a 0700 folder, both with a random name, and a 32-byte
 * token. A message without the token is dropped, logged and its connection closed, and nothing is said back.
 */
export async function openControl(home: string, target: ControlTarget): Promise<ControlChannel> {
  if (!SESSION_ID.test(target.sessionId)) throw new HnError('BAD_SESSION', 'A control channel needs a plain session id.');
  const folder = controlFolder(home);
  await privateFolder(folder);
  const name = randomBytes(12).toString('hex');
  let socketFolder: string | null = null;
  let path: string;
  if (process.platform === 'win32') path = `\\\\.\\pipe\\hn-control-${name}`;
  else {
    path = join(folder, `${name}.sock`);
    // A Unix socket path is limited to about 100 bytes; a deep home gets a private folder under the system temp instead.
    if (Buffer.byteLength(path) > 100) {
      socketFolder = await mkdtemp(join(tmpdir(), 'hn-'));
      await chmod(socketFolder, 0o700);
      path = join(socketFolder, 'c.sock');
    }
  }
  const token = randomBytes(32).toString('base64url');
  const sockets = new Set<Socket>();
  const server: Server = createServer((socket) => {
    if (sockets.size >= MAX_CONNECTIONS) {
      socket.destroy();
      return;
    }
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => undefined);
    socket.setEncoding('utf8');
    let buffer = '';
    const refuse = (why: string): void => {
      target.refused(why);
      buffer = '';
      socket.destroy();
    };
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      if (buffer.length > MAX_CONTROL_LINE && !buffer.includes('\n')) return refuse('a control message was too long');
      for (let end = buffer.indexOf('\n'); end !== -1 && !socket.destroyed; end = buffer.indexOf('\n')) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        let message: unknown;
        try {
          message = JSON.parse(line);
        } catch {
          return refuse('a control message was not JSON');
        }
        if (typeof message !== 'object' || message === null || Array.isArray(message)) return refuse('a control message was not an object');
        const record = message as Record<string, unknown>;
        if (!tokenMatches(record['token'], token)) return refuse('a control message had no valid token');
        socket.write(`${JSON.stringify(handle(record, target))}\n`);
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    // On Windows a pipe name already taken fails here, so nobody can squat the name first (first-instance).
    server.listen(path, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const endpoint: ControlEndpoint = { sessionId: target.sessionId, path, token, pid: process.pid };
  const file = join(folder, `${target.sessionId}.json`);
  await writeFile(file, JSON.stringify(endpoint), { mode: 0o600 });
  if (process.platform !== 'win32') await chmod(file, 0o600);
  let closed = false;
  return {
    endpoint,
    file,
    close: async () => {
      if (closed) return;
      closed = true;
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(file, { force: true });
      if (socketFolder !== null) await rm(socketFolder, { recursive: true, force: true });
    },
  };
}

function handle(record: Readonly<Record<string, unknown>>, target: ControlTarget): Record<string, unknown> {
  const op = record['op'];
  if (op === 'steer') {
    const text = record['text'];
    if (typeof text !== 'string' || text.trim() === '') return { ok: false, error: 'A steer needs text.' };
    if (text.length > MAX_STEER_CHARS) return { ok: false, error: `A steer may be at most ${MAX_STEER_CHARS} characters.` };
    target.steer(text);
    return { ok: true };
  }
  if (op === 'stop') {
    target.stop();
    return { ok: true };
  }
  if (op === 'state') return { ok: true, state: target.state() };
  return { ok: false, error: 'Unknown op. Use steer, stop or state.' };
}

/** Reads a session's endpoint file. Null when the session has no open channel. */
export async function readEndpoint(home: string, sessionId: string): Promise<ControlEndpoint | null> {
  if (!SESSION_ID.test(sessionId)) throw new HnError('BAD_SESSION', 'That is not a session id.');
  const text = await readFile(join(controlFolder(home), `${sessionId}.json`), 'utf8').catch(() => null);
  if (text === null) return null;
  const parsed = JSON.parse(text) as Partial<ControlEndpoint>;
  if (typeof parsed.path !== 'string' || typeof parsed.token !== 'string') return null;
  return { sessionId, path: parsed.path, token: parsed.token, pid: Number(parsed.pid) };
}

/** Sends one message over a channel and returns its one-line answer. `token` is sent as given; tests send a wrong one. */
export function sendControl(path: string, message: Readonly<Record<string, unknown>>, timeoutMs = 5_000): Promise<Record<string, unknown> | null> {
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    let buffer = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new HnError('CONTROL_TIMEOUT', 'The session did not answer on its control channel.'));
    }, timeoutMs);
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.write(`${JSON.stringify(message)}\n`));
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      const end = buffer.indexOf('\n');
      if (end === -1) return;
      clearTimeout(timer);
      socket.end();
      try {
        resolve(JSON.parse(buffer.slice(0, end)) as Record<string, unknown>);
      } catch {
        resolve(null);
      }
    });
    // A refused message gets no answer: the channel just closes.
    socket.on('close', () => {
      clearTimeout(timer);
      resolve(null);
    });
    socket.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

/** `hn steer` and `hn stop`: finds the session's channel in this user's home and sends one message. */
export async function controlSession(home: string, sessionId: string, op: 'steer' | 'stop' | 'state', text?: string): Promise<Record<string, unknown>> {
  const endpoint = await readEndpoint(home, sessionId);
  if (endpoint === null) throw new HnError('NO_CONTROL', `Session ${sessionId} has no open control channel. Is it running?`);
  const answer = await sendControl(endpoint.path, { token: endpoint.token, op, ...(text === undefined ? {} : { text }) });
  if (answer === null) throw new HnError('CONTROL_REFUSED', 'The session closed the channel without an answer.');
  return answer;
}

/** The channel's view of an open session: a steer is an `ipc` notice that taints the session, never the user's words. */
export function sessionTarget(session: OpenSession): ControlTarget {
  return {
    sessionId: session.sessionId,
    steer: (text) => session.notice(text, 'ipc'),
    stop: () => session.agent.stop(),
    state: () => ({
      sessionId: session.sessionId,
      busy: session.agent.busy,
      mode: session.gate.mode,
      tier: session.tier,
      turns: session.agent.events.filter((event) => event.type === 'turn/start').length,
    }),
    refused: (why) => session.agent.record('sandbox/event', { kind: 'control-refused', why }),
  };
}

export const openSessionControl = (home: string, session: OpenSession): Promise<ControlChannel> => openControl(home, sessionTarget(session));
