import { randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createServer, type Socket } from 'node:net';
import { join } from 'node:path';
import { resolvePaths } from '@hn/config';
import { HnError, sanitizeForDisplay } from '@hn/core';
import { Supervisor, type InstanceStarter, type SessionSettings } from '@hn/orchestrate';
import type { KeyStore } from '@hn/provider';
import { tokenMatches } from './control.ts';
import { JsonRpcPeer, RPC_INVALID_PARAMS, RPC_METHOD_NOT_FOUND, RPC_REFUSED, RpcError, type RpcParams } from './jsonrpc.ts';
import { startRpcClient } from './rpc-client.ts';

/** Instances are `hn rpc` processes. Their environment holds no key and no parent session; keys go over `initialize`. */
export function rpcInstanceStarter(options: { readonly keys: KeyStore; readonly env?: NodeJS.ProcessEnv; readonly args?: readonly string[] }): InstanceStarter {
  const env = Object.fromEntries(Object.entries(options.env ?? process.env).filter(([name]) => name !== 'HN_PARENT_SESSION' && !/_API_KEY$/.test(name)));
  return (workdir) => {
    const { client, process: child } = startRpcClient({ cwd: workdir, env, ...(options.args === undefined ? {} : { args: options.args }) });
    return {
      pid: child.pid,
      exited: child.exited,
      kill: () => child.kill(),
      shutdown: () => client.shutdown(),
      request: (method, params, timeoutMs) => client.request(method, method === 'initialize' ? { ...params, keys: JSON.parse(options.keys.toHandoff()) as Record<string, string> } : params, timeoutMs),
    };
  };
}

const supervisorFolder = (home: string): string => join(home, 'supervisor');

export interface SupervisorEndpoint {
  readonly path: string;
  readonly token: string;
  readonly file: string;
  close(): Promise<void>;
}

const text = (params: RpcParams, name: string): string => {
  const value = params[name];
  if (typeof value !== 'string' || value === '') throw new RpcError(RPC_INVALID_PARAMS, `${name} must be a non-empty string.`);
  return value;
};

/**
 * The supervisor's own door: JSON-RPC over a named pipe or a 0700 Unix socket, with a 32-byte token kept only in a 0600
 * endpoint file. Every request carries the token; one without it closes the connection with no answer.
 */
export async function openSupervisorEndpoint(home: string, supervisor: Supervisor, onRefused: (why: string) => void = () => undefined): Promise<SupervisorEndpoint> {
  const folder = supervisorFolder(home);
  await mkdir(folder, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') await chmod(folder, 0o700);
  const name = randomBytes(12).toString('hex');
  let path = process.platform === 'win32' ? `\\\\.\\pipe\\hn-supervisor-${name}` : join(folder, `${name.slice(0, 8)}.sock`);
  // A Unix socket path holds at most 104 bytes on macOS; a deep home gets a private folder under the system temp.
  if (process.platform !== 'win32' && Buffer.byteLength(path) > 100) {
    const short = await mkdtemp(join(tmpdir(), 'hn-'));
    await chmod(short, 0o700);
    path = join(short, 's.sock');
  }
  const token = randomBytes(32).toString('base64url');
  const sockets = new Set<Socket>();
  const dispatch = async (method: string, params: RpcParams): Promise<unknown> => {
    switch (method) {
      case 'new_session': {
        const settings: SessionSettings = {
          workdir: text(params, 'workdir'),
          ...(typeof params['mode'] === 'string' ? { mode: params['mode'] } : {}),
          ...(typeof params['model'] === 'string' ? { model: params['model'] } : {}),
          ...(typeof params['baseUrl'] === 'string' ? { baseUrl: params['baseUrl'] } : {}),
          ...(typeof params['window'] === 'number' ? { window: params['window'] } : {}),
          ...(typeof params['verify'] === 'string' ? { verify: params['verify'] } : {}),
          ...(Array.isArray(params['allow']) ? { allow: (params['allow'] as unknown[]).map(String) } : {}),
        };
        return supervisor.newSession(settings);
      }
      case 'prompt':
        return supervisor.prompt(text(params, 'instance'), text(params, 'text'));
      case 'fork':
        return supervisor.fork(text(params, 'instance'));
      case 'clone':
        return supervisor.clone(text(params, 'instance'));
      case 'get_state':
        return supervisor.getState(typeof params['instance'] === 'string' ? params['instance'] : undefined);
      case 'stop':
        await supervisor.stop(text(params, 'instance'));
        return {};
      default:
        throw new RpcError(RPC_METHOD_NOT_FOUND, 'Use new_session, prompt, fork, clone, get_state or stop.');
    }
  };
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => undefined);
    new JsonRpcPeer(socket, socket, {
      request: async (method, params) => {
        if (!tokenMatches(params['token'], token)) {
          onRefused(`a ${sanitizeForDisplay(method).slice(0, 40)} request without a valid token`);
          socket.destroy();
          throw new RpcError(RPC_REFUSED, 'refused');
        }
        try {
          return await dispatch(method, params);
        } catch (error) {
          if (error instanceof RpcError) throw error;
          throw new RpcError(RPC_REFUSED, sanitizeForDisplay(error instanceof Error ? error.message : String(error)));
        }
      },
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(path, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const file = join(folder, 'endpoint.json');
  await writeFile(file, JSON.stringify({ path, token, pid: process.pid }), { mode: 0o600 });
  if (process.platform !== 'win32') await chmod(file, 0o600);
  return {
    path,
    token,
    file,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(file, { force: true });
    },
  };
}

/** `hn supervisor` (experimental): runs until its standard input closes. Instances use the CLI's model flags as defaults. */
export async function runSupervisorCommand(context: { readonly positionals: readonly string[]; readonly nested: boolean; readonly keys: KeyStore; readonly args: readonly string[]; readonly out: (text: string) => void }): Promise<number | null> {
  if (context.positionals[0] !== 'supervisor') return null;
  if (context.nested) throw new HnError('NESTED_HN', 'hn supervisor cannot be started from inside an hn session.');
  const home = resolvePaths().home;
  const supervisor = new Supervisor({ start: rpcInstanceStarter({ keys: context.keys, args: context.args }), file: join(supervisorFolder(home), 'instances.json') });
  const endpoint = await openSupervisorEndpoint(home, supervisor, (why) => process.stderr.write(`refused: ${why}\n`));
  supervisor.startHeartbeat();
  context.out(`Supervisor running (experimental). Endpoint and token: ${endpoint.file}. Close standard input to stop.\n`);
  await new Promise<void>((resolve) => {
    process.stdin.on('end', resolve);
    process.stdin.on('close', resolve);
    process.stdin.resume();
  });
  await endpoint.close();
  await supervisor.close();
  return 0;
}
