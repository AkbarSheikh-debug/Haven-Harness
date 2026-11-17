import { createHash } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { connect, createServer, type Server } from 'node:net';
import { join } from 'node:path';
import { SessionAlreadyOwnedError } from '@hn/core';

export interface SessionLock {
  release(): Promise<void>;
}

export interface LockOptions {
  readonly sessionId: string;
  /** Scopes the lock, and holds the socket file on platforms that need one. */
  readonly lockDir: string;
}

function lockAddress({ sessionId, lockDir }: LockOptions): string {
  const name = createHash('sha256').update(lockDir).update('\0').update(sessionId).digest('hex').slice(0, 32);
  if (process.platform === 'win32') return `\\\\.\\pipe\\hn-lock-${name}`;
  // Abstract sockets vanish with their process, so Linux has no stale file to clean.
  if (process.platform === 'linux') return `\0hn-lock-${name}`;
  return join(lockDir, `${name}.sock`);
}

function listen(server: Server, address: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(address, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function hasLiveOwner(address: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = connect(address);
    probe.once('connect', () => {
      probe.destroy();
      resolve(true);
    });
    probe.once('error', () => resolve(false));
  });
}

async function bind(address: string, sessionId: string): Promise<Server> {
  // The lock carries no traffic. Control commands use a separate authenticated channel.
  const server = createServer((socket) => socket.destroy());
  try {
    await listen(server, address);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EADDRINUSE') throw error;
    if (process.platform === 'win32' || process.platform === 'linux' || (await hasLiveOwner(address))) {
      throw new SessionAlreadyOwnedError(sessionId);
    }
    // A socket file left by a crash on macOS.
    await rm(address, { force: true });
    await listen(server, address);
  }
  server.unref();
  return server;
}

/**
 * Takes the one writer lock for a session. The kernel releases it when the process
 * dies, however it dies, so a crash never leaves a session locked.
 */
export async function acquireSessionLock(options: LockOptions): Promise<SessionLock> {
  const server = await bind(lockAddress(options), options.sessionId);
  return {
    release: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}
