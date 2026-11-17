import type { Server } from 'node:http';

export interface Refusal {
  readonly status: number;
  readonly reason: string;
}

export interface ProxyLogEntry {
  readonly method: string;
  readonly url: string;
  readonly status: number;
  readonly reason?: string;
  readonly upstream?: string;
}

export function refusal(method: string, rawUrl: string): Refusal | null;
export function upstreamFor(rawUrl: string): string | null;
export function rewrite(text: string, publicBase: string): string;
export function createRegistryProxy(options: {
  readonly publicBase: string;
  readonly fetch?: (url: string, init: { method: string; headers: Record<string, string>; redirect: 'error' }) => Promise<Response>;
  readonly log?: (entry: ProxyLogEntry) => void;
}): Server;
