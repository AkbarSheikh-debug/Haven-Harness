import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { openAuditFile, type AuditEntry, type AuditFile, type ChainHead, type Checkpoint } from '@hn/security';
import { readJson, refusal, sendJson } from './http.ts';
import type { Route } from './server.ts';
import { writeAtomic } from './ledger.ts';
import { openCheckpoints, type CheckpointBook } from './audit-checkpoints.ts';
import { AuditStore } from './audit-store.ts';
import { auditReadRoutes, type AuditReadOptions } from './audit-read.ts';

/**
 * The broker's audit (decision 8). Every decision is a row in the broker's own keyed hash chain, on the broker's
 * disk. Rows are also shipped to a SIEM as OTLP/HTTP JSON logs, each carrying its number, the previous row's MAC and
 * its own, so whoever holds the broker's audit key can check the shipped copy row by row.
 *
 * Clients anchor their own audit heads here: a session sends (n, mac) as it writes. The laptop's chain is keyed with
 * a key only the laptop holds, so the broker cannot check its rows, but once a head is anchored a cut or edited tail
 * on the laptop no longer reaches it, and an anchor that goes backwards is refused.
 */

export interface OtlpTarget {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
}

export interface AnchorRecord extends ChainHead {
  readonly user: string;
  readonly session: string;
  readonly at: number;
}

export interface BrokerAuditSink {
  record(type: string, data: Readonly<Record<string, unknown>>): void;
  /** Resolves when every row so far is on disk and every shipment so far has been tried. */
  flush(): Promise<void>;
  /** Resolves when every row so far is on disk and in the index. */
  settle(): Promise<void>;
  /** What can be asked of the chain: an index over the rows, read by position. */
  readonly store: AuditStore;
  /** The broker's signed checkpoints and the key that signs them. */
  readonly checkpoints: CheckpointBook;
  /** Signs the chain's head as it stands once every row so far is on disk. Null while the chain is empty. */
  checkpoint(): Promise<Checkpoint | null>;
  /** The head each session last anchored. */
  anchorList(): readonly AnchorRecord[];
  /** Calls `listener` after each row is indexed. Returns the way to stop. */
  watch(listener: () => void): () => void;
  readonly routes: readonly Route[];
  readonly key: Uint8Array;
  readonly path: string;
  close(): void;
}

const MAX_QUEUE = 10_000;

/** One shipped row as an OTLP log record. */
function logRecord(entry: AuditEntry): Record<string, unknown> {
  const attr = (key: string, value: string | number): Record<string, unknown> => ({ key, value: typeof value === 'number' ? { intValue: String(value) } : { stringValue: value } });
  return {
    timeUnixNano: `${Date.parse(entry.ts)}000000`,
    severityText: 'INFO',
    body: { stringValue: entry.type },
    attributes: [attr('hn.n', entry.n), attr('hn.ts', entry.ts), attr('hn.prev', entry.prev), attr('hn.mac', entry.mac), attr('hn.data', JSON.stringify(entry.data))],
  };
}

/** Rebuilds chain rows from OTLP log records, so a shipped copy can be checked with `verifyAudit`. */
export function entriesFromOtlp(records: readonly Record<string, unknown>[]): AuditEntry[] {
  return records.map((record) => {
    const attrs = new Map(((record['attributes'] as { key: string; value: { stringValue?: string; intValue?: string } }[]) ?? []).map((item) => [item.key, item.value.stringValue ?? item.value.intValue ?? '']));
    return { n: Number(attrs.get('hn.n')), ts: String(attrs.get('hn.ts')), type: String((record['body'] as { stringValue?: string })?.stringValue), data: JSON.parse(String(attrs.get('hn.data') ?? '{}')) as Record<string, unknown>, prev: String(attrs.get('hn.prev')), mac: String(attrs.get('hn.mac')) };
  });
}

export interface AuditSinkOptions extends AuditReadOptions {
  /** Sign the head after every this many rows (default 100). */
  readonly checkpointEvery?: number;
  /** Sign the head this often while rows are being added (default 60 s). */
  readonly checkpointMs?: number;
  readonly now?: () => number;
}

export async function openBrokerAudit(state: string, otlp?: OtlpTarget, options: AuditSinkOptions = {}): Promise<BrokerAuditSink> {
  await mkdir(state, { recursive: true, mode: 0o700 });
  const keyPath = join(state, 'audit.key');
  let key: Uint8Array;
  try {
    key = await readFile(keyPath);
  } catch {
    key = randomBytes(32);
    await writeFile(keyPath, key, { mode: 0o600, flag: 'wx' });
  }
  const path = join(state, 'audit.jsonl');
  const file: AuditFile = await openAuditFile(path, key);
  const store = new AuditStore(path);
  await store.load();
  const checkpoints = await openCheckpoints(state, (n) => store.macOf(n));
  const every = options.checkpointEvery ?? 100;
  const clock = options.now ?? Date.now;
  const watchers = new Set<() => void>();
  let lastSigned = checkpoints.list().reduce((most, item) => Math.max(most, item.n), 0);
  const queue: AuditEntry[] = [];
  let shipping: Promise<void> = Promise.resolve();
  let dropped = 0;

  const ship = (): Promise<void> => {
    shipping = shipping.then(async () => {
      if (otlp === undefined || queue.length === 0) return;
      const batch = queue.slice(0, 500);
      const body = { resourceLogs: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'hn-broker' } }] }, scopeLogs: [{ scope: { name: 'hn.audit' }, logRecords: batch.map(logRecord) }] }] };
      try {
        const response = await fetch(`${otlp.url.replace(/\/$/, '')}/v1/logs`, { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json', ...otlp.headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(10_000) });
        // Only a delivered batch leaves the queue; anything else is tried again with the next row or flush.
        if (response.ok) queue.splice(0, batch.length);
      } catch {
        // The collector is down: keep the rows.
      }
    });
    return shipping;
  };
  const timer = otlp === undefined ? null : setInterval(() => void ship(), 2_000);
  timer?.unref();

  let writes: Promise<unknown> = Promise.resolve();
  const checkpoint = (): Promise<Checkpoint | null> => {
    const next = writes.then(async () => {
      const head = store.head;
      if (head.n === 0) return null;
      const signed = await checkpoints.sign(head, new Date(clock()));
      lastSigned = Math.max(lastSigned, signed.n);
      return signed;
    });
    return next;
  };
  const checkpointTimer = setInterval(() => {
    if (store.head.n > lastSigned) void checkpoint().catch((error: unknown) => process.emitWarning(`hn broker: could not sign an audit checkpoint: ${error instanceof Error ? error.message : String(error)}`));
  }, options.checkpointMs ?? 60_000);
  checkpointTimer.unref();

  const anchorsPath = join(state, 'anchors.json');
  let anchors = new Map<string, ChainHead & { user: string; at: number }>();
  try {
    anchors = new Map(Object.entries(JSON.parse(await readFile(anchorsPath, 'utf8')) as Record<string, ChainHead & { user: string; at: number }>));
  } catch {
    // None yet.
  }
  const saveAnchors = async (): Promise<void> => {
    await writeAtomic(anchorsPath, () => JSON.stringify(Object.fromEntries(anchors)));
  };

  const sink: BrokerAuditSink = {
    key,
    path,
    store,
    checkpoints,
    checkpoint,
    settle: async () => {
      await writes;
    },
    anchorList: () => [...anchors.entries()].map(([id, item]) => ({ n: item.n, mac: item.mac, user: item.user, session: id.slice(id.indexOf('\u0000') + 1), at: item.at })),
    watch(listener) {
      watchers.add(listener);
      return () => watchers.delete(listener);
    },
    record(type, data) {
      const written = file.record(type, data).then((entry) => {
        store.add(entry);
        for (const listener of [...watchers]) listener();
        // The row itself is signed, not whatever the head has become by the time a signature is made.
        if (every > 0 && entry.n % every === 0) void checkpoints.sign(entry, new Date(clock())).then((signed) => (lastSigned = Math.max(lastSigned, signed.n))).catch((error: unknown) => process.emitWarning(`hn broker: could not sign an audit checkpoint: ${error instanceof Error ? error.message : String(error)}`));
        if (otlp === undefined) return;
        if (queue.length >= MAX_QUEUE) {
          queue.shift();
          dropped += 1;
        }
        queue.push(entry);
        if (dropped > 0 && dropped % 1000 === 1) process.emitWarning(`hn broker: ${dropped} audit rows were not shipped (the collector is unreachable); they are still in ${path}.`);
      });
      writes = writes.then(() => written).catch(() => undefined);
    },
    async flush() {
      await writes;
      await ship();
    },
    close() {
      if (timer !== null) clearInterval(timer);
      clearInterval(checkpointTimer);
      watchers.clear();
    },
    routes: [
      {
        method: 'POST',
        path: '/v1/audit/anchor',
        async handle(context, request, response) {
          const who = context.auth(request, response, 'session');
          if (who === null) return;
          const body = (await readJson(request, 4096)) as Record<string, unknown> | null;
          const n = body?.['n'];
          const mac = body?.['mac'];
          if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0 || typeof mac !== 'string' || !/^[0-9a-f]{64}$/.test(mac)) return refusal(response, 400, 'Expected {n, mac}.');
          const id = `${who.identity.user}\u0000${who.sid}`;
          const last = anchors.get(id);
          if (last !== undefined && (n < last.n || (n === last.n && mac !== last.mac))) {
            context.audit('broker/anchor-refused', { user: who.identity.user, session: who.sid, n, last: last.n });
            return refusal(response, 409, `This session's audit already reached row ${last.n}; a head that goes back or changes is refused.`);
          }
          anchors.set(id, { n, mac, user: who.identity.user, at: context.now() });
          await saveAnchors();
          sendJson(response, 200, { n, mac });
        },
      },
      {
        method: 'GET',
        path: '/v1/audit/anchor',
        async handle(context, request, response) {
          const who = context.auth(request, response, 'session');
          if (who === null) return;
          const found = anchors.get(`${who.identity.user}\u0000${who.sid}`);
          sendJson(response, 200, found === undefined ? { n: 0 } : { n: found.n, mac: found.mac });
        },
      },
    ],
  };
  return { ...sink, routes: [...sink.routes, ...auditReadRoutes(sink, options)] };
}
