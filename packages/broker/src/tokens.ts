import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { mintCapability, verifyCapability, type Capability, type Identity } from '@hn/security';
import { writeAtomic } from './ledger.ts';

/**
 * The broker's tokens. Both kinds are the harness's macaroons, keyed by a secret only the broker holds,
 * with its own address as the audience and a short expiry. Who a token speaks for is looked up here by its id; it is
 * never read from a caveat, because a holder may add caveats. A holder can narrow a token (a child's tools and
 * paths) and nothing else. Revoking a login revokes every session token issued under it.
 */

export type TokenKind = 'login' | 'session';

interface TokenRecord {
  readonly id: string;
  readonly kind: TokenKind;
  /** The login a session token was issued under. */
  readonly parent: string | null;
  readonly sid: string;
  readonly identity: Identity;
  readonly subject: string;
  readonly expires: number;
  revoked: boolean;
}

export interface Authenticated {
  readonly identity: Identity;
  readonly tokenId: string;
  readonly sid: string;
  readonly capability: Capability;
}

export type AuthResult = { readonly ok: true; readonly who: Authenticated } | { readonly ok: false; readonly reason: string };

const MAX_TOKEN = 4096;
const refuse = (reason: string): AuthResult => ({ ok: false, reason });

export const encodeToken = (capability: Capability): string => Buffer.from(JSON.stringify(capability)).toString('base64url');

function decodeToken(text: string): Capability | null {
  if (text.length > MAX_TOKEN || !/^[A-Za-z0-9_-]+$/.test(text)) return null;
  try {
    const value: unknown = JSON.parse(Buffer.from(text, 'base64url').toString('utf8'));
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
    const { id, caveats, sig } = value as Record<string, unknown>;
    if (typeof id !== 'string' || typeof sig !== 'string' || !Array.isArray(caveats) || caveats.length > 32 || !caveats.every((caveat) => typeof caveat === 'string' && caveat.length < 512)) return null;
    return { id, caveats: caveats as string[], sig };
  } catch {
    return null;
  }
}

export class TokenBook {
  readonly #dir: string;
  readonly #audience: string;
  readonly #now: () => number;
  #key: Uint8Array = new Uint8Array();
  readonly #records = new Map<string, TokenRecord>();

  private constructor(dir: string, audience: string, now: () => number) {
    this.#dir = dir;
    this.#audience = audience;
    this.#now = now;
  }

  static async open(dir: string, audience: string, now: () => number = Date.now): Promise<TokenBook> {
    const book = new TokenBook(dir, audience, now);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const keyPath = join(dir, 'token.key');
    try {
      book.#key = await readFile(keyPath);
    } catch {
      book.#key = randomBytes(32);
      await writeFile(keyPath, book.#key, { mode: 0o600, flag: 'wx' });
    }
    if (book.#key.length !== 32) throw new Error(`${keyPath} is not a 32-byte key.`);
    try {
      const saved = JSON.parse(await readFile(join(dir, 'tokens.json'), 'utf8')) as { v: 1; records: TokenRecord[] };
      for (const record of saved.records) if (record.expires > now()) book.#records.set(record.id, { ...record });
    } catch {
      // No book yet: nobody has logged in.
    }
    return book;
  }

  async #save(): Promise<void> {
    const path = join(this.#dir, 'tokens.json');
    const live = [...this.#records.values()].filter((record) => record.expires > this.#now());
    await writeAtomic(path, () => JSON.stringify({ v: 1, records: live }));
  }

  async #issue(kind: TokenKind, parent: string | null, sid: string, identity: Identity, subject: string, ttlMs: number): Promise<{ token: string; expires: number }> {
    const id = randomBytes(16).toString('hex');
    const expires = this.#now() + ttlMs;
    this.#records.set(id, { id, kind, parent, sid, identity, subject, expires, revoked: false });
    await this.#save();
    return { token: encodeToken(mintCapability(this.#key, id, [`aud=${this.#audience}`, `sid=${sid}`, `exp=${expires}`])), expires };
  }

  /** After a verified OIDC login. */
  issueLogin(identity: Identity, subject: string, ttlMs: number): Promise<{ token: string; expires: number }> {
    return this.#issue('login', null, `login:${randomBytes(8).toString('hex')}`, identity, subject, ttlMs);
  }

  /** One hn session's token, bound to its id, never outliving the login it came from. */
  issueSession(login: Authenticated, session: string, ttlMs: number): Promise<{ token: string; expires: number }> {
    const parent = this.#records.get(login.tokenId);
    if (parent === undefined) throw new Error('unknown login');
    return this.#issue('session', parent.id, session, parent.identity, parent.subject, Math.min(ttlMs, parent.expires - this.#now()));
  }

  /**
   * Checks a bearer token for one kind of use. `session` is what the request says it is (a header); the token's
   * `sid` must match it, and for a session token it must also be the session the broker issued it to.
   */
  authenticate(header: string | undefined, session: string | undefined, kind: TokenKind, scope: { tool?: string } = {}): AuthResult {
    if (header === undefined || !header.startsWith('Bearer ')) return refuse('No token.');
    const capability = decodeToken(header.slice('Bearer '.length).trim());
    if (capability === null) return refuse('The token is malformed.');
    const record = this.#records.get(capability.id);
    if (record === undefined) return refuse('The token is unknown here.');
    if (record.kind !== kind) return refuse(`A ${record.kind} token cannot be used for this.`);
    if (record.revoked || (record.parent !== null && this.#records.get(record.parent)?.revoked !== false)) return refuse('The token was revoked.');
    const verdict = verifyCapability(this.#key, capability, { audience: this.#audience, session: session ?? '', now: this.#now(), ...(scope.tool === undefined ? {} : { tool: scope.tool }) });
    if (!verdict.ok) return refuse(verdict.reason);
    if (session !== record.sid) return refuse('The token belongs to a different session.');
    return { ok: true, who: { identity: record.identity, tokenId: record.id, sid: record.sid, capability } };
  }

  /** Whether a token's caveats cover one tool, using the same check as everything else. */
  covers(who: Authenticated, tool: string): boolean {
    return verifyCapability(this.#key, who.capability, { audience: this.#audience, session: who.sid, now: this.#now(), tool }).ok;
  }

  async revoke(id: string): Promise<boolean> {
    const record = this.#records.get(id);
    if (record === undefined) return false;
    record.revoked = true;
    await this.#save();
    return true;
  }
}
