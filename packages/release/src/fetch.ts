import { ReleaseError } from './manifest.ts';
import { helperEntry, helperManifestName, helperSignatureName, installHelper, verifyHelperManifest, type HelperInstall } from './sandbox.ts';

/**
 * Bounded downloads (Phase 9, decision 3). A URL is followed only when it is https, or plain http to this machine
 * (a local mirror); every redirect is checked again, so https never downgrades; the body is read with a hard cap.
 * Nothing here trusts what it fetches: the caller verifies the bytes. The helper download additionally verifies the
 * signed manifest before it asks for the binary, and the binary before it writes it.
 */

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
export const MAX_REDIRECTS = 5;

const loopback = (host: string): boolean => host === '127.0.0.1' || host === '[::1]' || host === 'localhost';

/** https, or http to loopback; never credentials in the address. */
export function allowedDownloadUrl(url: URL): boolean {
  if (url.username !== '' || url.password !== '') return false;
  return url.protocol === 'https:' || (url.protocol === 'http:' && loopback(url.hostname));
}

export interface FetchLimits {
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
}

export async function fetchBounded(address: string, maxBytes: number, limits: FetchLimits = {}): Promise<Buffer> {
  const fetcher = limits.fetch ?? fetch;
  let url: URL;
  try {
    url = new URL(address);
  } catch {
    throw new ReleaseError(`${address} is not an address.`);
  }
  const signal = AbortSignal.timeout(limits.timeoutMs ?? 120_000);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    if (!allowedDownloadUrl(url)) throw new ReleaseError(`Refusing to fetch ${url.origin}${url.pathname}: only https (or http to this machine) is followed.`);
    let response: Response;
    try {
      response = await fetcher(url, { redirect: 'manual', signal });
    } catch (error) {
      throw new ReleaseError(`Could not fetch ${url.origin}${url.pathname}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (REDIRECTS.has(response.status)) {
      const location = response.headers.get('location');
      await response.body?.cancel().catch(() => undefined);
      if (location === null) throw new ReleaseError(`${url.origin}${url.pathname} redirected nowhere.`);
      try {
        url = new URL(location, url);
      } catch {
        throw new ReleaseError('A redirect named an address that is not one.');
      }
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new ReleaseError(`${url.origin}${url.pathname} answered ${response.status}.`);
    }
    const declared = Number(response.headers.get('content-length') ?? '0');
    if (Number.isFinite(declared) && declared > maxBytes) {
      await response.body?.cancel().catch(() => undefined);
      throw new ReleaseError(`${url.origin}${url.pathname} is larger than the ${maxBytes} bytes allowed.`);
    }
    if (response.body === null) return Buffer.alloc(0);
    const chunks: Buffer[] = [];
    let total = 0;
    const reader = response.body.getReader();
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new ReleaseError(`${url.origin}${url.pathname} is larger than the ${maxBytes} bytes allowed.`);
      }
      chunks.push(Buffer.from(next.value));
    }
    return Buffer.concat(chunks);
  }
  throw new ReleaseError(`Too many redirects (more than ${MAX_REDIRECTS}).`);
}

export interface HelperDownload extends HelperInstall, FetchLimits {
  /** Where the release's assets are, without a trailing slash. */
  readonly baseUrl: string;
  readonly onFetch?: (what: string) => void;
}

/**
 * Fetches, verifies and installs the helper for this platform. Order matters: the manifest and its signature come
 * first and must verify before the binary is requested, and the binary is read against the size the manifest
 * names, so a server cannot make the download larger than what was signed.
 */
export async function downloadHelper(request: HelperDownload): Promise<string> {
  const base = request.baseUrl.replace(/\/+$/, '');
  const [manifestBytes, signatureBytes] = await Promise.all([fetchBounded(`${base}/${helperManifestName(request.version)}`, 64 * 1024, request), fetchBounded(`${base}/${helperSignatureName(request.version)}`, 16 * 1024, request)]);
  let signature: unknown;
  try {
    signature = JSON.parse(signatureBytes.toString('utf8'));
  } catch {
    throw new ReleaseError('The helper signature file is not JSON.');
  }
  const manifest = verifyHelperManifest(manifestBytes, signature, request.pinned, request.version);
  const entry = helperEntry(manifest, request.platform);
  request.onFetch?.(`${entry.file} (${entry.size} bytes)`);
  const binary = await fetchBounded(`${base}/${entry.file}`, entry.size, request);
  return installHelper(request, manifestBytes, signature, binary);
}
