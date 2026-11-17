import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HnError } from '@hn/core';
import type { EgressProxy } from './egress-proxy.ts';

/**
 * Headless Chrome or Edge for the `browser` tool. Found by absolute path, never by name. A throwaway
 * profile, no extensions, no sync, no background requests. Every request goes through the harness egress proxy,
 * loopback included (Chrome sends loopback direct unless told not to), and the browser resolves no names itself, so
 * the proxy's checks cannot be stepped around. QUIC is off (it would not use the proxy) and WebRTC may not send UDP.
 */

export function findBrowser(env: NodeJS.ProcessEnv = process.env): string | null {
  const candidates =
    process.platform === 'win32'
      ? [
          join(env['ProgramFiles'] ?? 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
          join(env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe'),
          join(env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
          join(env['ProgramFiles'] ?? 'C:\\Program Files', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        ]
      : process.platform === 'darwin'
        ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', '/Applications/Chromium.app/Contents/MacOS/Chromium']
        : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge'];
  const configured = env['HN_BROWSER_BIN'];
  if (configured !== undefined && configured !== '' && existsSync(configured) && /^([a-zA-Z]:[\\/]|\/)/.test(configured)) return configured;
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

/** The command line. Kept apart so the safety flags are tested without starting a browser. */
export function browserArgs(proxyPort: number, profile: string): string[] {
  return [
    '--headless=new',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-sync',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-default-apps',
    '--disable-domain-reliability',
    '--disable-client-side-phishing-detection',
    '--metrics-recording-only',
    '--mute-audio',
    '--no-pings',
    '--disable-breakpad',
    '--disable-crash-reporter',
    '--disable-quic',
    '--dns-prefetch-disable',
    '--disable-features=DnsOverHttps,AsyncDns,NetworkPrediction,InterestFeedContentSuggestions,Translate,OptimizationHints,MediaRouter,AutofillServerCommunication,CertificateTransparencyComponentUpdater',
    `--proxy-server=http://127.0.0.1:${proxyPort}`,
    // Without this Chrome sends loopback requests direct, around the proxy.
    '--proxy-bypass-list=<-loopback>',
    // The browser resolves nothing itself: every name is resolved and checked by the proxy.
    '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    '--webrtc-ip-handling-policy=disable_non_proxied_udp',
    'about:blank',
  ];
}

interface Pending {
  resolve(value: Record<string, unknown>): void;
  reject(error: Error): void;
}

export interface PageSnapshot {
  readonly url: string;
  readonly title: string;
  readonly text: string;
  readonly links: readonly { readonly text: string; readonly href: string }[];
}

const NAVIGATION_TIMEOUT_MS = 20_000;

export class HeadlessBrowser {
  readonly #child: ChildProcess;
  readonly #socket: WebSocket;
  readonly #profile: string;
  readonly #pending = new Map<number, Pending>();
  readonly #events: ((method: string, params: Record<string, unknown>, sessionId?: string) => void)[] = [];
  #next = 1;
  #session: string | null = null;

  private constructor(child: ChildProcess, socket: WebSocket, profile: string) {
    this.#child = child;
    this.#socket = socket;
    this.#profile = profile;
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data)) as { id?: number; result?: Record<string, unknown>; error?: { message?: string }; method?: string; params?: Record<string, unknown>; sessionId?: string };
      if (message.id !== undefined) {
        const pending = this.#pending.get(message.id);
        this.#pending.delete(message.id);
        if (message.error !== undefined) pending?.reject(new Error(message.error.message ?? 'The browser refused.'));
        else pending?.resolve(message.result ?? {});
      } else if (message.method !== undefined) {
        for (const listener of this.#events) listener(message.method, message.params ?? {}, message.sessionId);
      }
    });
  }

  static async launch(binary: string, proxy: EgressProxy): Promise<HeadlessBrowser> {
    const profile = await mkdtemp(join(tmpdir(), 'hn-browser-'));
    const child = spawn(binary, browserArgs(proxy.port, profile), { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
    const endpoint = await new Promise<string>((resolve, reject) => {
      let text = '';
      const timer = setTimeout(() => reject(new HnError('BROWSER_START', 'The browser did not start in time.')), 20_000);
      child.stderr?.setEncoding('utf8').on('data', (chunk: string) => {
        text += chunk;
        const match = /DevTools listening on (ws:\/\/127\.0\.0\.1:\d+\/\S+)/.exec(text);
        if (match !== null) {
          clearTimeout(timer);
          resolve(match[1] as string);
        }
      });
      child.once('exit', () => reject(new HnError('BROWSER_START', `The browser exited at start: ${text.slice(0, 300)}`)));
    });
    const socket = new WebSocket(endpoint);
    await new Promise<void>((resolve, reject) => {
      socket.addEventListener('open', () => resolve(), { once: true });
      socket.addEventListener('error', () => reject(new HnError('BROWSER_START', 'Could not reach the browser.')), { once: true });
    });
    const browser = new HeadlessBrowser(child, socket, profile);
    await browser.#call('Browser.setDownloadBehavior', { behavior: 'deny' }).catch(() => undefined);
    const { targetId } = (await browser.#call('Target.createTarget', { url: 'about:blank' })) as { targetId: string };
    const { sessionId } = (await browser.#call('Target.attachToTarget', { targetId, flatten: true })) as { sessionId: string };
    browser.#session = sessionId;
    await browser.#call('Page.enable', {}, sessionId);
    await browser.#call('Runtime.enable', {}, sessionId);
    return browser;
  }

  #call(method: string, params: Record<string, unknown>, sessionId?: string): Promise<Record<string, unknown>> {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#socket.send(JSON.stringify({ id, method, params, ...(sessionId === undefined ? {} : { sessionId }) }));
    });
  }

  async #evaluate<T>(expression: string): Promise<T> {
    const result = (await this.#call('Runtime.evaluate', { expression, returnByValue: true }, this.#session ?? undefined)) as { result?: { value?: T } };
    return result.result?.value as T;
  }

  /** Opens a URL and waits for the page's load event (or the timeout). */
  async open(url: string): Promise<void> {
    const loaded = new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, NAVIGATION_TIMEOUT_MS);
      this.#events.push((method, _params, sessionId) => {
        if (method === 'Page.loadEventFired' && sessionId === this.#session) {
          clearTimeout(timer);
          resolve();
        }
      });
    });
    const navigated = (await this.#call('Page.navigate', { url }, this.#session ?? undefined)) as { errorText?: string };
    if (typeof navigated.errorText === 'string' && navigated.errorText !== '') throw new HnError('BROWSER_NAVIGATE', `The page did not load: ${navigated.errorText}`);
    await loaded;
    // Requests a page starts on load (images, frames, scripts) get a moment to be made and refused.
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  async snapshot(): Promise<PageSnapshot> {
    return this.#evaluate<PageSnapshot>(
      `({ url: location.href, title: document.title, text: (document.body ? document.body.innerText : '').slice(0, 200000), links: Array.from(document.querySelectorAll('a[href]')).slice(0, 200).map((a) => ({ text: (a.innerText || '').trim().slice(0, 120), href: a.href })) })`,
    );
  }

  async screenshot(): Promise<string> {
    const shot = (await this.#call('Page.captureScreenshot', { format: 'png' }, this.#session ?? undefined)) as { data?: string };
    return shot.data ?? '';
  }

  async close(): Promise<void> {
    try {
      this.#socket.close();
    } catch {
      // Already closed.
    }
    this.#child.kill();
    await new Promise((resolve) => setTimeout(resolve, 300));
    await rm(this.#profile, { recursive: true, force: true, maxRetries: 5 }).catch(() => undefined);
  }
}
