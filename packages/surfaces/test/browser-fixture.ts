import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';

/**
 * A real Chrome or Edge, driven over the DevTools protocol by a client that is a page long (no dependency). It is a test
 * tool: it starts a browser with its own empty profile, in headless mode, opens pages, runs script in them and reads the
 * answer, and records what the page itself complains about (a script dialog, an uncaught error, a console error, which
 * is where a content-security-policy violation shows up).
 */

const WINDOWS = [
  ['ProgramFiles', 'Google\\Chrome\\Application\\chrome.exe'],
  ['ProgramFiles(x86)', 'Google\\Chrome\\Application\\chrome.exe'],
  ['LOCALAPPDATA', 'Google\\Chrome\\Application\\chrome.exe'],
  ['ProgramFiles(x86)', 'Microsoft\\Edge\\Application\\msedge.exe'],
  ['ProgramFiles', 'Microsoft\\Edge\\Application\\msedge.exe'],
] as const;
const MAC = ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', '/Applications/Chromium.app/Contents/MacOS/Chromium'];
const LINUX = ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge'];

/** Where a Chrome-family browser is on this machine, or null. `HN_BROWSER` names one explicitly. */
export function findBrowser(env: NodeJS.ProcessEnv = process.env): string | null {
  const given = env['HN_BROWSER'];
  if (given !== undefined && given !== '') return existsSync(given) ? given : null;
  if (process.platform === 'win32') {
    for (const [variable, rest] of WINDOWS) {
      const base = env[variable];
      if (base !== undefined && existsSync(join(base, rest))) return join(base, rest);
    }
    return null;
  }
  if (process.platform === 'darwin') return MAC.find((path) => existsSync(path)) ?? null;
  for (const folder of (env['PATH'] ?? '').split(delimiter)) {
    for (const name of LINUX) if (folder !== '' && existsSync(join(folder, name))) return join(folder, name);
  }
  return null;
}

interface Pending {
  readonly resolve: (value: Record<string, unknown>) => void;
  readonly reject: (error: Error) => void;
}

export class Browser {
  readonly #socket: WebSocket;
  readonly #child: ChildProcess;
  readonly #pending = new Map<number, Pending>();
  readonly #listeners = new Map<string, ((params: Record<string, unknown>, sessionId: string | undefined) => void)[]>();
  #next = 0;

  private constructor(socket: WebSocket, child: ChildProcess) {
    this.#socket = socket;
    this.#child = child;
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data)) as { id?: number; result?: Record<string, unknown>; error?: { message: string }; method?: string; params?: Record<string, unknown>; sessionId?: string };
      if (message.id !== undefined) {
        const waiting = this.#pending.get(message.id);
        this.#pending.delete(message.id);
        if (message.error !== undefined) waiting?.reject(new Error(message.error.message));
        else waiting?.resolve(message.result ?? {});
      } else if (message.method !== undefined) {
        for (const listener of this.#listeners.get(message.method) ?? []) listener(message.params ?? {}, message.sessionId);
      }
    });
  }

  static async launch(path: string, profile: string): Promise<Browser> {
    // A container or a locked-down runner may not let the browser make its own sandbox; say so explicitly, never by default.
    const extra = process.env['HN_BROWSER_NO_SANDBOX'] === '1' ? ['--no-sandbox'] : [];
    const child = spawn(path, [...extra, '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-gpu', '--disable-background-networking', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
    // However the test ends, the browser must not outlive it: a stray browser keeps the test runner from exiting.
    child.unref();
    process.once('exit', () => child.kill());
    const endpoint = await new Promise<string>((resolve, reject) => {
      let text = '';
      const timer = setTimeout(() => reject(new Error(`The browser did not say where to connect within 60 seconds. It printed: ${text}`)), 60_000);
      child.stderr?.on('data', (chunk: Buffer) => {
        text += chunk.toString();
        const found = /DevTools listening on (ws:\/\/\S+)/.exec(text);
        if (found !== null) {
          clearTimeout(timer);
          resolve(found[1] as string);
        }
      });
      child.once('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`The browser exited with ${code} before it was ready. It printed: ${text}`));
      });
    });
    const socket = new WebSocket(endpoint);
    await new Promise<void>((resolve, reject) => {
      socket.addEventListener('open', () => resolve());
      socket.addEventListener('error', () => reject(new Error('Could not connect to the browser.')));
    });
    return new Browser(socket, child);
  }

  on(method: string, listener: (params: Record<string, unknown>, sessionId: string | undefined) => void): void {
    this.#listeners.set(method, [...(this.#listeners.get(method) ?? []), listener]);
  }

  send(method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<Record<string, unknown>> {
    const id = (this.#next += 1);
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#socket.send(JSON.stringify({ id, method, params, ...(sessionId === undefined ? {} : { sessionId }) }));
    });
  }

  async page(): Promise<Page> {
    const { targetId } = (await this.send('Target.createTarget', { url: 'about:blank' })) as { targetId: string };
    const { sessionId } = (await this.send('Target.attachToTarget', { targetId, flatten: true })) as { sessionId: string };
    const page = new Page(this, sessionId);
    await page.start();
    return page;
  }

  async close(): Promise<void> {
    const exited = new Promise<void>((resolve) => (this.#child.exitCode === null ? this.#child.once('exit', () => resolve()) : resolve()));
    try {
      await Promise.race([this.send('Browser.close'), new Promise((resolve) => setTimeout(resolve, 5_000))]);
    } catch {
      // A browser that is already going away cannot answer.
    }
    this.#socket.close();
    const timer = setTimeout(() => this.#child.kill(), 10_000);
    await exited;
    clearTimeout(timer);
  }
}

export class Page {
  /** Script dialogs the page opened (an `alert` from injected markup would be here). */
  readonly dialogs: string[] = [];
  /** Uncaught errors and console errors, which is where a blocked inline script or a CSP violation is reported. */
  readonly problems: string[] = [];
  /** Every address the page asked the network for. */
  readonly requests: string[] = [];

  readonly browser: Browser;
  readonly sessionId: string;

  constructor(browser: Browser, sessionId: string) {
    this.browser = browser;
    this.sessionId = sessionId;
  }

  async start(): Promise<void> {
    this.browser.on('Page.javascriptDialogOpening', (params, session) => {
      if (session === this.sessionId) {
        this.dialogs.push(String(params['message']));
        void this.browser.send('Page.handleJavaScriptDialog', { accept: false }, this.sessionId).catch(() => undefined);
      }
    });
    this.browser.on('Runtime.exceptionThrown', (params, session) => {
      if (session === this.sessionId) this.problems.push(`exception: ${JSON.stringify(params['exceptionDetails'])}`);
    });
    this.browser.on('Runtime.consoleAPICalled', (params, session) => {
      if (session === this.sessionId && (params['type'] === 'error' || params['type'] === 'assert')) this.problems.push(`console.${String(params['type'])}: ${JSON.stringify(params['args'])}`);
    });
    this.browser.on('Log.entryAdded', (params, session) => {
      const entry = params['entry'] as { level?: string; text?: string; source?: string; url?: string } | undefined;
      if (session === this.sessionId && entry?.level === 'error' && entry.source !== 'network') this.problems.push(`log: ${entry.text} ${entry.url ?? ''}`);
    });
    this.browser.on('Network.requestWillBeSent', (params, session) => {
      if (session === this.sessionId) this.requests.push(String((params['request'] as { url?: string } | undefined)?.url));
    });
    await Promise.all(['Page', 'Runtime', 'Log', 'Network'].map((domain) => this.browser.send(`${domain}.enable`, {}, this.sessionId)));
  }

  async goto(url: string): Promise<void> {
    await this.browser.send('Page.navigate', { url }, this.sessionId);
    await this.waitFor('document.readyState === "complete"');
  }

  /** Runs an expression in the page and returns its value. */
  async eval<T>(expression: string): Promise<T> {
    const reply = (await this.browser.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, this.sessionId)) as { result?: { value?: T }; exceptionDetails?: { text?: string; exception?: { description?: string } } };
    if (reply.exceptionDetails !== undefined) throw new Error(`The page threw: ${reply.exceptionDetails.exception?.description ?? reply.exceptionDetails.text}`);
    return reply.result?.value as T;
  }

  /** Waits until an expression is truthy, and says what it was waiting for if it never is. */
  async waitFor(expression: string, ms = 20_000): Promise<void> {
    const started = Date.now();
    let last: unknown;
    while (Date.now() - started < ms) {
      try {
        last = await this.eval<unknown>(expression);
        if (last) return;
      } catch (error) {
        last = error instanceof Error ? error.message : error;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`Waited ${ms} ms for ${expression}. Last value: ${String(last)}. Page problems: ${this.problems.join(' | ')}`);
  }

  /** A real key press, as the browser's own input handling sees it. */
  async press(key: string, code: number): Promise<void> {
    for (const type of ['keyDown', 'keyUp']) await this.browser.send('Input.dispatchKeyEvent', { type, key, code: key, windowsVirtualKeyCode: code }, this.sessionId);
  }
}
