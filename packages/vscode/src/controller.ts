import * as vscode from 'vscode';
import { AcpClient, type AgentEvent, type ApprovalRequest, type LaunchSpec, type SessionMeta } from './acp-client.ts';
import { resolveLaunch } from './launch.ts';
import { sanitize } from './text.ts';

/**
 * The editor side: commands, an output channel, a status line, and the one thing that matters, the approval. An agent's
 * request to change a file opens VS Code's own diff editor on the exact change, then asks in a modal that offers only
 * "Allow once"; closing it, pressing Escape or anything else is a no. Nothing the agent sends is drawn as HTML (there is
 * no webview), and nothing is done in a workspace that is not trusted.
 */

export const DIFF_SCHEME = 'hn-diff';
const SESSION_ID = /^[A-Za-z0-9-]{1,64}$/;

/** What a person is asked. Real in the extension (a modal); scripted in tests. */
export interface Ui {
  askPrompt(): Promise<string | undefined>;
  askSessionId(): Promise<string | undefined>;
  /** True only for an explicit "Allow once". */
  confirm(title: string, detail: string): Promise<boolean>;
}

export const windowUi: Ui = {
  askPrompt: async () => vscode.window.showInputBox({ prompt: 'What should hn do?', ignoreFocusOut: true }),
  askSessionId: async () =>
    vscode.window.showInputBox({ prompt: 'The id of the session to resume', ignoreFocusOut: true, validateInput: (value) => (SESSION_ID.test(value) ? undefined : 'That is not a session id.') }),
  confirm: async (title, detail) => (await vscode.window.showWarningMessage(title, { modal: true, detail }, 'Allow once')) === 'Allow once',
};

export interface ControllerOptions {
  /** How to start hn. Without it: the user's own settings (never a folder's). */
  readonly launch?: (cwd: string) => LaunchSpec;
}

/** Only the user's own settings count: a folder's `.vscode/settings.json` must not choose what runs or where code goes. */
function userSetting(name: string): string {
  const info = vscode.workspace.getConfiguration('hn').inspect<string>(name);
  return (info?.globalValue ?? info?.defaultValue ?? '').trim();
}

function launchFromSettings(cwd: string): LaunchSpec {
  return resolveLaunch({ path: userSetting('path'), model: userSetting('model'), baseUrl: userSetting('baseUrl') }, cwd, process.env);
}

/** A file name safe to put in a URI, keeping the extension so the editor can colour it. */
const diffName = (path: string): string => `${(path.split(/[\\/]/).pop() ?? 'file').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80) || 'file'}`;

export class Controller implements vscode.Disposable {
  readonly #ui: Ui;
  readonly #options: ControllerOptions;
  readonly #output = vscode.window.createOutputChannel('hn');
  readonly #status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  readonly #docs = new Map<string, string>();
  readonly #titles = new Map<string, string>();
  readonly #disposables: vscode.Disposable[] = [];
  #client: AcpClient | null = null;
  #session: { id: string; cwd: string; meta: SessionMeta } | null = null;
  #busy = false;
  #counter = 0;
  #transcript = '';

  constructor(ui: Ui, options: ControllerOptions = {}) {
    this.#ui = ui;
    this.#options = options;
    this.#status.command = 'hn.showOutput';
    this.#paint('idle');
    this.#status.show();
    this.#disposables.push(
      vscode.workspace.registerTextDocumentContentProvider(DIFF_SCHEME, { provideTextDocumentContent: (uri) => this.#docs.get(uri.path) ?? '' }),
      vscode.commands.registerCommand('hn.ask', (prompt?: unknown) => this.ask(typeof prompt === 'string' ? prompt : undefined)),
      vscode.commands.registerCommand('hn.newSession', () => this.newSession()),
      vscode.commands.registerCommand('hn.resumeSession', () => this.resumeSession()),
      vscode.commands.registerCommand('hn.cancel', () => this.cancel()),
      vscode.commands.registerCommand('hn.stop', () => this.stop()),
      vscode.commands.registerCommand('hn.showOutput', () => this.#output.show(true)),
    );
  }

  /** For tests and the status bar: where the session runs, as shown. */
  get statusText(): string {
    return this.#status.text;
  }

  /** What was written to the output channel (the last 200 KB), because VS Code cannot read a channel back. */
  get transcript(): string {
    return this.#transcript;
  }

  get sessionId(): string | null {
    return this.#session?.id ?? null;
  }

  #paint(state: 'idle' | 'running' | 'waiting'): void {
    const meta = this.#session?.meta;
    const where = meta === undefined ? '' : ` · ${meta.mode ?? 'safe'} · ${meta.sandbox === true ? 'in a box' : 'no box'}`;
    const icon = state === 'running' ? '$(sync~spin)' : state === 'waiting' ? '$(bell)' : '$(shield)';
    this.#status.text = `${icon} hn: ${state === 'waiting' ? 'waiting for you' : state}${where}`;
    this.#status.tooltip =
      meta === undefined
        ? 'Haven Harness. Click for the output.'
        : meta.sandbox === true
          ? `Tools run in a verified box (tier ${meta.tier ?? '?'}). Click for the output.`
          : `No box: every change and command asks you first, and only the gate stands between the agent and your files (tier ${meta.tier ?? '?'}). Click for the output.`;
  }

  /** hn reads instruction files, skills and hooks from the folder, so it does nothing until the folder is trusted. */
  #trusted(): boolean {
    if (vscode.workspace.isTrusted) return true;
    void vscode.window.showWarningMessage('hn does nothing in a folder you have not trusted: it reads instruction files and hooks from the folder.');
    return false;
  }

  #folder(): string | null {
    const active = vscode.window.activeTextEditor?.document.uri;
    const chosen = (active === undefined ? undefined : vscode.workspace.getWorkspaceFolder(active)) ?? vscode.workspace.workspaceFolders?.[0];
    if (chosen === undefined || chosen.uri.scheme !== 'file') {
      void vscode.window.showInformationMessage('Open a folder on this computer first.');
      return null;
    }
    return chosen.uri.fsPath;
  }

  #write(text: string): void {
    this.#output.append(text);
    this.#transcript = (this.#transcript + text).slice(-200_000);
  }

  #line(text: string): void {
    this.#write(text + '\n');
  }

  #event(event: AgentEvent): void {
    if (event.type === 'message') this.#write(event.text);
    else if (event.type === 'tool') {
      this.#titles.set(event.id, event.title);
      this.#line(`\n[${event.kind}] ${event.title}`);
    } else if (event.type === 'tool-update') {
      if (event.status === 'completed' || event.status === 'failed') this.#line(`  -> ${event.status}: ${this.#titles.get(event.id) ?? event.id}`);
    }
  }

  async #approve(request: ApprovalRequest, signal: AbortSignal): Promise<'allow' | 'reject'> {
    this.#paint('waiting');
    const opened: vscode.Uri[] = [];
    try {
      const notes: string[] = [`What: ${request.kind}`];
      if (request.diff !== undefined) {
        const n = (this.#counter += 1);
        const name = diffName(request.diff.path);
        const before = vscode.Uri.from({ scheme: DIFF_SCHEME, path: `/${n}/before/${name}` });
        const after = vscode.Uri.from({ scheme: DIFF_SCHEME, path: `/${n}/after/${name}` });
        this.#docs.set(before.path, request.diff.oldText ?? '');
        this.#docs.set(after.path, request.diff.newText);
        opened.push(before, after);
        notes.push(`File: ${request.diff.path}`, request.diff.oldText === null ? 'This file does not exist yet.' : 'The change is open in the diff editor.');
        if (request.diff.cut) notes.push('Only the first part is shown; the rest is cut.');
        await vscode.commands.executeCommand('vscode.diff', before, after, `hn wants to change ${request.diff.path}`, { preview: true });
      } else notes.push('There is no file change to show; only the description below.');
      const yes = signal.aborted ? false : await this.#ui.confirm(request.title, notes.join('\n'));
      return yes && !signal.aborted ? 'allow' : 'reject';
    } finally {
      for (const uri of opened) this.#docs.delete(uri.path);
      await this.#closeDiffs(opened).catch(() => undefined);
      this.#paint(this.#busy ? 'running' : 'idle');
    }
  }

  async #closeDiffs(uris: readonly vscode.Uri[]): Promise<void> {
    const paths = new Set(uris.map((uri) => uri.path));
    const tabs: vscode.Tab[] = [];
    for (const group of vscode.window.tabGroups.all) {
      for (const tab of group.tabs) {
        if (tab.input instanceof vscode.TabInputTextDiff && paths.has(tab.input.modified.path)) tabs.push(tab);
      }
    }
    if (tabs.length > 0) await vscode.window.tabGroups.close(tabs);
  }

  async #connect(cwd: string): Promise<AcpClient | null> {
    if (this.#client?.alive === true) return this.#client;
    this.#line(`\n[hn: starting in ${cwd}]`);
    try {
      const spec = (this.#options.launch ?? launchFromSettings)(cwd);
      this.#client = await AcpClient.start(spec, {
        event: (event) => this.#event(event),
        approve: (request, signal) => this.#approve(request, signal),
        exited: (reason) => {
          this.#line(`\n[hn: ${sanitize(reason)}]`);
          this.#client = null;
          this.#session = null;
          this.#busy = false;
          this.#paint('idle');
          void vscode.window.showErrorMessage('hn stopped. See the hn output for why.');
        },
      });
      return this.#client;
    } catch (error) {
      const message = sanitize(error instanceof Error ? error.message : String(error));
      this.#line(`\n[hn: ${message}]`);
      void vscode.window.showErrorMessage(message);
      return null;
    }
  }

  async #open(resume?: string): Promise<boolean> {
    if (!this.#trusted()) return false;
    const cwd = this.#session?.cwd ?? this.#folder();
    if (cwd === null) return false;
    const client = await this.#connect(cwd);
    if (client === null) return false;
    try {
      if (resume === undefined) {
        const { sessionId, meta } = await client.newSession(cwd);
        this.#session = { id: sessionId, cwd, meta };
      } else {
        await client.loadSession(resume, cwd);
        this.#session = { id: resume, cwd, meta: {} };
      }
      this.#line(`[hn: session ${this.#session.id}]`);
      this.#paint('idle');
      return true;
    } catch (error) {
      const message = sanitize(error instanceof Error ? error.message : String(error));
      this.#line(`\n[hn: ${message}]`);
      void vscode.window.showErrorMessage(message);
      return false;
    }
  }

  async newSession(): Promise<void> {
    if (this.#busy) return void vscode.window.showInformationMessage('hn is working on a turn. Stop it first.');
    this.#session = null;
    await this.#open();
  }

  async resumeSession(): Promise<void> {
    if (this.#busy) return void vscode.window.showInformationMessage('hn is working on a turn. Stop it first.');
    const id = (await this.#ui.askSessionId())?.trim();
    if (id === undefined || id === '') return;
    if (!SESSION_ID.test(id)) return void vscode.window.showErrorMessage('That is not a session id.');
    this.#session = null;
    await this.#open(id);
  }

  async ask(given?: string): Promise<void> {
    if (!this.#trusted()) return;
    if (this.#busy) return void vscode.window.showInformationMessage('hn is already working on a turn. Stop it first, or wait.');
    const prompt = (given ?? (await this.#ui.askPrompt()))?.trim();
    if (prompt === undefined || prompt === '') return;
    if (this.#session === null || this.#client?.alive !== true) {
      this.#session = null;
      if (!(await this.#open())) return;
    }
    const session = this.#session;
    const client = this.#client;
    if (session === null || client === null) return;
    this.#busy = true;
    this.#paint('running');
    this.#output.show(true);
    this.#line(`\n> ${prompt}\n`);
    try {
      const reason = await client.prompt(session.id, prompt);
      this.#line(`\n[${reason}]`);
    } catch (error) {
      this.#line(`\n[hn: ${sanitize(error instanceof Error ? error.message : String(error))}]`);
    } finally {
      this.#busy = false;
      this.#paint('idle');
    }
  }

  cancel(): void {
    if (this.#client !== null && this.#session !== null && this.#busy) this.#client.cancel(this.#session.id);
  }

  async stop(): Promise<void> {
    const client = this.#client;
    this.#client = null;
    this.#session = null;
    this.#busy = false;
    await client?.close();
    this.#paint('idle');
  }

  dispose(): void {
    void this.stop();
    for (const item of this.#disposables) item.dispose();
    this.#output.dispose();
    this.#status.dispose();
  }
}
