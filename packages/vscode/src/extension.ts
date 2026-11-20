import * as vscode from 'vscode';
import { Controller, windowUi } from './controller.ts';

/** The shipped entry point. It has no hooks for tests or other extensions: the approval is always the real modal. */
export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(new Controller(windowUi));
}

export function deactivate(): void {}
