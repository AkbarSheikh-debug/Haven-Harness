// Runs inside a real VS Code that has the PACKED extension installed, in a folder that was not trusted.
import assert from 'node:assert/strict';
import * as vscode from 'vscode';

export async function run(config) {
  assert.equal(vscode.workspace.isTrusted, false);
  // The manifest says untrusted folders are not supported, so VS Code must not run the extension at all. It may not
  // even list it to the extension host; if it does, it must not be active.
  const extension = vscode.extensions.getExtension(config.extensionId);
  await assert.rejects(Promise.resolve(vscode.commands.executeCommand('hn.ask', 'say hello')), /not found/);
  assert.ok(extension === undefined || extension.isActive === false, 'the extension ran in an untrusted folder');
  assert.ok(!(await vscode.commands.getCommands(true)).includes('hn.ask'), 'hn.ask is registered in an untrusted folder');
}
