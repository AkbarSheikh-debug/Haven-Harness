// Runs inside a real VS Code that has the PACKED extension installed (not the source). Trusted folder.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import * as vscode from 'vscode';

export async function run(config) {
  assert.equal(vscode.workspace.isTrusted, true);
  const extension = vscode.extensions.getExtension(config.extensionId);
  assert.ok(extension, `${config.extensionId} is not installed`);
  assert.equal(extension.packageJSON.version, config.version);

  // Activation by command, with nothing else to start it.
  assert.equal(extension.isActive, false, 'the extension started by itself; it should wait for a command');
  await vscode.commands.executeCommand('hn.showOutput');
  assert.equal(extension.isActive, true);
  const commands = await vscode.commands.getCommands(true);
  for (const id of ['hn.ask', 'hn.newSession', 'hn.resumeSession', 'hn.cancel', 'hn.stop', 'hn.showOutput']) assert.ok(commands.includes(id), `${id} is not registered`);

  // The three settings exist, with the defaults, and a folder's own settings file cannot change them.
  const project = vscode.workspace.workspaceFolders[0].uri.fsPath;
  await mkdir(join(project, '.vscode'), { recursive: true });
  await writeFile(join(project, '.vscode', 'settings.json'), JSON.stringify({ 'hn.path': 'C:/evil/hn.exe', 'hn.baseUrl': 'http://evil.example', 'hn.model': 'evil' }));
  await new Promise((resolve) => setTimeout(resolve, 1500));
  const settings = vscode.workspace.getConfiguration('hn');
  assert.equal(settings.inspect('path').defaultValue, 'hn');
  assert.equal(settings.inspect('baseUrl').defaultValue, '');
  assert.equal(settings.inspect('model').defaultValue, '');
  for (const name of ['path', 'baseUrl', 'model']) {
    const info = settings.inspect(name);
    assert.equal(info.workspaceValue, undefined, `a folder's settings set hn.${name}`);
    assert.equal(info.workspaceFolderValue, undefined, `a folder's settings set hn.${name}`);
  }
  assert.equal(settings.get('path'), 'hn');
}
