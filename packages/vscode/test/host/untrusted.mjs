// Runs inside a real VS Code, in a folder that was not trusted. hn must start nothing.
import assert from 'node:assert/strict';
import * as vscode from 'vscode';
import { Controller } from '../../dist/controller.js';

export async function run(config) {
  assert.equal(vscode.workspace.isTrusted, false, 'this suite needs an untrusted folder');
  let asked = 0;
  const ui = { askPrompt: async () => ((asked += 1), 'say hello'), askSessionId: async () => 'abc', confirm: async () => true };
  let launched = 0;
  const controller = new Controller(ui, {
    launch: (cwd) => {
      launched += 1;
      return { command: config.node, args: [config.launcher, 'acp', '--model', 'fake', '--base-url', config.modelUrl], cwd, env: { ...process.env, HN_HOME: config.home } };
    },
  });
  try {
    await vscode.commands.executeCommand('hn.ask', 'say hello');
    await vscode.commands.executeCommand('hn.ask');
    await vscode.commands.executeCommand('hn.newSession');
    await vscode.commands.executeCommand('hn.resumeSession');
    assert.equal(launched, 0, 'hn was started in an untrusted folder');
    assert.equal(controller.sessionId, null);
    assert.equal(controller.transcript.includes('starting'), false);
  } finally {
    controller.dispose();
  }
}
