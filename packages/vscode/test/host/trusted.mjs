// Runs inside a real VS Code, in a trusted folder. The agent is a real `hn acp` process with a fake model.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import * as vscode from 'vscode';
import { Controller, DIFF_SCHEME } from '../../dist/controller.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function until(check, what, ms = 90_000) {
  const started = Date.now();
  while (Date.now() - started < ms) {
    if (await check()) return;
    await sleep(50);
  }
  throw new Error(`timed out waiting for ${what}`);
}

const NOTES = 'alpha\nbeta\n';

/** The diff editors hn has open right now, with the text each side shows. */
async function openDiffs() {
  const tabs = vscode.window.tabGroups.all.flatMap((group) => group.tabs).filter((tab) => tab.input instanceof vscode.TabInputTextDiff && tab.input.modified.scheme === DIFF_SCHEME);
  return Promise.all(tabs.map(async (tab) => ({ before: (await vscode.workspace.openTextDocument(tab.input.original)).getText(), after: (await vscode.workspace.openTextDocument(tab.input.modified)).getText(), label: tab.label })));
}

export async function run(config) {
  assert.equal(vscode.workspace.isTrusted, true, 'the folder should be trusted for this suite');
  const project = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  assert.ok(project, 'no folder was opened');
  const confirms = [];
  let answer = true;
  let resumeId;
  const ui = {
    askPrompt: async () => undefined,
    askSessionId: async () => resumeId,
    confirm: async (title, detail) => {
      // What is on screen at the moment the person is asked.
      await until(async () => (await openDiffs()).length > 0 || !detail.includes('diff editor'), 'the diff editor to open', 10_000);
      confirms.push({ title, detail, diffs: await openDiffs() });
      return answer;
    },
  };
  const env = { ...process.env, HN_HOME: config.home };
  delete env.ELECTRON_RUN_AS_NODE;
  const controller = new Controller(ui, { launch: (cwd) => ({ command: config.node, args: [config.launcher, 'acp', '--model', 'fake', '--base-url', config.modelUrl, '--window', '64000'], cwd, env }) });
  try {
    const commands = await vscode.commands.getCommands(true);
    for (const id of ['hn.ask', 'hn.newSession', 'hn.resumeSession', 'hn.cancel', 'hn.stop', 'hn.showOutput']) assert.ok(commands.includes(id), `${id} is not registered`);

    // A plain turn, then where the session runs is shown.
    await vscode.commands.executeCommand('hn.ask', 'say hello');
    assert.match(controller.transcript, /hello from hn/);
    assert.match(controller.transcript, /\[end_turn\]/);
    assert.match(controller.statusText, /idle/);
    assert.match(controller.statusText, /no box/, 'the status line does not say there is no box');
    const firstSession = controller.sessionId;
    assert.ok(firstSession, 'no session id');

    // An edit: the real diff editor shows the exact change, the file is written only after allow once, and the tab closes.
    await writeFile(join(project, 'notes.txt'), NOTES);
    await vscode.commands.executeCommand('hn.ask', 'EDIT notes.txt');
    assert.equal(confirms.length, 1, 'the edit was never asked about');
    assert.equal(confirms[0].diffs.length, 1, 'the diff editor was not open when the person was asked');
    assert.equal(confirms[0].diffs[0].before, NOTES);
    assert.equal(confirms[0].diffs[0].after, 'alpha\ngamma\n');
    assert.match(confirms[0].title, /edit notes\.txt/);
    assert.equal(await readFile(join(project, 'notes.txt'), 'utf8'), 'alpha\ngamma\n');
    assert.equal((await openDiffs()).length, 0, 'the diff tab was left open');
    assert.match(controller.transcript, /-> completed: edit_file/);

    // Reject, and anything that is not an explicit yes, applies nothing and is reported failed.
    answer = false;
    await writeFile(join(project, 'notes.txt'), NOTES);
    await vscode.commands.executeCommand('hn.ask', 'EDIT notes.txt');
    assert.equal(confirms.length, 2);
    assert.equal(await readFile(join(project, 'notes.txt'), 'utf8'), NOTES, 'a rejected edit was written');
    assert.match(controller.transcript, /-> failed: edit_file/);

    // A second turn while one is running is refused, and cancel ends the running one.
    const slow = vscode.commands.executeCommand('hn.ask', 'SLOW');
    await until(() => /\[other\]|\[hn: starting|> SLOW/.test(controller.transcript) && controller.statusText.includes('running'), 'the slow turn to start', 20_000);
    await sleep(500);
    await vscode.commands.executeCommand('hn.ask', 'say hello');
    await vscode.commands.executeCommand('hn.cancel');
    await slow;
    assert.match(controller.transcript, /\[cancelled\]/);
    assert.equal((controller.transcript.match(/> say hello/g) ?? []).length, 1, 'a second turn was started while one was running');

    // Stop, then resume the same session in a fresh process.
    await vscode.commands.executeCommand('hn.stop');
    assert.equal(controller.sessionId, null);
    resumeId = firstSession;
    await vscode.commands.executeCommand('hn.resumeSession');
    assert.equal(controller.sessionId, firstSession);
    await vscode.commands.executeCommand('hn.ask', 'say hello again');
    assert.match(controller.transcript, /\[end_turn\]\s*$/);
    await vscode.commands.executeCommand('hn.stop');
  } finally {
    controller.dispose();
  }
}
