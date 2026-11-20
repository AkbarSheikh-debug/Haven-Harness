import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import { buildExtension, requireVsCode, runHost, skipWithoutVsCode, vscodeExe, withProject } from './host-driver.ts';

describe('the extension in a real VS Code', { skip: skipWithoutVsCode }, () => {
  before(async () => {
    assert.ok(vscodeExe !== null || !requireVsCode, 'HN_REQUIRE_VSCODE=1 but no VS Code was found; set HN_VSCODE.');
    buildExtension();
  });

  it('shows the exact change in the diff editor, applies it only after allow once, and applies nothing on reject or cancel', { timeout: 300_000 }, async () => {
    await withProject(async (top, project, url) => {
      const outcome = await runHost({ suite: 'trusted.mjs', trusted: true }, url, top, project);
      assert.equal(outcome.ok, true, `${outcome.error ?? ''}\n${outcome.output.slice(-2000)}`);
    });
  });

  it('attack: editor_untrusted_folder_starts_nothing - starts nothing in a folder that was not trusted', { timeout: 300_000 }, async () => {
    await withProject(async (top, project, url, requests) => {
      const outcome = await runHost({ suite: 'untrusted.mjs', trusted: false }, url, top, project);
      assert.equal(outcome.ok, true, `${outcome.error ?? ''}\n${outcome.output.slice(-2000)}`);
      assert.equal(requests(), 0, 'a model request was made from an untrusted folder');
    });
  });
});
