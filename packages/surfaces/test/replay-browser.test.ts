import assert from 'node:assert/strict';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { KeyStore } from '@hn/provider';
import { startReplayServe, startServe } from '@hn/surfaces';
import { startFakeOpenAI, withTempDir, type FakeOpenAI } from '@hn/testkit';
import { Browser, findBrowser, type Page } from './browser-fixture.ts';
import { frameRanges, recordSession, startScriptedModel } from './replay-fixture.ts';

/**
 * The replay screen in a REAL Chrome-family browser, because most of what it promises is about what a browser does with
 * it: that a command which looks like markup is shown as characters, that no script runs but the page's own, that nothing
 * is fetched from anywhere else, and that a person can step through and see each decision. A machine with no such browser
 * skips this; CI sets HN_REQUIRE_BROWSER=1, so there a missing browser fails the run instead.
 */

const browserPath = findBrowser();
const required = process.env['HN_REQUIRE_BROWSER'] === '1';

describe('the replay screen in a real browser', () => {
  let model: FakeOpenAI;
  before(async () => {
    model = await startScriptedModel();
  });
  after(async () => {
    await model.close();
  });

  it('a browser is available when one is required', () => {
    if (required) assert.ok(browserPath !== null, 'HN_REQUIRE_BROWSER=1 but no Chrome or Edge was found. Set HN_BROWSER to one.');
  });

  /** Text of the first element that matches, or null. */
  const text = (page: Page, selector: string): Promise<string | null> => page.eval<string | null>(`(function(){var n=document.querySelector(${JSON.stringify(selector)});return n===null?null:n.textContent;})()`);
  const click = (page: Page, selector: string): Promise<boolean> => page.eval<boolean>(`(function(){var n=document.querySelector(${JSON.stringify(selector)});if(n===null)return false;n.click();return true;})()`);
  const count = (page: Page, selector: string): Promise<number> => page.eval<number>(`document.querySelectorAll(${JSON.stringify(selector)}).length`);
  const titles = (page: Page): Promise<string[]> => page.eval<string[]>('Array.prototype.map.call(document.querySelectorAll("#timeline li"), function(li){return li.textContent;})');
  const choose = async (page: Page, id: string): Promise<void> => {
    await page.eval(`(function(){var s=document.getElementById("session");s.value=${JSON.stringify(id)};s.dispatchEvent(new Event("change"));})()`);
  };
  const filter = async (page: Page, name: string): Promise<void> => {
    assert.ok(await click(page, `#filters button[data-filter="${name}"]`), `no filter ${name}`);
    await page.waitFor(`document.querySelector('#filters button[data-filter="${name}"]').getAttribute('aria-pressed') === 'true'`);
  };

  it('attack: replay_log_text_cannot_become_markup - logs in, lists sessions, and steps through one: each gate decision, approval, taint change and diff, with the state at each step', { timeout: 240_000 }, async (t) => {
    if (browserPath === null) {
      if (required) assert.fail('HN_REQUIRE_BROWSER=1 but no Chrome or Edge was found.');
      return t.skip('no Chrome or Edge on this machine (set HN_BROWSER to one)');
    }
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const first = await recordSession(top, model);
      const second = await recordSession(top, model);
      assert.notEqual(first.sessionId, second.sessionId);
      // The second session's log is then edited by one byte.
      const forged = await readFile(second.file);
      const ranges = frameRanges(forged);
      const mid = Math.floor(((ranges[1] as { start: number }).start + (ranges[1] as { end: number }).end) / 2);
      forged.writeUInt8(forged.readUInt8(mid) ^ 0xff, mid);
      await writeFile(second.file, forged);

      const served = await startReplayServe({ cwd: first.project, env: { HN_HOME: first.home } });
      const profile = join(top, 'browser-profile');
      await mkdir(profile);
      const browser = await Browser.launch(browserPath, profile);
      try {
        const page = await browser.page();
        const base = `http://127.0.0.1:${served.port}`;

        // --- Login, as a person does it: the form, with the token typed in. -------------------------------------------------
        await page.goto(`${base}/replay`);
        assert.equal(await page.eval('location.pathname'), '/login', 'an unauthenticated page was not sent to the login');
        assert.equal(await count(page, '#timeline'), 0, 'a log was shown before login');
        await page.eval(`(function(){document.querySelector("input[name=token]").value=${JSON.stringify(served.token)};document.querySelector("form").submit();})()`);
        await page.waitFor('location.pathname === "/replay" && document.querySelectorAll("#session option").length > 2');
        assert.equal(await page.eval('document.title'), 'hn session replay');

        // --- The verified session. --------------------------------------------------------------------------------------------
        await choose(page, first.sessionId);
        await page.waitFor('document.getElementById("integrity").className === "verified" && document.querySelectorAll("#timeline li").length > 20');
        assert.match((await text(page, '#integrity')) ?? '', /Log verified/);
        const summary = (await text(page, '#summary')) ?? '';
        assert.match(summary, /Refused by the gate\s*2/);
        assert.match(summary, /Approvals asked\s*5 \(1 denied\)/);
        assert.match(summary, /Files changed\s*new\.txt/);
        assert.match(summary, /Untrusted input\s*entered at step \d+/);
        const total = (await titles(page)).length;
        assert.match((await text(page, '#position')) ?? '', new RegExp(`^1 / ${total}$`));

        // The gate's decisions only: allowed ones and the two refusals, each with its reason.
        await filter(page, 'gate');
        const gate = await titles(page);
        assert.ok(gate.every((title) => /Gate (allowed|REFUSED)/.test(title)), gate.join(' | '));
        assert.equal(gate.filter((title) => /REFUSED - Gate REFUSED/.test(title)).length, 2);
        assert.ok(await click(page, '#next-refusal'));
        assert.match((await text(page, '#detail h2')) ?? '', /Gate REFUSED read_file at the path-jail step/);
        assert.match((await text(page, '#detail pre')) ?? '', /outside the project/);
        assert.equal(await text(page, '#detail .badge'), 'REFUSED');
        assert.match((await text(page, '#state')) ?? '', /Refused by the gate so far\s*1/);
        assert.ok(await click(page, '#next-refusal'));
        assert.match((await text(page, '#detail h2')) ?? '', /Gate REFUSED bash at the guardian-or-human step/);
        assert.match((await text(page, '#detail pre')) ?? '', /The user said no/);
        assert.match((await text(page, '#state')) ?? '', /Refused by the gate so far\s*2/);

        // Approvals, and who answered.
        await filter(page, 'approvals');
        const approvals = await titles(page);
        assert.ok(approvals.some((title) => /Denied by human/.test(title)) && approvals.some((title) => /Allowed once by human/.test(title)), approvals.join(' | '));

        // Taint: nothing untrusted before, and it is flagged at the moment it entered.
        await filter(page, 'taint');
        assert.equal((await titles(page)).length, 1);
        assert.match((await text(page, '#detail h2')) ?? '', /Untrusted input entered the session/);
        assert.match((await text(page, '#detail pre')) ?? '', /an untrusted tool-output row entered/);
        assert.match((await text(page, '#state')) ?? '', /Untrusted input in the session\s*YES/);
        await filter(page, 'all');
        await page.eval('document.activeElement && document.activeElement.blur()');
        await page.press('ArrowLeft', 37);
        await page.waitFor('document.querySelector("#state dd").textContent === "no"');
        assert.match((await text(page, '#state')) ?? '', /Untrusted input in the session\s*no/, 'the step before the taint already showed untrusted input');

        // File changes, as a diff: the edit shows what was replaced and what replaced it.
        await filter(page, 'files');
        await page.waitFor('document.querySelectorAll("#timeline li").length >= 2');
        assert.ok(await page.eval<boolean>('(function(){var li=Array.prototype.filter.call(document.querySelectorAll("#timeline li"),function(l){return /edit_file/.test(l.textContent);})[0];if(!li)return false;li.click();return true;})()'));
        await page.waitFor('document.querySelectorAll("#detail .diff .del").length > 0');
        assert.equal(await text(page, '#detail .diff .del'), '- hello');
        assert.equal(await text(page, '#detail .diff .add'), '+ hello world');
        assert.match((await text(page, '#detail .diff .head')) ?? '', /Edit to new\.txt/);

        // Keyboard: End goes to the last step, an arrow goes back one.
        await filter(page, 'all');
        await page.eval('document.activeElement && document.activeElement.blur()');
        await page.press('End', 35);
        await page.waitFor(`document.getElementById("position").textContent === "${total} / ${total}"`);
        await page.press('ArrowLeft', 37);
        await page.waitFor(`document.getElementById("position").textContent === "${total - 1} / ${total}"`);
        // The address says which step this is, so it can be shared and reopened.
        assert.equal(await page.eval('location.hash'), `#${first.sessionId}:${total - 2}`);

        // --- A command written to attack the page is shown as characters, and nothing in it runs. -----------------------------
        await filter(page, 'commands');
        assert.ok(await page.eval<boolean>('(function(){var li=Array.prototype.filter.call(document.querySelectorAll("#timeline li"),function(l){return /img src=x/.test(l.textContent);})[0];if(!li)return false;li.click();return true;})()'));
        await page.waitFor('document.querySelector("#detail pre") && /onerror/.test(document.querySelector("#detail pre").textContent)');
        const shown = (await text(page, '#detail pre')) ?? '';
        assert.match(shown, /<img src=x onerror=alert\(1\)><script>alert\(2\)<\/script>/, 'the markup was not shown as the characters it is');
        assert.match(shown, /\\u\{202e\}evil\\u\{200b\}\\u\{1b\}/, 'hidden characters were not written out');
        assert.equal(await count(page, 'img'), 0, 'an image element was made from log text');
        assert.equal(await count(page, 'iframe, object, embed, link[rel=import]'), 0);
        assert.equal(await count(page, 'script'), 1, 'a script element other than the page\'s own exists');
        assert.equal(await page.eval('document.querySelectorAll("#timeline [onerror], #detail [onerror], [onclick], [onload]").length'), 0);
        assert.deepEqual(page.dialogs, [], 'a script dialog opened');
        assert.deepEqual(page.problems, [], 'the page reported an error, or the browser blocked something');
        assert.ok(
          page.requests.every((url) => url.startsWith(base) || url.startsWith('about:') || url.startsWith('data:')),
          `the page asked another address for something: ${page.requests.filter((url) => !url.startsWith(base)).join(', ')}`,
        );

        // --- The edited log: refused, with nothing of it shown. ------------------------------------------------------------------
        await choose(page, second.sessionId);
        await page.waitFor('document.getElementById("integrity").className === "refused"');
        assert.match((await text(page, '#integrity')) ?? '', /REFUSED: this log does not verify/);
        assert.equal(await page.eval('document.getElementById("controls").hidden'), true);
        assert.equal(await page.eval('document.getElementById("layout").hidden'), true);
        assert.equal(await text(page, '#summary'), '');
        // Nothing of the earlier session is left in the page, hidden or not, and the empty panels are not drawn.
        assert.equal(await page.eval('document.getElementById("timeline").childElementCount'), 0, 'an earlier session had steps left in the page');
        assert.equal(await text(page, '#detail'), '');
        assert.equal(await text(page, '#state'), '');
        assert.equal(await page.eval('getComputedStyle(document.getElementById("layout")).display'), 'none', 'the panels of a refused log are drawn');
        assert.equal(await page.eval('getComputedStyle(document.getElementById("controls")).display'), 'none');
        const everything = (await page.eval<string>('document.body.innerText')) ?? '';
        assert.doesNotMatch(everything, /new\.txt|node --version|do the work|path-jail/, 'a forged log leaked into the page');

        // --- And back to the good one, and straight to a step from an address. ---------------------------------------------------
        await page.goto("about:blank");
        await page.goto(`${base}/replay#${first.sessionId}:5`);
        await page.waitFor('document.getElementById("integrity").className === "verified"');
        await page.waitFor(`document.getElementById("position").textContent === "6 / ${total}"`);
        assert.deepEqual(page.dialogs, []);
      } finally {
        await browser.close();
        await served.close();
      }
    });
  });

  it('the live hn serve login works in a real browser: the form posts with its own origin, not null, as a no-referrer policy would make it', { timeout: 120_000 }, async (t) => {
    if (browserPath === null) {
      if (required) assert.fail('HN_REQUIRE_BROWSER=1 but no Chrome or Edge was found.');
      return t.skip('no Chrome or Edge on this machine (set HN_BROWSER to one)');
    }
    await withTempDir(async (dir) => {
      const top = await realpath(dir);
      const project = join(top, 'project');
      await mkdir(project);
      const live = await startFakeOpenAI(() => ({ text: 'hi' }));
      const served = await startServe({ keys: KeyStore.capture({}), cwd: project, defaults: { model: 'fake', baseUrl: live.url, window: 64_000 }, env: { HN_HOME: join(top, 'home') }, sessionExtras: { verify: 'off' } });
      const profile = join(top, 'browser-profile');
      await mkdir(profile);
      const browser = await Browser.launch(browserPath, profile);
      try {
        const page = await browser.page();
        await page.goto(`http://127.0.0.1:${served.port}/`);
        assert.equal(await page.eval('location.pathname'), '/login');
        await page.eval(`(function(){document.querySelector("input[name=token]").value=${JSON.stringify(served.token)};document.querySelector("form").submit();})()`);
        await page.waitFor('location.pathname === "/" && /^session /.test(document.getElementById("status").textContent)');
        // The replay screen is part of the same server, behind the same login.
        await page.goto(`http://127.0.0.1:${served.port}/replay`);
        await page.waitFor('document.querySelectorAll("#session option").length >= 1');
        assert.deepEqual(page.problems, []);
      } finally {
        await browser.close();
        await served.close();
        await live.close();
      }
    });
  });
});
