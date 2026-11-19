import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { HELPER_PLATFORMS, helperAssetName } from '@hn/release';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const FOLDER = join(ROOT, '.github', 'workflows');

async function workflows(): Promise<Map<string, string>> {
  const found = new Map<string, string>();
  for (const name of (await readdir(FOLDER)).sort()) if (/\.ya?ml$/.test(name)) found.set(name, await readFile(join(FOLDER, name), 'utf8'));
  return found;
}

/** The text of every `run:` block (one line or a literal block), so secrets and untrusted input can be looked for there. */
function runScripts(text: string): string[] {
  const lines = text.split('\n');
  const scripts: string[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^(\s*)(?:- )?run:\s*(.*)$/.exec(lines[index] as string);
    if (match === null) continue;
    const indent = (match[1] as string).length;
    if ((match[2] as string).trim() !== '|' && (match[2] as string).trim() !== '>') {
      scripts.push(match[2] as string);
      continue;
    }
    const block: string[] = [];
    for (let next = index + 1; next < lines.length; next += 1) {
      const line = lines[next] as string;
      if (line.trim() !== '' && line.length - line.trimStart().length <= indent) break;
      block.push(line);
    }
    scripts.push(block.join('\n'));
  }
  return scripts;
}

describe('the workflows', () => {
  it('pin every action by commit, never by a tag or branch, and name the version beside the pin', async () => {
    for (const [name, text] of await workflows()) {
      const uses = [...text.matchAll(/^\s*(?:- )?uses:\s*(\S+)(.*)$/gm)];
      assert.ok(uses.length > 0, `${name} uses no actions`);
      for (const [, action, rest] of uses) assert.match(`${action}${rest}`, /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}\s+#\s*v\d/, `${name}: ${action} is not pinned by commit with its version noted`);
    }
  });

  it('never run on pull_request_target, always start with read-only permissions, and grant write only to a job', async () => {
    for (const [name, text] of await workflows()) {
      assert.doesNotMatch(text, /pull_request_target/, name);
      const top = /^permissions:\n((?:[ ]{2}.*\n)+)/m.exec(text);
      assert.ok(top !== null, `${name} sets no top-level permissions`);
      assert.doesNotMatch(top[1] as string, /write/, `${name} grants write to every job`);
      assert.doesNotMatch(text, /permissions:\s*write-all/, name);
    }
  });

  it('give every job a time limit, and every checkout no stored credentials', async () => {
    for (const [name, text] of await workflows()) {
      const jobs = text.slice(text.indexOf('\njobs:'));
      const headers = [...jobs.matchAll(/^ {2}([\w-]+):\n/gm)].length;
      assert.equal([...jobs.matchAll(/^\s+timeout-minutes:\s*\d+/gm)].length, headers, `${name}: every job needs timeout-minutes`);
      for (const checkout of text.matchAll(/actions\/checkout@[0-9a-f]{40}[^\n]*\n((?:\s+with:\n(?:\s+\S.*\n)+)?)/g)) assert.match(checkout[1] as string, /persist-credentials:\s*false/, `${name}: a checkout keeps its credentials`);
    }
  });

  it('keep secrets and untrusted text out of shell lines: they reach a step only through env, never inside run', async () => {
    for (const [name, text] of await workflows()) {
      for (const script of runScripts(text)) {
        assert.doesNotMatch(script, /\$\{\{\s*secrets\./, `${name}: a secret is expanded inside a run line`);
        assert.doesNotMatch(script, /\$\{\{\s*(github\.event\.|github\.head_ref|inputs\.)/, `${name}: untrusted input is expanded inside a run line`);
        assert.doesNotMatch(script, /echo[^\n]*\$\{?(RELEASE_SIGNING_KEY|NPM_TOKEN|GH_TOKEN)/, `${name}: a secret is echoed`);
        assert.doesNotMatch(script, /set -x|--debug/, `${name}: tracing would print secrets`);
      }
    }
  });

  it('build the six helpers under the names hn looks for, from the locked dependencies, and attach them to a draft', async () => {
    const text = (await workflows()).get('release.yml') as string;
    assert.ok(existsSync(join(ROOT, 'native', 'hn-sandbox', 'Cargo.lock')), '--locked needs Cargo.lock');
    for (const platform of HELPER_PLATFORMS) assert.match(text, new RegExp(`platform: ${platform},`), `${platform} is not built`);
    assert.equal([...text.matchAll(/platform: [a-z0-9-]+, os:/g)].length, HELPER_PLATFORMS.length, 'a platform is built that hn does not look for');
    assert.match(text, /cargo build --release --locked/);
    assert.match(text, /dist\/hn-sandbox-\$\{VERSION\}-\$\{\{ matrix\.platform \}\}\$\{\{ matrix\.exe \}\}/);
    assert.equal(helperAssetName('1.2.3', 'win32-x64'), 'hn-sandbox-1.2.3-win32-x64.exe');
    assert.match(text, /gh release create[^\n]*--draft/);
    assert.match(text, /--verify-tag/);
    assert.doesNotMatch(text, /npm publish/, "publishing to npm is the owner's step, not the workflow's");
    assert.match(text, /actions\/attest@/);
    assert.match(text, /trap 'rm -f "\$\{keyfile\}"' EXIT/, 'the key file must be removed');
    assert.match(text, /umask 077/);
  });

  it('run the installed-package smoke test on all three systems, and the docs build on a pull request', async () => {
    const all = await workflows();
    const release = all.get('release.yml') as string;
    for (const os of ['windows-latest', 'ubuntu-latest', 'macos-latest']) assert.match(release.slice(release.indexOf('smoke:')), new RegExp(os));
    assert.match(release, /hn setup --from dist/);
    const docs = all.get('docs.yml') as string;
    assert.match(docs, /pull_request:/);
    assert.match(docs, /if: github\.event_name != 'pull_request'/, 'a pull request must not deploy');
    const ci = all.get('ci.yml') as string;
    for (const os of ['windows-latest', 'ubuntu-latest', 'macos-latest']) assert.match(ci, new RegExp(os));
  });

  it('carry no plan, phase or decision text, so they can be published as they are', async () => {
    for (const [name, text] of await workflows()) assert.doesNotMatch(text, /\bphase \d|\bdecision \d|master plan|section \d+\.\d|\bslide \d/i, name);
  });
});
