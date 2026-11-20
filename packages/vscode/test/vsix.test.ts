import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { before, describe, it } from 'node:test';
import { inflateRawSync } from 'node:zlib';
import { findCli, packVsix, requireVsCode, runCli, runHost, skipWithoutVsCode, vscodeExe, withProject } from './host-driver.ts';

/** Reads a zip's entries back, to check the packed file is what was written. */
function unzip(bytes: Buffer): Map<string, Buffer> {
  const entries = new Map<string, Buffer>();
  const end = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = bytes.readUInt16LE(end + 10);
  let at = bytes.readUInt32LE(end + 16);
  for (let n = 0; n < count; n += 1) {
    const size = bytes.readUInt32LE(at + 20);
    const nameLength = bytes.readUInt16LE(at + 28);
    const offset = bytes.readUInt32LE(at + 42);
    const name = bytes.subarray(at + 46, at + 46 + nameLength).toString('utf8');
    const start = offset + 30 + bytes.readUInt16LE(offset + 26) + bytes.readUInt16LE(offset + 28);
    entries.set(name, inflateRawSync(bytes.subarray(start, start + size)));
    at += 46 + nameLength;
  }
  return entries;
}

describe('the packer and the editor tests share one folder safely', () => {
  it('compiles into a folder of its own, never the dist the editor tests load', async () => {
    // Found on CI: the packer rebuilt `dist` while a real VS Code was loading it, and the host test could not find a file.
    // The test files run side by side, so exactly one thing may build `dist`.
    const source = await readFile(new URL('../../../scripts/pack-vsix.ts', import.meta.url), 'utf8');
    const calls = source.match(/buildExtension\([^)]*\)/g) ?? [];
    assert.deepEqual(calls, ['buildExtension(scratch)'], `the packer builds the shared dist: ${calls.join(', ')}`);
  });
});

describe('the packed .vsix', () => {
  it('is a zip that reads back, and two packs of the same source are byte-identical', { timeout: 120_000 }, async () => {
    const dir = join(process.env['TEMP'] ?? process.env['TMPDIR'] ?? '/tmp', `hn-vsix-${process.pid}`);
    await mkdir(dir, { recursive: true });
    const first = packVsix('0.1.0', join(dir, 'a'));
    const second = packVsix('0.1.0', join(dir, 'b'));
    assert.equal(first.sha256, second.sha256, 'two packs of one source differ');
    const bytes = await readFile(first.path);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), first.sha256);
    const entries = unzip(bytes);
    assert.deepEqual([...entries.keys()].sort(), [...first.files]);
    const manifest = JSON.parse(entries.get('extension/package.json')?.toString('utf8') ?? '{}') as Record<string, unknown>;
    assert.equal(manifest['name'], 'haven-harness');
    assert.equal(manifest['version'], '0.1.0');
    assert.equal(manifest['private'], undefined);
    assert.equal(manifest['devDependencies'], undefined, 'the workspace dev dependencies went into the package');
    assert.equal(manifest['dependencies'], undefined, 'the extension has a runtime dependency');
    assert.deepEqual(manifest['activationEvents'], [], 'the extension starts by itself');
    assert.deepEqual((manifest['capabilities'] as { untrustedWorkspaces: { supported: boolean } }).untrustedWorkspaces.supported, false);
    for (const [name, data] of entries) {
      if (name.startsWith('extension/dist/')) assert.ok(!/from ['"](?!\.\/|node:|vscode['"])/.test(data.toString('utf8')), `${name} imports something that is not shipped`);
    }
  });
});

describe('the packed extension, installed into a real VS Code', { skip: skipWithoutVsCode }, () => {
  let vsix = '';
  before(async () => {
    assert.ok(vscodeExe !== null || !requireVsCode, 'HN_REQUIRE_VSCODE=1 but no VS Code was found; set HN_VSCODE.');
    const dir = join(process.env['TEMP'] ?? process.env['TMPDIR'] ?? '/tmp', `hn-vsix-install-${process.pid}`);
    vsix = packVsix('0.1.0', dir).path;
  });

  const install = async (top: string): Promise<string> => {
    const exe = vscodeExe as string;
    const extensions = join(top, 'installed-extensions');
    const run = runCli(exe, await findCli(exe), ['--install-extension', vsix, '--extensions-dir', extensions, '--user-data-dir', join(top, 'user-data')]);
    assert.equal(run.status, 0, run.output);
    assert.match(run.output, /successfully installed/i);
    const listed = runCli(exe, await findCli(exe), ['--list-extensions', '--show-versions', '--extensions-dir', extensions, '--user-data-dir', join(top, 'user-data')]);
    assert.match(listed.output, /haven-harness\.haven-harness@0\.1\.0/);
    return extensions;
  };

  it('attack: editor_folder_settings_cannot_choose_binary_or_model_server - installs with VS Code\'s own installer, starts only on a command, and takes no setting from a folder', { timeout: 400_000 }, async () => {
    await withProject(async (top, project, url) => {
      const extensionsDir = await install(top);
      const outcome = await runHost({ suite: 'installed.mjs', trusted: true, extensionsDir, extra: { extensionId: 'haven-harness.haven-harness', version: '0.1.0' } }, url, top, project);
      assert.equal(outcome.ok, true, `${outcome.error ?? ''}\n${outcome.output.slice(-2000)}`);
    });
  });

  it('attack: editor_installed_extension_not_run_in_untrusted_folder - is not run at all in a folder that was not trusted', { timeout: 400_000 }, async () => {
    await withProject(async (top, project, url, requests) => {
      const extensionsDir = await install(top);
      const outcome = await runHost({ suite: 'installed-untrusted.mjs', trusted: false, extensionsDir, extra: { extensionId: 'haven-harness.haven-harness' } }, url, top, project);
      assert.equal(outcome.ok, true, `${outcome.error ?? ''}\n${outcome.output.slice(-2000)}`);
      assert.equal(requests(), 0);
    });
  });
});
