import assert from 'node:assert/strict';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Gate, Jail, ModeRefusedError } from '@hn/security';
import { NonceSinks, PluginBackend, boxProfileName, bwrapArgs, findHelper, loadPluginConfigs, seatbeltProfile, verifyPluginBackend } from '@hn/operations';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));

/** A backend plugin: `host` runs every program on this machine, `refuse` runs nothing, `box` runs it in hn-sandbox's Windows box. */
const PLUGIN = `import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
const [mode, helper, root, name] = process.argv.slice(2);
const reply = (message) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...message }) + '\\n');
createInterface({ input: process.stdin }).on('line', (line) => {
  const message = JSON.parse(line);
  if (mode === 'refuse') return reply({ id: message.id, error: { code: -32000, message: 'not today' } });
  const { program, args, cwd, input } = message.params;
  const boxed = ['run', '--name', name, '--grant', root, '--cwd', cwd, '--env', 'SystemRoot=' + process.env.SystemRoot, '--env', 'LOCALAPPDATA=' + root + '\\\\home', '--', program, ...args];
  const child = mode === 'box' ? spawn(helper, boxed) : spawn(program, args, { cwd });
  const out = [], err = [];
  child.stdout.on('data', (chunk) => out.push(chunk));
  child.stderr.on('data', (chunk) => err.push(chunk));
  child.stdin.end(input);
  child.on('close', (code) => reply({ id: message.id, result: { code, stdout: Buffer.concat(out).toString('base64'), stderr: Buffer.concat(err).toString('base64') } }));
});
`;

describe('backend plugins', () => {
  let base = '';
  let pluginPath = '';
  let sinks: NonceSinks;
  before(async () => {
    base = await realpath(await mkdtemp(join(tmpdir(), 'hn-plugins-')));
    pluginPath = join(base, 'plugin.mjs');
    await writeFile(pluginPath, PLUGIN);
    sinks = await NonceSinks.open();
  });
  after(async () => {
    await sinks.close();
    await rm(base, { recursive: true, force: true, maxRetries: 10 });
  });

  const folders = async (name: string): Promise<{ scratch: string; outside: string }> => {
    const scratch = join(base, name, 'scratch');
    const outside = join(base, name, 'outside');
    await mkdir(scratch, { recursive: true });
    await mkdir(outside, { recursive: true });
    return { scratch, outside };
  };

  it('takes plugins only from the user file, by absolute path, with no unknown fields', async () => {
    const home = join(base, 'home');
    await mkdir(home, { recursive: true });
    assert.deepEqual(await loadPluginConfigs(home), []);
    await writeFile(join(home, 'backends.json'), JSON.stringify({ backends: [{ name: 'remote', command: 'plugin.exe' }] }));
    await assert.rejects(loadPluginConfigs(home), /absolute path/);
    await writeFile(join(home, 'backends.json'), JSON.stringify({ backends: [{ name: 'remote', command: process.execPath, tier: 5 }] }));
    await assert.rejects(loadPluginConfigs(home), /unknown field "tier"/);
    await writeFile(join(home, 'backends.json'), JSON.stringify({ backends: [{ name: 'remote', command: process.execPath, args: ['x'], claimedTier: 5 }] }));
    assert.deepEqual(await loadPluginConfigs(home), [{ name: 'remote', command: process.execPath, args: ['x'], claimedTier: 5 }]);
  });

  it('attack: plugin_backend_cannot_claim_tier (a plugin that says tier 5 but runs on this machine is tier 2)', { timeout: 120_000 }, async () => {
    const plugin = PluginBackend.start({ name: 'liar', command: process.execPath, args: [pluginPath, 'host'], claimedTier: 5 });
    try {
      const earned = await verifyPluginBackend(plugin, sinks, { ...(await folders('host')), interpreter: process.execPath });
      assert.equal(earned.tier, 2);
      assert.equal(earned.claimed, 5, 'the claim is recorded, so it is visible that it was not used');
      assert.ok(earned.hits.length > 0, 'the canary did not reach the host listener through an unconfined plugin');
    } finally {
      plugin.close();
    }
  });

  it('attack: plugin_backend_cannot_claim_tier (a plugin that runs nothing proves nothing, so it is tier 2)', { timeout: 60_000 }, async () => {
    const plugin = PluginBackend.start({ name: 'mute', command: process.execPath, args: [pluginPath, 'refuse'], claimedTier: 5 });
    try {
      const earned = await verifyPluginBackend(plugin, sinks, { ...(await folders('refuse')), interpreter: process.execPath });
      assert.equal(earned.tier, 2);
      assert.match(earned.evidence.join('\n'), /did not run the canary/);
    } finally {
      plugin.close();
    }
  });

  it('attack: plugin_backend_cannot_claim_tier (a plugin that really is boxed earns at most tier 3, asserted, and never yolo)', { timeout: 120_000, skip: process.platform === 'win32' ? false : 'the boxed plugin uses the Windows box' }, async () => {
    const helper = await findHelper({ env: {}, repoRoot });
    assert.ok(helper !== null);
    const root = join(base, 'boxed', 'root');
    const name = boxProfileName(`plugin-${process.pid}`);
    const scratch = join(root, 'work');
    const outside = join(base, 'boxed', 'outside');
    await mkdir(scratch, { recursive: true });
    await mkdir(join(root, 'home', 'Packages', name, 'AC', 'Temp'), { recursive: true });
    await mkdir(outside, { recursive: true });
    const plugin = PluginBackend.start({ name: 'boxed', command: process.execPath, args: [pluginPath, 'box', helper, root, name], claimedTier: 5 });
    try {
      const earned = await verifyPluginBackend(plugin, sinks, { scratch, outside, interpreter: process.execPath });
      assert.deepEqual(earned.evidence, []);
      assert.equal(earned.tier, 3, 'never the 5 it claimed');
      assert.equal(earned.asserted, true);
      assert.throws(
        () => new Gate({ mode: 'yolo', tier: earned.tier, assertedTier: earned.asserted, workdir: scratch, jail: new Jail({ root: scratch, realpath: async (path) => path }), audit: () => undefined }),
        ModeRefusedError,
      );
    } finally {
      plugin.close();
      const { spawnSync } = await import('node:child_process');
      spawnSync(helper, ['forget', '--name', name]);
    }
  });
});

describe('the Linux and macOS box command lines', () => {
  const paths = { copy: '/home/u/.hn/boxes/s/copy', home: '/home/u/.hn/boxes/s/home', tmp: '/home/u/.hn/boxes/s/tmp', cwd: '/home/u/.hn/boxes/s/copy' };

  it('bubblewrap unshares every namespace, clears the environment, binds only the copy, home and temp writable, and never the real home', () => {
    const args = bwrapArgs(paths, '/bin/bash', 'make test', { HN_PARENT_SESSION: 's' });
    for (const flag of ['--unshare-all', '--die-with-parent', '--new-session', '--clearenv']) assert.ok(args.includes(flag), flag);
    assert.ok(!args.includes('--share-net'));
    const writable = args.flatMap((arg, i) => (arg === '--bind' ? [args[i + 1]] : []));
    assert.deepEqual(writable, [paths.copy, paths.home, paths.tmp]);
    assert.ok(!args.some((arg) => arg === '/home' || arg === '/root' || arg === '/var/run/docker.sock'));
    assert.deepEqual(args.slice(-4), ['--', '/bin/bash', '-c', 'make test']);
    assert.throws(() => bwrapArgs({ ...paths, copy: 'relative' }, '/bin/bash', 'x', {}), /absolute/);
  });

  it('Seatbelt denies by default and denies all network; only the copy, home and temp are writable; a path cannot inject a rule', () => {
    const profile = seatbeltProfile(paths);
    assert.match(profile, /^\(version 1\)\n\(deny default\)/);
    assert.match(profile, /\(deny network\*\)/);
    assert.doesNotMatch(profile, /allow network/);
    assert.match(profile, /\(allow file-write\* \(subpath "\/home\/u\/\.hn\/boxes\/s\/copy"\)/);
    assert.throws(() => seatbeltProfile({ ...paths, copy: '/x") (allow network*) ("' }), /cannot be put/);
  });
});
