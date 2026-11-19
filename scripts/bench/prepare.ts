// Builds what a benchmark run installs in each task container: hn's npm package, and the sandbox
// helper for Linux, signed together with a key made for the benchmark. Nothing here is the release key and nothing
// needs a release to exist: the package pins the benchmark key, and `hn setup --from` checks the helper against it
// exactly as it would a released one. A score published from this build says so.
//
//   node --disable-proto=throw scripts/bench/prepare.ts --out <folder> [--arch x64|arm64] [--dry-run]
//
// Output, under --out: `package/haven-harness-<version>.tgz`, `helpers-signed/` (the helper, its signed manifest and
// signature) and `bench-key.pem` (private, kept so the same key signs a later rebuild). It needs Docker, to build the
// helper for Linux in a Rust image pinned by digest.

import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { promisify } from 'node:util';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('../../', import.meta.url));

/** The image the helper is built in, by digest: a tag can move, and a build must be the same build. */
export const RUST_IMAGE = 'rust@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37';
export const KEY_ID = 'bench';
const ARCHES = { x64: 'linux-x64', arm64: 'linux-arm64' } as const;

export interface Step {
  readonly what: string;
  readonly command: string;
  readonly args: readonly string[];
}

export interface Plan {
  readonly version: string;
  readonly platform: string;
  readonly steps: readonly Step[];
  readonly package: string;
  readonly helpers: string;
}

/** The commands, in order, without running any. A dry run prints this, and the tests check it. */
export function plan(options: { out: string; version: string; arch: keyof typeof ARCHES; root?: string }): Plan {
  const root = options.root ?? ROOT;
  const out = resolve(options.out);
  const platform = ARCHES[options.arch];
  const key = join(out, 'bench-key.pem');
  const rawHelpers = join(out, 'helpers-raw');
  const signed = join(out, 'helpers-signed');
  const pkg = join(out, 'package');
  const helperName = `hn-sandbox-${options.version}-${platform}`;
  const node = process.execPath;
  return {
    version: options.version,
    platform,
    package: join(pkg, `haven-harness-${options.version}.tgz`),
    helpers: signed,
    steps: [
      { what: 'pack the npm package, pinning the benchmark key', command: node, args: ['--disable-proto=throw', join(root, 'scripts', 'pack-npm.ts'), '--version', options.version, '--key', key, '--key-id', KEY_ID, '--out', pkg] },
      {
        what: `build hn-sandbox for ${platform} in a pinned Rust image`,
        command: 'docker',
        args: ['run', '--rm', '-v', `${join(root, 'native', 'hn-sandbox')}:/src:ro`, '-v', `${rawHelpers}:/out`, RUST_IMAGE, 'sh', '-c', `set -e; cp -r /src /build && cd /build && rm -rf target && CARGO_TARGET_DIR=/tmp/t cargo build --release --locked && cp /tmp/t/release/hn-sandbox /out/${helperName}`],
      },
      { what: 'hash and sign the helper manifest with the benchmark key', command: node, args: ['--disable-proto=throw', join(root, 'scripts', 'sandbox-manifest.ts'), '--version', options.version, '--binaries', rawHelpers, '--key', key, '--key-id', KEY_ID, '--out', signed, '--allow-partial'] },
    ],
  };
}

async function main(): Promise<number> {
  const { values } = parseArgs({ options: { out: { type: 'string' }, arch: { type: 'string', default: 'x64' }, 'dry-run': { type: 'boolean', default: false }, json: { type: 'boolean', default: false } } });
  if (values.out === undefined) {
    process.stderr.write('Use: node --disable-proto=throw scripts/bench/prepare.ts --out <folder> [--arch x64|arm64] [--dry-run]\n');
    return 2;
  }
  if (values.arch !== 'x64' && values.arch !== 'arm64') {
    process.stderr.write('--arch is x64 or arm64.\n');
    return 2;
  }
  const version = (JSON.parse(await readFile(join(ROOT, 'package.json'), 'utf8')) as { version: string }).version;
  const built = plan({ out: values.out, version, arch: values.arch });
  if (values['dry-run']) {
    if (values.json) {
      process.stdout.write(`${JSON.stringify({ ...built, rustImage: RUST_IMAGE, keyId: KEY_ID })}\n`);
      return 0;
    }
    for (const step of built.steps) process.stdout.write(`${step.what}:\n  ${[step.command, ...step.args].join(' ')}\n`);
    return 0;
  }
  const out = resolve(values.out);
  await mkdir(join(out, 'helpers-raw'), { recursive: true });
  const key = join(out, 'bench-key.pem');
  if (!existsSync(key)) {
    // Made here, kept here, never the release key. Whoever has this folder can sign a helper this package will accept.
    await writeFile(key, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    await chmod(key, 0o600).catch(() => undefined);
    process.stdout.write(`Made a benchmark signing key at ${key}. It is not the release key; keep it with this folder.\n`);
  }
  for (const step of built.steps) {
    process.stdout.write(`${step.what}...\n`);
    // SOURCE_DATE_EPOCH makes the package byte-identical for the same commit, like a release build.
    await run(step.command, [...step.args], { maxBuffer: 1 << 26, timeout: 900_000, env: { ...process.env, SOURCE_DATE_EPOCH: process.env['SOURCE_DATE_EPOCH'] ?? '1700000000' } }).catch((error: { stderr?: string; message: string }) => {
      throw new Error(`${step.what} failed: ${(error.stderr ?? error.message).slice(-800)}`);
    });
  }
  await copyFile(join(out, 'helpers-raw', `hn-sandbox-${built.version}-${built.platform}`), join(built.helpers, `hn-sandbox-${built.version}-${built.platform}`));
  process.stdout.write(`\nReady.\n  package: ${built.package}\n  helpers: ${built.helpers}\nThen: python scripts/bench/run_bench.py --hn-package ${built.package} --hn-helpers ${built.helpers} ...\n`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().then(
    (code) => process.exit(code),
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exit(1);
    },
  );
}
