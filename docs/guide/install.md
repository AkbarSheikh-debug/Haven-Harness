# Installing Haven Harness

You need **Node 24.14 or newer**. You do not need pnpm, Rust or a compiler.

```bash
npm install -g haven-harness
hn doctor
```

`npx haven-harness doctor` runs it without installing. The package installs two commands, `hn` and `haven-harness`,
and works on Windows, Linux and macOS, on x64 and arm64.

## What the package does and does not do

- **It runs no install scripts.** Nothing executes when you install it. A test fails the build if the package, or
  anything it carries, declares a `preinstall`, `install` or `postinstall` script or a native build step, and the
  install is run with `--foreground-scripts` in the test suite to show that none ran.
- **It carries its own dependencies.** The compiled code, its pure-JavaScript dependencies and ripgrep's binaries for
  the six supported platforms are bundled, so installing does not pick up newer, unreviewed versions of them.
  The SBOM (`sbom.cdx.json`, inside the package and beside each release) lists every one with a hash.
- **Its files are signed.** `manifest.json` lists every file with its SHA-256 and `manifest.sig.json` is an ed25519
  signature over it, made with the release key. `hn doctor` checks the signature and every hash and reports
  **release integrity**. Because the key travels with the package, this shows the files are what was signed; it does
  not by itself show who published the package. For that, npm's provenance statement on the release names the build
  that made it, and the key is also published in the release notes.
- **It is reproducible.** Two builds of one commit give byte-identical packages.

## The sandbox helper

File access and the Windows box need a small native program, `hn-sandbox`. It is not in the package. The first time a
session needs it, `hn` downloads the one for your platform from the release (about a megabyte or two), and prints what
it fetches and from where:

```
hn: fetching hn-sandbox 0.9.0 for linux-x64 from https://github.com (first use; the signature and SHA-256 are checked before it is kept or run).
```

You can do it ahead of time with `hn setup`. What is checked, in order:

1. The release's `hn-sandbox-manifest-<version>.json` and its signature are fetched first, and nothing else is asked
   for until they verify against the key pinned in your installed package.
2. The manifest must be for **exactly the version you run**, so an old, genuinely signed manifest cannot be replayed to
   hand you an older helper.
3. The manifest lists your platform with a size and a SHA-256. The download is read against that size and never
   larger, and its hash must match before it is written under its final name.
4. Every time the helper is about to be used, it is hashed again and compared with the signed manifest stored beside it.
   A helper that was swapped or edited after the download is refused, and a fresh one is fetched.

A helper that fails any check is never run. Only `https` addresses are followed (and `http` to your own machine, for a
local mirror), every redirect is checked again, and nothing is fetched at all if you set `HN_NO_DOWNLOAD=1`.

### Offline, mirrors and air gaps

```bash
hn setup --from ./release-files     # a folder with hn-sandbox-manifest-<version>.json, its .sig.json and your platform's helper
export HN_RELEASE_URL=https://mirror.example.com/haven-harness/v0.9.0   # fetch from your own mirror instead
```

A mirror cannot change what is trusted: the same signature and hash checks decide, whoever served the bytes.

## What can go wrong

| You see | Meaning |
|---|---|
| `hn-sandbox … is not installed yet` in `hn doctor` | Normal before first use. Run `hn setup`, or just start a session. |
| `…could not be installed, and nothing was run: … does not match its signed SHA-256` | The download was altered or damaged. Nothing was kept. Try again, or install from a trusted copy with `hn setup --from`. |
| `…is signed with key "…", which this installation does not trust` | The release was signed by a key your package does not pin. Do not use it. |
| `release integrity … was changed` in `hn doctor` | A file of the installed package differs from what was signed. Reinstall: `npm install -g haven-harness`. |
| `This release has no hn-sandbox for <platform>` | Your platform is not one of the six: Windows, Linux or macOS on x64 or arm64. |

## Building from source

See the [README](../../README.md#quick-start). A source checkout builds its own helper with `pnpm build:sandbox` and never
downloads one.

## Checking and updating a release

See [releases](releases.md).
