# Releases: checking and updating

Most people install with `npm install -g haven-harness` ([installing](install.md)). Besides the npm package, each release
has six `hn-sandbox` helpers with a signed manifest (`hn-sandbox-manifest-<version>.json` and its `.sig.json`),
`SHA256SUMS`, and a build provenance attestation from the workflow that made them. The rest of this page is about the
per-platform archives, which are what `hn update` installs.

Each release archive is one per platform (for example `haven-harness-0.8.0-win32-x64.tgz`) with two files beside it:

| File | What it is |
|---|---|
| `….tgz` | The release: `bin/hn.mjs`, `bin/hn-sandbox[.exe]`, the compiled code and every runtime dependency under `lib/node_modules`, `RELEASE-KEY.json`, `sbom.cdx.json`, and `manifest.json` (every file with its SHA-256) |
| `….sig.json` | An ed25519 signature over the manifest |
| `….sbom.cdx.json` | A CycloneDX 1.5 software bill of materials: every vendored package with a hash of exactly what shipped |

**Reproducible:** two builds of one commit are byte-identical (times come from the commit), so anyone can rebuild a
release and compare.

## Installing a release for the first time

The first install is the one moment you must trust something from outside: the public release key. Check it against
the key published in the repository's README or release notes before you use it.

## Updating

```bash
hn update haven-harness-0.9.0-win32-x64.tgz          # looks for the .sig.json beside it
hn update https://example.com/haven-harness-0.9.0-win32-x64.tgz --sig https://example.com/haven-harness-0.9.0-win32-x64.sig.json
```

An update is installed only when **all** of these hold:

- the signature checks against the key pinned in the release you are running (never a key the new archive brings);
- the archive holds exactly the files its manifest lists, each with the listed hash, and only regular files with plain
  relative paths (no links, no `..`, no absolute paths);
- it is built for this platform;
- its version is newer than any version ever installed on this machine. That record is kept with an HMAC under this
  machine's key, so deleting or editing it does not open the way to a downgrade.

Updates are only ever started by a person typing `hn update`. It is refused inside an hn session, and nothing in a
project's files can name an update source.

## Building a release (maintainers)

```bash
node --disable-proto=throw scripts/release.ts --keygen ./release-keys        # once; keep release-key.pem offline
pnpm build:sandbox
node --disable-proto=throw scripts/check-release-age.ts                       # every dependency pinned and at least 7 days old
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) node --disable-proto=throw scripts/release.ts \
  --version 0.9.0 --key ./release-keys/release-key.pem --key-id <id> --out ./dist
```

The npm package and the six sandbox helpers are built by the release workflow (`.github/workflows/release.yml`) from a
`vX.Y.Z` tag, or by hand:

```bash
# the helpers: build on each platform (or cross-build), name them hn-sandbox-<version>-<platform>[.exe], put them in ./helpers
cargo build --release --locked --manifest-path native/hn-sandbox/Cargo.toml
node --disable-proto=throw scripts/sandbox-manifest.ts --version 0.9.0 --binaries ./helpers --key ./release-keys/release-key.pem --key-id <id>
node --disable-proto=throw scripts/pack-npm.ts --version 0.9.0 --key ./release-keys/release-key.pem --key-id <id> --out ./dist
```

The workflow signs only when the release key is given to it as a secret of a protected `release` environment, and it
creates a **draft** release: nothing is published until its owner publishes it. Without the key it builds the six
helpers and says nothing was signed. The workflow's build provenance is a GitHub attestation; publishing the npm
package with `npm publish --provenance` from CI adds npm's own provenance statement.
