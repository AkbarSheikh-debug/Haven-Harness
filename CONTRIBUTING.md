# Contributing to Haven Harness

Thank you for helping. Bug reports, fixes, tests, docs, new tools and new sandbox backends are all welcome.

## Before you start

- **Small fixes** (typos, clear bugs, a missing test): open a pull request directly.
- **Bigger changes** (a new tool, a new door, a change to the gate or a sandbox): open an issue first so the design can
  be agreed before you spend time on it. The maintainer has the final say on what is merged.
- **Security problems:** never in a public issue. See [SECURITY.md](SECURITY.md).

## Setup

```bash
git clone https://github.com/<you>/haven-harness.git
cd haven-harness
corepack enable
pnpm install --frozen-lockfile
pnpm build:sandbox      # Rust stable; builds native/hn-sandbox
pnpm typecheck
pnpm test
```

Node 24.14 or newer. TypeScript runs directly through Node's type stripping, so there is no build step for the
packages: edit a `.ts` file and run it.

## The rules of the codebase

These are checked by tests, so a pull request that breaks one will fail CI.

1. **Only `packages/operations` starts processes.** Everything else asks it.
2. **No source file over 400 lines.** Split by responsibility when you get close.
3. **Nothing bypasses the gate.** A new tool declares its effect; the gate decides. A tool never asks a person on its
   own and never decides its own permission.
4. **Untrusted text keeps its origin.** Output that came from the web, an MCP server, a file in the workspace or a child
   agent must carry that origin.
5. **A new defence gets a named attack.** Add the attack's name to `surfaces/test/attacks.test.ts` and a test whose
   title contains that name.
6. **Programs by absolute path.** Never start a program by a bare name the project folder could shadow.

And by convention:

- Tests use the built-in `node:test` runner and the fakes in `packages/testkit`. Prefer a real process to a mock.
- No new runtime dependency without an issue first. The project keeps very few on purpose.
- Comments say *why*, not what. Error messages tell the user what to do next.

## Pull requests

1. Fork, then branch from `main` (`fix/short-name` or `feat/short-name`).
2. Keep each pull request to one change. Add or update tests with it.
3. Run `pnpm typecheck` and `pnpm test` (and `pnpm test:sandbox` if you touched the Rust crate).
4. Write commit messages in the imperative ("Refuse links in the import", not "Refused links").
5. Fill in the pull request template, including what you tested and on which OS.

## License of contributions

Haven Harness is licensed under the Apache License 2.0. Under section 5 of that license, anything you submit for
inclusion is licensed under the same terms, with no extra agreement to sign. Only submit work you have the right to
submit.

## Where help is especially welcome

- Running the test suite on Linux and macOS and reporting what breaks.
- Language server configurations and repo-map grammars for more languages.
- Benchmark tasks for `packages/evals`.
- Documentation and examples.
