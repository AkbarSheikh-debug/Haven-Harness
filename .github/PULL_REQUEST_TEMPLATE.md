## What this changes

<!-- One change per pull request. Link the issue if there is one. -->

## How it was tested

<!-- Commands you ran, and on which OS. New behaviour needs a new or updated test. -->

- [ ] `pnpm typecheck`
- [ ] `pnpm test`
- [ ] `pnpm test:sandbox` (only if `native/` changed)

## Checklist

- [ ] No process is started outside `packages/operations`
- [ ] No source file is over 400 lines
- [ ] Nothing bypasses the gate, and untrusted output keeps its origin
- [ ] A new defence has a named attack and a test titled with it
