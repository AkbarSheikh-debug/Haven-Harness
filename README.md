# Haven Harness

**An open-source coding agent built around one idea: an agent should be powerful *and* provably contained.**

Haven Harness (`hn`) is a terminal coding agent that reads, writes and runs code for you, delegates to a crew of
sub-agents, remembers what matters between sessions, and drives whole fleets of repositories. Every action it takes
passes a permission gate. Every command it runs can be put in a sandbox that is **verified from outside**, not trusted
because it says so. Every piece of text it did not get from you is tracked as untrusted, all the way to the gate.

> **Status: early, and moving fast.** The core is built and heavily tested (1,300+ tests, 63 named attacks with a
> test each), but interfaces will still change. Windows is the most-tested platform today. Expect rough edges, and
> please report them.

---

## Why another coding agent?

Most agents treat safety as a prompt: "please don't delete my home folder". Haven Harness treats it as engineering.

| | What it means here |
|---|---|
| **A gate on every action** | Each tool call is classified by what it can do (observe, reversible, execution, external, irreversible) and decided by your mode. Nothing runs around the gate, including sub-agents, workflows and scheduled runs. |
| **Sandboxes that are checked, not trusted** | Before a sandbox counts, a canary runs inside it and tries to reach your machine on every address, read a secret outside it, and leave a process behind, while listeners on the host watch. Only what the *host* saw decides. |
| **Untrusted text stays untrusted** | Web pages, MCP servers, repository files and child agents are tagged by origin. A session that has read untrusted text loses the right to act unattended until a person approves. |
| **Your files come back through review** | A sandboxed agent works on a copy. Its changes come back through an import that holds `.git` internals, CI workflows, hooks and links for a person. |
| **A tamper-evident log** | Every session is an append-only log with a chained HMAC. A forged or edited log loads read-only, with no approvals. |
| **A super agent, not just an agent** | A crew of sub-agents, agent teams with a merge queue, scripted workflows, fleets of repositories, loops and schedules: all under the same gate. |

---

## What it can do today

**Work on code**
- Read, write, edit and patch files inside the project, through a path jail that refuses links, hard links and secrets.
- Run shell commands, search with ripgrep, and fetch web pages through an egress policy that blocks private networks,
  cloud metadata and the machine's own addresses.
- Understand a codebase: a **repo map** ranked by PageRank over real tree-sitter symbols, and **LSP** (definition,
  references, hover, diagnostics after every edit) from language servers you configure.
- Look at the web in a **headless browser** whose every request goes through a checking proxy.
- Plan mode, goals and a todo list that survive context compaction; checkpoints, `/rewind` and `/rollback`.

**Work as a super agent**
- **Sub-agents:** a built-in crew (`scout`, `planner`, `worker`, `reviewer`) with narrowed rights; children can never
  hold more than their parent, and parallel writers each get a private git clone.
- **Agent teams** (experimental): a Lead and members sharing a task graph, with a merge queue for their work.
- **Workflows:** short scripts that orchestrate agents and tools (`agent`, `parallel`, `pipeline`), journaled so a
  crashed run resumes.
- **Fleets:** one job file, many repositories, a shared rate limit, results in order, and resume after a crash.
- **Ralph loops and schedules:** repeat a task until a check passes; run prompts on a schedule with the OS scheduler.
- **Steering:** `hn steer` and `hn stop` reach a running session from another terminal.

**Remember**
- `MEMORY.md`, `USER.md` and daily notes per project, recalled when relevant, written only when you ask or approve.
- Search over past sessions; background review and "dream" sweeps that propose, never write, long-term memory.
- Learned skills that are linted, scanned and quarantined until a person accepts them.

**Meet you where you work**
- A line REPL, a full-screen **TUI** with an approvals inbox, and headless `hn -p` for scripts and CI.
- **ACP** for editors that speak the Agent Client Protocol, a JSON-RPC door, and `hn serve`, a loopback web UI hardened
  against DNS rebinding and CSRF.

**Models**
- Anthropic, any OpenAI-compatible endpoint, and local models through **Ollama** (`--model ollama/qwen3:14b`).

---

## Sandboxes

| Tier | What | Where |
|---|---|---|
| **Windows native box** | An AppContainer with no capabilities, low integrity, in a Job Object that kills everything when it closes; built in Rust (`native/hn-sandbox`). | Windows 10/11 |
| **Container** | Docker with every confinement asked for, a pinned image, and a quota. Project images come from reviewed recipes (`.hn/sandbox.json`, a devcontainer or a Dockerfile) built with no network. | Any OS with Docker |
| **Plugins** | Your own backend, spoken to over JSON-RPC. Whatever tier it claims is ignored; it earns one only by passing the canary. | Any |
| **None** | The default on a fresh install. The gate still applies, and the banner says **NOT SANDBOXED**. | Any |

`yolo` mode (no prompts) is refused unless the session is in a verified sandbox.

---

## Quick start

Requirements: **Node 24.14+**, **pnpm** (via `corepack enable`), and **Rust** (stable) for the native helper.

```bash
git clone https://github.com/AkbarSheikh-debug/haven-harness.git
cd haven-harness
corepack enable
pnpm install --frozen-lockfile
pnpm build:sandbox          # builds native/hn-sandbox (the safe file helper and the Windows box)
node packages/surfaces/bin/hn.mjs doctor
```

Give it a model:

```bash
# Anthropic
export ANTHROPIC_API_KEY=...            # PowerShell: $env:ANTHROPIC_API_KEY = "..."
node packages/surfaces/bin/hn.mjs

# A local model through Ollama
node packages/surfaces/bin/hn.mjs --model ollama/qwen3:14b

# Any OpenAI-compatible server
node packages/surfaces/bin/hn.mjs --model <name> --base-url http://localhost:8000/v1
```

Tip: make an alias, e.g. `alias hn="node /path/to/haven-harness/packages/surfaces/bin/hn.mjs"`.

### Common commands

```bash
hn                                   # interactive session in the current folder
hn tui                               # full-screen session with an approvals inbox
hn -p "fix the failing test"         # one headless turn, for scripts and CI
hn -p "..." --sandbox native --mode yolo   # unattended, in a verified Windows box
hn --resume <session> | --continue   # pick a session back up
hn doctor                            # check the install, the sandbox and Docker
hn fleet jobs.json --workers 4       # many repositories, one job file
hn ralph "make the tests pass" --check "pnpm test" --max 10
hn schedule add --name nightly --rrule "FREQ=DAILY" "summarise yesterday's commits"
hn steer <session> "focus on the parser first"
hn serve | hn acp | hn rpc           # web UI, editors, JSON-RPC
hn sandbox show | propose | build    # project image recipes
hn prepare --image <name>@sha256:... # install dependencies through a locked-down proxy
```

**Modes:** `read-only`, `plan`, `safe`, `accept-edits`, `smart`, `dont-ask` (with `--allow`), and `yolo` (verified
sandbox only). In a session, try `/agents`, `/compact`, `/checkpoints`, `/rewind`, `/memory`, `/handoff`, `/learn`.

---

## Project layout

```
packages/
  core          events, errors and shared types
  session       the append-only, HMAC-chained session log
  provider      Anthropic, OpenAI-compatible and Ollama adapters, retries, prices
  context       budgets, compaction, skills, instructions
  loop          the agent loop: turns, tools, compaction, memory hooks
  security      the gate, modes, taint, path jail, egress policy, redaction, command parsing
  operations    the only package that starts processes: sandboxes, git, LSP, browser, proxies
  tools         the tools the model sees
  memory        notes, recall, dream sweeps, learned skills
  delegate      sub-agents, roles, grants and the child channel
  orchestrate   fleets, workflows, teams, ralph, schedules, the supervisor
  surfaces      the CLI and every door: REPL, TUI, -p, RPC, ACP, serve
  config        defaults
  testkit       fake models and helpers for tests
  evals         benchmark tasks
native/hn-sandbox   Rust: safe file access, keychain, and the Windows native box
```

See [docs/architecture.md](docs/architecture.md) for how the pieces fit together.

---

## Development

```bash
pnpm typecheck     # tsc --noEmit
pnpm test          # the full suite (about 4 to 5 minutes)
pnpm test:sandbox  # the Rust helper's tests
node --disable-proto=throw --test packages/security/test/gate.test.ts   # one file
```

Tests that need Docker or a live model skip themselves; set `HN_LIVE_OLLAMA=1` with Ollama running to include the
live-model tests.

## Contributing

Contributions are welcome: bug reports, fixes, new tools, new sandbox backends, docs and tests. Start with
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through [SECURITY.md](SECURITY.md), not public issues.

## License

Copyright 2026 Akbar Sheikh. Licensed under the [Apache License, Version 2.0](LICENSE): use it, fork it, change it and
ship it, commercially or not, keeping the license and the [NOTICE](NOTICE).
