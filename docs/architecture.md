# Architecture

Haven Harness is a pnpm monorepo of TypeScript packages that run directly on Node 24 (type stripping, no build step),
plus one Rust crate for what Node cannot do safely on its own.

## The shape of a turn

```
 you ──> a door (REPL, TUI, -p, RPC, ACP, serve)          packages/surfaces
            │
            ▼
        the session ──> append-only log, HMAC-chained      packages/session
            │
            ▼
        the agent loop                                    packages/loop
            │   ├─ the model, streamed                     packages/provider
            │   ├─ the context budget and compaction       packages/context
            │   └─ memory recall and flush                 packages/memory
            ▼
        a tool call ──> THE GATE                          packages/security
            │             mode × effect × taint × rules
            │             allow │ ask a person │ deny
            ▼
        the tool                                          packages/tools
            │
            ▼
        operations: the only code that starts processes   packages/operations
            ├─ the host (no sandbox: the gate still applies)
            ├─ a container (Docker)
            ├─ the Windows native box (native/hn-sandbox)
            └─ a backend plugin
            │
            ▼
        the result, tagged with its origin, goes back into the log and the model's context
```

## The rules every package keeps

- **The log is the truth.** Everything a session knows is a projection of its log: the transcript, the mode, the goal,
  the todo list, approvals and taint. A crash loses at most the step in flight, and a resume rebuilds the rest.
- **One gate.** Every tool call, from the main agent, a child, a workflow, a schedule or a fleet job, is decided by
  `Gate` in `packages/security`. A tool cannot decide its own permission.
- **Effects, not tool names.** The gate reasons about what a call can do: `observe`, `reversible`, `execution`,
  `external` or `irreversible`. Shell commands are parsed (tree-sitter) to find their real effect.
- **Origins travel.** Text from the web, MCP servers, workspace files and child agents carries its origin. Once a
  session holds untrusted text, it is tainted: unattended actions that could leak or change things need a person.
- **Only `operations` starts processes.** A test (`operations/test/structure.test.ts`) fails if any other package
  spawns one. Programs are found by absolute path, never by a name the project could shadow.
- **Sandboxes earn their tier.** A backend is trusted only after the verifier's canary runs inside it and the host sees
  nothing get out. A backend's own report never counts.
- **Small files.** No source file is over 400 lines (`loop/test/loop.test.ts` checks).

## Packages

| Package | Responsibility |
|---|---|
| `core` | Event catalog, event validation, error types, shared helpers. |
| `session` | The log: zstd frames, chained HMAC, single-writer lock, projection, crash repair, fork. |
| `provider` | Model adapters (Anthropic, OpenAI-compatible, Ollama), capabilities, retries, prices, key handling. |
| `context` | Token budgets, compaction, plan state (goal and todos), skills, project instructions. |
| `loop` | The agent: turns, iterations, parallel tool calls, compaction triggers, memory hooks. |
| `security` | The gate and modes, taint, approval cards, the path jail, egress policy, secret redaction, the command parser. |
| `operations` | Processes and boundaries: host exec, containers, the native box and its verifier, git, checkpoints, LSP, the browser and its proxy, `prepare`. |
| `tools` | Tool definitions the model sees: files, shell, search, web, browser, repo map, LSP, memory, planning, MCP. |
| `memory` | Notes and long-term memory files, recall, session search, background review, dream sweeps, learned skills. |
| `delegate` | Sub-agents: roles, grants that only narrow, the child channel, approvals relayed to the parent's person. |
| `orchestrate` | Fleets, workflows and `run_code`, agent teams and their task graph, ralph loops, schedules, the supervisor. |
| `surfaces` | The `hn` CLI and every door: REPL, TUI, headless, JSON-RPC, ACP, `hn serve`, plus sandbox and recipe commands. |
| `config` | Defaults. |
| `testkit` | A scripted fake model, a fake OpenAI-compatible server, seeded randomness, temp folders. |
| `evals` | Benchmark tasks and their runner. |
| `native/hn-sandbox` | Rust helper: path-safe file access, the OS keychain, and the Windows AppContainer box. |

## The Windows native box

`hn-sandbox run` starts a program in a per-session AppContainer profile with **no capabilities** (so no network), at
low integrity, inside a Job Object that kills every process in the box when it closes and caps processes and memory.
The box can write only its own folder. The helper reads the real token and job back from Windows and reports them.

The verifier (`operations/src/native-verifier.ts`) then decides from the outside: host listeners on every address of
the machine must see no connection or packet; a nonce file outside the box must stay unread; no file may appear outside
the box; a proof file only the canary can produce must appear inside it; and a background process the canary started
must stop when the box ends.

## Testing philosophy

- Real processes over mocks: doors are tested by starting `hn` and talking to it; the browser test drives a real
  headless Chrome; the box test runs a real AppContainer.
- A fake model (`testkit`) scripts the agent, so behaviour is deterministic and free.
- Every named attack has a test with the attack's name in its title, and `surfaces/test/attacks.test.ts` fails if one
  is missing.
