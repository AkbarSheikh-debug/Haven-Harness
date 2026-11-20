# The security model

Haven Harness assumes the model can be talked into anything. Prompts shape what it tries; code decides what happens.
This page says what each layer does, and, as plainly, what it does **not** do.

## The rules everything follows

1. **The model being convinced is never enough for an action to happen.** Every tool call passes one gate, with no
   way around it: not through sub-agents, workflows, `run_code`, schedules or MCP.
2. **Fail closed.** No approver, an error in a check, or an unknown value all mean no.
3. **Lower layers only narrow.** A project, a role, a child agent or a later policy layer can take rights away, never add them.
4. **The log is the truth,** HMAC-chained. A forged or edited log loads read-only, with no approvals, mode or memory rights.
5. **Secrets never reach the model or the log.** Keys are held by the harness process (or, in team mode, by the broker),
   redacted from every output, and never put in a child's environment.
6. **Untrusted text is tracked by origin** (web, MCP, workspace files, child agents, events). Once a session holds
   untrusted text, can reach the outside, and holds something private, it loses the right to act unseen: a person
   decides each outward step (the Rule of Two).
7. **Nothing becomes long-term memory without a person's yes.**
8. **Below a verified sandbox there is no boundary, and the product says so.** The gate slows mistakes down; it does
   not stop a determined attacker running code on your machine.

## Tiers: what each covers and does not

A tier counts only after the outside-in check passes on this machine: a canary inside the sandbox tries to reach the
host on every address, read a file outside, write one, and leave a process running, while the host watches. [What ran on which OS](sandbox-verified.md) is listed with where it ran.

| Tier | Covers | Does **not** cover |
|---|---|---|
| **None** (fresh install) | The gate, the path jail, secret masking, egress rules for the harness's own web tools, taint, approvals | Anything a shell command does: a command you approve runs with your full rights, network included. `yolo` is refused. |
| **Container** (Docker, pinned image, network off) | Process, file and network isolation from the host; the project is a copy that comes back through review | Kernel or Docker escapes; a Docker Desktop older than 4.44.3 (`hn doctor` refuses it); anything you mount by hand |
| **Windows native box** (AppContainer, no capabilities, Job Object) | No network to any host address, no reads of your files outside the box, no process survives the box, changes come back through review | Timing channels; RPC and named pipes to Windows services an AppContainer may still reach; reading Windows system folders (open to every app); programs whose folder denies AppContainers cannot run in it |
| **Plugin backend** | Whatever its canary proves, at most the native tier, and never `yolo` | Anything it claims beyond what the canary saw |
| **Linux native box** (bubblewrap, every namespace unshared, no capability; Landlock and seccomp where the kernel has them) | No network to any host address, no reads of your files outside the box, no process survives the box, no `ptrace`, `mount` or `bpf` inside it, changes come back through review | Timing channels; kernel bugs (the box shares the host kernel); a kernel without Landlock or seccomp gives a lower tier that is named as such |
| **macOS native box** (Seatbelt, deny by default, no network) | No network, no reads of your files outside the box, writes only to the copy, changes come back through review | A process that calls `setsid` can outlive its command; `sandbox-exec` is deprecated by Apple; timing channels |

## The worktree is hostile output

A sandboxed agent works on a copy. Its changes come back through an import that holds for a person: `.git` internals,
nested repositories, `.gitattributes`, `.gitmodules`, hooks, CI workflows, editor and agent config, package scripts,
links leaving the tree. Nothing the agent wrote runs on your machine before you have seen it.

## Local mode and team mode

| | Local mode | Team mode |
|---|---|---|
| Identity | Your OS account | Your organisation's OpenID Connect login |
| Policy | `~/.hn/policy.json`, **advisory**: it binds the agent, not the person who owns the machine | A signed policy tree, applied by the broker on every call, and by the laptop as well |
| Model keys | On this machine, held by the harness | On the broker only |
| What binds a person who edits the client | Nothing | Model access, budgets, server-side tools, approvals, team memory |

**The limit of team mode, stated plainly:** a modified client can still read local files and lie about local results.
Only what runs on the broker is fully bound. See [team-mode.md](team-mode.md).

## Logs and audit

Each session log is HMAC-chained with a key only this machine holds; locally it is tamper-evident to someone holding
that key, and a cut tail is caught only against a head known from somewhere else. In team mode the broker keeps that
head (an anchor), and keeps its own chain of every decision, which can be shipped to a SIEM and checked there.

## The supply chain of hn itself

Releases are byte-reproducible, signed with ed25519, and carry a CycloneDX SBOM; updates install only when signed by
the key the installed copy pins, and never to an older or equal version ([releases.md](releases.md)). No dependency
runs install scripts; every package is pinned by a sha512 hash; new versions wait 7 days before use.

## Reporting a hole

Please use [SECURITY.md](../../SECURITY.md), not a public issue. Every attack the project knows about is listed with
its test in [attacks.md](attacks.md).
