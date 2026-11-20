# Verified on every OS

A sandbox is a claim until something outside it checks. hn's rule is the same on every OS: a box counts as a tier only
when a canary run inside it fails to get out **and the host, watching from outside, agrees**. This page lists what that
check looks at, what each OS's result was, and where it ran. A result is only claimed for the place it was observed.

## What the check does

The canary is harness code, piped into the box. Nothing the box prints clears it. The host decides from facts the box
cannot forge:

- Listeners on every address of the machine (IPv4 and IPv6, TCP and UDP) see no connection or packet from the box.
- A file with a secret outside the box is not read; a file the box tries to create outside it does not appear.
- A proof file only the canary can produce appears inside the box, so a runner that runs nothing fails.
- A background process the canary starts stops when the box ends.
- On Linux, the namespaces the process is really in (network, pid, ipc, uts, user, mount, cgroup) are compared with the
  host's own, and the process holds no capability.
- Each extra layer a box says it applied has a probe only that layer stops, and counts only if the probe held:
  **Landlock** (a write to `/run`, a folder the mount table opens, must be refused) and **seccomp** (the kernel reports a
  filter, and `ptrace` answers `EPERM`).

Three stand-ins must fail it, and do, in the test suite: a "sandbox" that is not one, one that runs nothing, and one that
leaks (bubblewrap with the network shared on Linux, a Seatbelt profile with the network allowed on macOS). A fourth hides
what the canary printed, to show the host's own listeners are what catch it.

A layer the machine lacks is not a failed run. The box is reported as a lower tier and the layer is named as not applied.

## Results

Each runner row was produced by `scripts/box-evidence.ts` in [CI run 44653086359](https://github.com/AkbarSheikh-debug/Haven-Harness/actions/runs/44653086359), where the full test suite also passed on all three OSes. The result is written to the job summary and to a build annotation.

| OS | Kernel | Where it ran | Box | Layers verified | Not applied |
|---|---|---|---|---|---|
| Windows 11 | 10.0.26100 | GitHub-hosted runner (`windows-latest`) | AppContainer, no capabilities, low integrity, Job Object | AppContainer, job object | none |
| Ubuntu 26.04 | 7.0.0-1019-azure | GitHub-hosted runner (`ubuntu-latest`) | bubblewrap, every namespace unshared | namespaces, Landlock, seccomp | none |
| macOS | Darwin 25.6.0 | GitHub-hosted runner (`macos-latest`, arm64) | `sandbox-exec`, deny by default, no network | Seatbelt | process tree: a process that calls `setsid` can outlive the command |
| Debian 12 (userland) | 6.18.58.1-microsoft-standard-WSL2 | a **privileged** container on a developer machine (Docker Desktop) | bubblewrap, every namespace unshared | namespaces, Landlock (ABI 7), seccomp | none |

Two Linux kernels are listed because one result is a claim and two are evidence. A WSL2 kernel is not a distribution's
kernel, so the Ubuntu run is the one to rely on. Runner images change; the kernel in a later run may differ from the one above.

## What it took, and what it does not cover

- **Linux needs namespaces for ordinary users.** Ubuntu 24.04 and later restrict them; CI runs
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`. In an ordinary Docker container bubblewrap fails
  ("No permissions to create new namespace", because Docker's default seccomp profile forbids it). hn reports that with the
  setting that changes it, and the tests fail rather than skip wherever CI requires a box.
- **macOS has no process namespace.** The box ends the command's process group, but a process that calls `setsid` can
  outlive it. The check cannot test that, and the box's layer list says so. `sandbox-exec` is deprecated by Apple; it
  still worked on the runner above.
- **Timing channels** are not covered on any OS. On Linux and macOS a box shares the host's kernel, which Landlock and
  seccomp narrow without removing. The system folders a box may read (the system, certificates) are readable on every OS.
- A box on another machine is not covered by these rows. Run `hn doctor` to see what yours can do, and `hn` verifies the
  box again every time a session starts.

## Run it yourself

```bash
node --disable-proto=throw scripts/box-evidence.ts     # the row for this machine
scripts/linux-box/run-in-container.sh sh -c 'pnpm install --frozen-lockfile --ignore-scripts && pnpm build:sandbox && pnpm test'
```

The second command runs the suite on Linux in a privileged container (it copies the repository, so nothing is changed).
`scripts/linux-box/mutation-check.ts` breaks the box code on purpose, one way at a time (a namespace left shared, a path
made writable, a filter that lets `ptrace` through), and fails if any break goes unnoticed by a test.
