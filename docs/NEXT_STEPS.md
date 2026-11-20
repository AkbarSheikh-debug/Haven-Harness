# What is left

This is a first, working version of Haven Harness. This file is the list of what remains, in the order it should be done, so the work can be picked up later without the history. Nothing below is half-finished code: each item is a thing that was deliberately left for afterwards.

## What exists today

- The core agent with a permission gate on every action, a verified Windows sandbox, taint tracking, a tamper-evident session log, memory, sub-agents, teams, workflows, fleets and schedules.
- Team mode: a self-hosted broker that holds model keys and applies a signed policy.
- Signed releases, an update verifier, and a one-command npm install that fetches a verified sandbox helper on first use.
- A cost report by role and model, per-role model choice in `routing.json`, and a Harbor adapter with a resumable, spend-capped benchmark runner (`scripts/bench`, see [docs/guide/benchmarks.md](guide/benchmarks.md)).
- The full test suite passes (about 1,560 tests) and typechecks clean.

## 1. Finish the benchmarks (the biggest open item)

A benchmark run is long (hours), so it was left for afterwards. State: Terminal-Bench 2 with the local `qwen3:14b` is **10 of 89 tasks judged, 0 passed**; a 10-task calibration scored 0 of 10. Nothing has been published.

1. Start Docker Desktop and Ollama (`ollama pull qwen3:14b` if the model is gone).
2. Build what each container installs, once: `node --disable-proto=throw scripts/bench/prepare.ts --out <folder>`. **Do not rebuild between resumes**: one run must use one build.
3. Pull the task images ahead of the agent, so downloads overlap with work: `python scripts/bench/prefetch_images.py --registry <out>/registry.json --dataset terminal-bench@2.0 --min-free-gb 150`.
4. Run, or resume (the same command resumes and only runs tasks without a result): `python scripts/bench/run_bench.py --dataset terminal-bench@2.0 --model ollama/qwen3:14b --base-url http://host.docker.internal:11434 --window 32768 --hn-package <folder>/package/haven-harness-<version>.tgz --hn-helpers <folder>/helpers-signed --out <run folder> --n-concurrent 1 --retries 1 --max-tokens 40000000`. Expect roughly 7 to 8 hours for the 89 tasks.
5. Then the fixed 50-task SWE-bench Verified subset: the same command with `--dataset swebench-verified@1.0 --task-list scripts/bench/swebench-verified-50.txt`.
6. Check reproducibility: `python scripts/bench/repro_check.py --of <run folder> --sample 10 --seed repro-1 -- <the same arguments, without --out>`.
7. Publish from a clean commit: `python scripts/bench/publish_results.py --run <run folder> ... --out docs/guide/benchmark-results.md`. It refuses a partial run, an uncommitted tree, or a run with no commit.

**A hosted-model score needs a key and a cap**, which have not been provided. Use a key made for the benchmark, with a spend cap, and revoke it afterwards: a model that goes looking can read it from inside the container. Run the same steps with `--model anthropic/<model>` and `--max-usd <cap>`.

## 2. First real release

None of this has run yet, because it needs accounts and a key that belong to the owner.

- **Run `release.yml` on GitHub once.** It builds the sandbox helper for six platforms, signs a manifest, and creates a draft release. It has never run, so the first run will show what breaks.
- **The release signing key** stays offline (or a protected CI secret you choose to add). It signs the helper manifest and the package.
- **npm:** an account with two-factor authentication, and a check that the name `haven-harness` is still free. The workflow never runs `npm publish`; publishing is a manual step.
- Publish the draft release, then install it on a clean machine and run `hn doctor`.

## 3. Security work still open

- **An independent security review.** The review packet is ready; the review itself needs someone outside the project.
- Key rotation for the policy and release keys is by hand (no revocation list yet).
- Releases carry no sigstore provenance until they are built by CI.

## 4. Next phases

- **Make the three-OS CI jobs required.** The Linux box (bubblewrap, Landlock, seccomp) and the macOS box (Seatbelt) are built and verified from outside on GitHub runners (see [verified on every OS](guide/sandbox-verified.md)). Requiring the three `test` jobs is a branch-protection setting on GitHub, which belongs to the repository owner: Settings, Branches, add a rule for `main` and tick the three `test (...)` checks.
- **Where people work:** a VS Code extension on the ACP door, and a GitHub Action that turns a labelled issue into a pull request with every command run in a verified box.
- **Trust you can show:** a public page that lists every named attack with its test, a hall of fame for reported holes, and a replay and audit screen in `hn serve`.

## 5. Known limits

- In a benchmark container the model's API key is in hn's own starting environment, readable by a model that looks for it. hn removes it from everything it starts and from every file.
- A claimed outer sandbox (`--external-sandbox`, `--benchmark-container`) is never verified and is capped at `dont-ask` with an explicit allow list, never `yolo`.
- Model sampling is not fixed, so a benchmark task can come out differently on a rerun; the reproducibility check measures by how much.
- Budgets can be overrun by up to the in-flight cap's worth of calls, and broker approvals live in memory.
- Windows is the most-tested platform. The Linux and macOS boxes are verified on one runner image each plus a privileged Linux container; a distribution or kernel not listed in the evidence table has not been run. On macOS a process that calls `setsid` can outlive its command.
