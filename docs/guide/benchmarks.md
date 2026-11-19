# Running the benchmarks yourself

Haven Harness can be scored on any [Harbor](https://github.com/laude-institute/harbor) dataset, such as Terminal-Bench 2 or SWE-bench Verified, with one command that you can rerun and that says exactly what it ran. This page is how. Scores, when they are published, come from these scripts and nothing else.

## What you need

- **Docker**, running. Every task runs in its own container.
- **Python 3.12 or newer**, with **Harbor 0.25.0**. The scripts are pinned to it, so a score names the tool that made it: `python -m venv bench-env && bench-env/bin/pip install harbor==0.25.0`.
- **Node 24 and this repository**, to build what is installed in each container.
- **A model.** A hosted one needs a key; a local one (`ollama/...`) needs Ollama reachable from the containers (`--base-url http://host.docker.internal:11434`).

**Use a key made for the benchmark, with a spend cap, and revoke it afterwards.** hn keeps the key out of everything the model's commands can see and out of every file, but it is in hn's own starting environment inside the container, and a model that goes looking can read it from `/proc`. Every agent installed in a benchmark container has that exposure.

## 1. Build what each container installs

```
node --disable-proto=throw scripts/bench/prepare.ts --out bench-inputs
```

This makes a signing key for the benchmark (not the release key), packs hn's npm package pinning it, builds the sandbox helper for Linux in a Rust image pinned by digest, and signs the helper. Nothing is downloaded from a release, so none has to exist. `--dry-run` prints what it would do.

## 2. Run

```
python scripts/bench/run_bench.py \
  --dataset terminal-bench@2.0 --model anthropic/claude-opus-5-5 \
  --hn-package bench-inputs/package/haven-harness-<version>.tgz --hn-helpers bench-inputs/helpers-signed \
  --out runs/tb2-opus --max-usd 150
```

| Option | Meaning |
|---|---|
| `--dataset name@version` | What to score. The version is required, so a result says what it scored. |
| `--model provider/model` | `anthropic/...`, `ollama/...` or `openai-compatible/...` (with `--base-url`). |
| `--max-usd`, `--max-tokens` | **A cap is required.** It is checked between waves, so it can be passed by at most one wave of tasks. |
| `--n-concurrent`, `--wave` | How many tasks run at once, and how many go in a wave. |
| `--tasks N`, `--include a,b`, `--task-list FILE` | A smaller or a fixed set of tasks, always sorted by name. |
| `--retries N` | Extra tries for a task whose trial **errored** (default 1). A task that was judged is never rerun. |

A dollar cap needs a model with a known price ([what a run cost](cost.md)). If the price is unknown the run stops after the first wave and says so; use `--max-tokens` instead.

## 3. Read the result

`runs/tb2-opus/report.md` and `report.json` hold, per task, **passed** (reward 1), **failed** (judged, below 1) or **errored** (never judged), with tokens and cost, and, at the top, exactly what was run: the dataset and Harbor versions, the model, hn's package hash and commit, the date and the command. The score is passed tasks over **every task in the set**; an errored or unrun task is not a pass, and the report keeps errors apart from failures.

If it stops (the cap, Docker not answering), run the same command again: it resumes, running only what has no result. `STOPPED.txt` says why it stopped.

## How hn is trusted inside the container

The task container is the only boundary, and hn cannot verify it from inside. hn runs unattended with `--benchmark-container`, which needs an allow entry in hn's own home, `HN_BENCH_CONTAINER=1`, and a process that really is in a Linux container. It is capped at `dont-ask` with the allow list `bash`, `write_file` and `edit_file`, never `yolo`. Every report says this. A workstation is refused even with all of that in place.
