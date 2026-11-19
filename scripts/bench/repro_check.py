"""Rerun a sample of tasks from a finished run and say how many agree.

    python scripts/bench/repro_check.py --of runs/tb2-qwen3-14b --sample 10 --seed repro-1 -- \\
        <the same arguments the run was made with, except --out>

A model's sampling is not fixed, so a rerun of one task can come out differently, and a published score should say by how
much. This picks ``--sample`` judged tasks from the run's report, ranked by SHA-256 of ``<seed>:<task>`` (nobody chooses
them), reruns just those through ``run_bench.py`` into ``<run>/repro``, and writes ``<run>/repro.json``: for each task
the original and the new result, and the share that agree. It reports what it finds: a poor agreement is the finding, not
a failure of this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import run_bench as rb


def pick(report: dict[str, Any], sample: int, seed: str) -> list[str]:
    """Judged tasks only (an errored one has no result to agree with), chosen by hash of seed and task name."""
    judged = [row["task"] for row in report["tasks"] if row["status"] in ("passed", "failed")]
    if sample < 1 or sample > len(judged):
        raise ValueError(f"--sample must be from 1 to {len(judged)} (the judged tasks), got {sample}.")
    ranked = sorted(judged, key=lambda task: hashlib.sha256(f"{seed}:{task}".encode()).hexdigest())
    return sorted(ranked[:sample])


def compare(original: dict[str, Any], rerun: dict[str, Any], tasks: list[str]) -> dict[str, Any]:
    before = {row["task"]: row for row in original["tasks"]}
    after = {row["task"]: row for row in rerun["tasks"]}
    rows = []
    for task in tasks:
        old, new = before[task]["status"], after.get(task, {}).get("status", "not_run")
        rows.append({"task": task, "original": old, "rerun": new, "agree": old == new})
    judged_again = [row for row in rows if row["rerun"] in ("passed", "failed")]
    agreed = sum(1 for row in judged_again if row["agree"])
    return {
        "tasks": rows,
        "sampled": len(tasks),
        "rerun_judged": len(judged_again),
        "agree": agreed,
        # Over the tasks the rerun judged: one that errored the second time says nothing about agreement.
        "agreement": (agreed / len(judged_again)) if judged_again else None,
        "original_passes": sum(1 for row in rows if row["original"] == "passed"),
        "rerun_passes": sum(1 for row in rows if row["rerun"] == "passed"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--of", required=True, type=Path, help="the finished run's folder")
    parser.add_argument("--sample", type=int, default=10)
    parser.add_argument("--seed", required=True)
    parser.add_argument("rest", nargs=argparse.REMAINDER, help="after --: the run's own arguments, without --out")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    original = json.loads((args.of / "report.json").read_text(encoding="utf-8"))
    tasks = pick(original, args.sample, args.seed)
    out = args.of / "repro"
    listing = args.of / "repro-tasks.txt"
    listing.write_text("\n".join(tasks) + "\n", encoding="utf-8")
    rest = [part for part in args.rest if part != "--"]
    code = rb.main([*rest, "--out", str(out), "--task-list", str(listing), "--retries", "1"])
    if code == 2:
        return 2
    rerun = json.loads((out / "report.json").read_text(encoding="utf-8"))
    result = {"of": str(args.of), "seed": args.seed, **compare(original, rerun, tasks)}
    (args.of / "repro.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    share = "none of the sampled tasks could be judged again" if result["agreement"] is None else f"{result['agree']} of {result['rerun_judged']} agreed ({result['agreement']:.0%})"
    print(f"Reproducibility: {share}; the original run passed {result['original_passes']} of the {result['sampled']}, the rerun {result['rerun_passes']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
