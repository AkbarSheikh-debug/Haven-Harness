"""Render the published results page from run reports.

    python scripts/bench/publish_results.py --run runs/tb2-qwen3-14b --run runs/swe50-qwen3-14b --out docs/guide/benchmark-results.md

Every number on the page comes from a run's ``report.json`` and nothing is typed in: a page that disagrees with its
reports cannot be produced. It copies each report beside the page (``docs/results/<name>/report.json``) so the per-task
rows are public, states what was and was not measured, lists every task that ERRORED separately from those that failed,
and carries the container-boundary statement the run recorded. It refuses a run that was not from a clean commit unless
told, because a score from a tree nobody can see is not a score anyone can reproduce.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any


class Refused(Exception):
    pass


def load_report(run: Path) -> dict[str, Any]:
    path = run / "report.json"
    if not path.is_file():
        raise Refused(f"{run} has no report.json; run run_bench.py first.")
    report = json.loads(path.read_text(encoding="utf-8"))
    for key in ("what", "counts", "tasks", "tasks_in_set", "score"):
        if key not in report:
            raise Refused(f"{path} is not a run report (no {key!r}).")
    return report


def check(report: dict[str, Any], name: str, allow_dirty: bool, allow_stopped: bool) -> None:
    commit = (report["what"].get("hn_commit") or "")
    if not commit:
        raise Refused(f"{name}: the run recorded no commit, so it cannot be reproduced.")
    if commit.endswith("-dirty") and not allow_dirty:
        raise Refused(f"{name}: it ran from a tree with uncommitted changes ({commit}). Rerun from a clean commit, or pass --allow-dirty and the page will say so.")
    if report.get("stopped") and not allow_stopped:
        raise Refused(f"{name}: it stopped early ({report['stopped']}). A partial run is not published as a score; finish it, or pass --allow-stopped.")
    counts = report["counts"]
    if counts["not_run"] and not allow_stopped:
        raise Refused(f"{name}: {counts['not_run']} task(s) never ran.")


def percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_run(name: str, report: dict[str, Any], dirty_ok: bool) -> list[str]:
    what, counts = report["what"], report["counts"]
    cost = "unknown (the model has no price)" if report.get("cost_usd") is None else f"${report['cost_usd']:.2f}"
    judged = counts["passed"] + counts["failed"]
    errored = [row for row in report["tasks"] if row["status"] == "errored"]
    lines = [
        f"### {what['dataset']} with {what['model']}",
        "",
        f"**{counts['passed']} of {report['tasks_in_set']} tasks passed ({percent(report['score'])}).** "
        f"{counts['failed']} failed, {counts['errored']} errored (never judged), {counts['not_run']} not run. "
        f"{judged} were judged.",
        "",
        "| | |",
        "|---|---|",
        f"| Dataset | `{what['dataset']}` |",
        f"| Model | `{what['model']}` |",
        f"| Tokens | {report['tokens']:,} |",
        f"| Cost | {cost} |",
        f"| Date | {what['started'][:10]} |",
        f"| Harbor | {what['harbor']} (pinned {what['harbor_pinned']}) |",
        f"| hn commit | `{what['hn_commit']}`{' (uncommitted changes)' if dirty_ok and str(what['hn_commit']).endswith('-dirty') else ''} |",
        f"| hn package SHA-256 | `{what['hn_package_sha256']}` |",
        f"| Tasks at once | {what['n_concurrent']} |",
        f"| Retries for an errored task | {what['retries']} |",
        f"| Per-task results | `docs/results/{name}/report.json` |",
        "",
    ]
    if errored:
        lines += [f"**Errored, not failed ({len(errored)}):** " + ", ".join(f"`{row['task']}` ({row.get('exception') or 'no result'})" for row in errored), ""]
    return lines


def render(runs: list[tuple[str, dict[str, Any]]], dirty_ok: bool) -> str:
    boundary = runs[0][1]["what"]["container_boundary"]
    out = [
        "# Benchmark results",
        "",
        "These numbers come from `scripts/bench/run_bench.py` and are rendered by `scripts/bench/publish_results.py` from the run reports, with nothing typed in. "
        "How to rerun them is in [Running the benchmarks yourself](benchmarks.md). A low score is published as it is.",
        "",
        "## How hn ran",
        "",
        boundary,
        "",
        "Each task ran in its own Harbor container with a model of the stated name. hn used the same prompts and defaults a person gets: no benchmark-specific prompt, hint or tool, and no change made after seeing a task fail unless it was a general fix and the whole run was then repeated. "
        "Every task that errored is listed apart from the tasks that failed, because an error means the task was never judged.",
        "",
        "## Results",
        "",
    ]
    for name, report in runs:
        out += render_run(name, report, dirty_ok)
    out += [
        "## What was and was not measured",
        "",
        "- The score is passed tasks over **every task in the set**. A task that errored or never ran is not a pass.",
        "- A hosted model is not on this page unless a run for it is. A model that was not run has no score here, and none is implied.",
        "- Model sampling is not fixed, so a rerun of the same task can differ. The reproducibility check reruns a sample and reports how many agreed; it is in the run folder when it was done.",
        "- hn's package here was built locally for the benchmark and signed with a key made for it; it is not a release.",
        "",
    ]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="append", required=True, type=Path, help="a run folder holding report.json; repeat for each run")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--results-dir", type=Path, help="where reports are copied (default: <out's parent>/../results)")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--allow-stopped", action="store_true")
    args = parser.parse_args(argv)
    try:
        runs = []
        for run in args.run:
            report = load_report(run)
            name = run.resolve().name
            check(report, name, args.allow_dirty, args.allow_stopped)
            runs.append((name, report))
        names = [name for name, _ in runs]
        if len(set(names)) != len(names):
            raise Refused("Two runs have the same folder name; rename one so their reports do not overwrite each other.")
    except Refused as refusal:
        print(f"Refused: {refusal}", file=sys.stderr)
        return 2
    results = args.results_dir or args.out.resolve().parent.parent / "results"
    for run in args.run:
        target = results / run.resolve().name
        target.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(run / "report.json", target / "report.json")
    args.out.write_text(render(runs, args.allow_dirty), encoding="utf-8")
    print(f"Wrote {args.out} from {len(runs)} run(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
