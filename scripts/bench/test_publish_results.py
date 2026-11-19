"""Tests for the results page renderer."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import publish_results as pr

BOUNDARY = "hn ran unattended inside Harbor's task container, which was its only boundary; hn does not verify it."


def report(**over) -> dict:
    base = {
        "what": {"dataset": "terminal-bench@2.0", "model": "ollama/qwen3:14b", "harbor": "0.25.0", "harbor_pinned": "0.25.0", "hn_package": "haven-harness-0.8.0.tgz", "hn_package_sha256": "ab" * 32, "hn_commit": "c" * 40, "started": "2026-11-20T01:00:00+00:00", "n_concurrent": 1, "retries": 1, "container_boundary": BOUNDARY},
        "counts": {"passed": 3, "failed": 5, "errored": 1, "not_run": 0},
        "tasks_in_set": 9,
        "score": 3 / 9,
        "tokens": 1234567,
        "cost_usd": None,
        "stopped": None,
        "tasks": [{"task": "a", "status": "passed"}, {"task": "b", "status": "errored", "exception": "RuntimeError"}],
    }
    base.update(over)
    return base


def make_run(tmp: Path, name: str, rep: dict) -> Path:
    run = tmp / name
    run.mkdir(parents=True)
    (run / "report.json").write_text(json.dumps(rep))
    return run


class Rendering(unittest.TestCase):
    def test_every_figure_on_the_page_comes_from_the_report(self):
        text = pr.render([("run-a", report())], False)
        for expected in ["**3 of 9 tasks passed (33.3%).**", "5 failed, 1 errored (never judged), 0 not run", "8 were judged", "1,234,567", "unknown (the model has no price)", "2026-11-20", "Harbor | 0.25.0", "`" + "c" * 40 + "`", "ab" * 32, "docs/results/run-a/report.json"]:
            self.assertIn(expected, text)
        self.assertIn(BOUNDARY, text)

    def test_an_errored_task_is_listed_apart_from_failures_and_named_with_why(self):
        text = pr.render([("run-a", report())], False)
        self.assertIn("**Errored, not failed (1):** `b` (RuntimeError)", text)

    def test_it_states_what_was_not_measured_and_makes_no_claim_for_a_model_that_was_not_run(self):
        text = pr.render([("run-a", report())], False)
        self.assertIn("A hosted model is not on this page unless a run for it is", text)
        self.assertIn("A low score is published as it is.", text)
        self.assertIn("no benchmark-specific prompt", text)

    def test_a_known_cost_is_shown_in_dollars(self):
        self.assertIn("| Cost | $12.35 |", pr.render([("r", report(cost_usd=12.3456))], False))


class Refusals(unittest.TestCase):
    def refuse(self, rep: dict, *flags: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(Path(tmp), "run-a", rep)
            out = Path(tmp) / "docs" / "guide" / "page.md"
            out.parent.mkdir(parents=True)
            code = pr.main(["--run", str(run), "--out", str(out), *flags])
            self.assertEqual(code, 2, "refused")
            self.assertFalse(out.exists(), "and nothing was written")
            return ""

    def test_a_run_from_an_uncommitted_tree_a_partial_run_and_a_run_with_no_commit_are_not_published(self):
        what = report()["what"]
        self.refuse(report(what={**what, "hn_commit": "c" * 40 + "-dirty"}))
        self.refuse(report(stopped="the cap was reached"))
        self.refuse(report(counts={"passed": 1, "failed": 0, "errored": 0, "not_run": 3}))
        self.refuse(report(what={**what, "hn_commit": None}))

    def test_a_folder_that_is_not_a_run_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(pr.main(["--run", tmp, "--out", str(Path(tmp) / "x.md")]), 2)
            run = Path(tmp) / "r"
            run.mkdir()
            (run / "report.json").write_text('{"what": {}}')
            self.assertEqual(pr.main(["--run", str(run), "--out", str(Path(tmp) / "x.md")]), 2)

    def test_the_flags_allow_a_dirty_or_partial_run_and_the_page_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            what = report()["what"]
            run = make_run(Path(tmp), "run-a", report(what={**what, "hn_commit": "c" * 40 + "-dirty"}))
            out = Path(tmp) / "docs" / "guide" / "page.md"
            out.parent.mkdir(parents=True)
            self.assertEqual(pr.main(["--run", str(run), "--out", str(out), "--allow-dirty"]), 0)
            self.assertIn("(uncommitted changes)", out.read_text())

    def test_two_runs_with_one_folder_name_are_refused_so_a_report_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = make_run(Path(tmp) / "one", "same", report())
            b = make_run(Path(tmp) / "two", "same", report())
            self.assertEqual(pr.main(["--run", str(a), "--run", str(b), "--out", str(Path(tmp) / "x.md")]), 2)


class Writing(unittest.TestCase):
    def test_it_copies_each_report_beside_the_page_and_the_copy_is_the_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            rep = report()
            run = make_run(Path(tmp), "run-a", rep)
            out = Path(tmp) / "docs" / "guide" / "benchmark-results.md"
            out.parent.mkdir(parents=True)
            self.assertEqual(pr.main(["--run", str(run), "--out", str(out)]), 0)
            self.assertEqual(json.loads((Path(tmp) / "docs" / "results" / "run-a" / "report.json").read_text()), rep)
            self.assertIn("# Benchmark results", out.read_text())


if __name__ == "__main__":
    unittest.main()
