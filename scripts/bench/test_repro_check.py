"""Tests for the reproducibility check."""

from __future__ import annotations

import unittest

import repro_check as rc

ORIGINAL = {"tasks": [{"task": f"t{n}", "status": s} for n, s in enumerate(["passed", "failed", "failed", "errored", "passed", "failed", "failed", "passed"])]}


class Picking(unittest.TestCase):
    def test_it_picks_only_judged_tasks_by_hash_and_the_same_seed_gives_the_same_sample(self):
        first = rc.pick(ORIGINAL, 4, "s")
        self.assertEqual(first, rc.pick(ORIGINAL, 4, "s"))
        self.assertNotIn("t3", rc.pick(ORIGINAL, 7, "s"), "an errored task was never judged, so it has nothing to agree with")
        self.assertEqual(len(rc.pick(ORIGINAL, 7, "s")), 7)
        self.assertNotEqual(rc.pick(ORIGINAL, 4, "s"), rc.pick(ORIGINAL, 4, "other"))

    def test_a_sample_larger_than_the_judged_tasks_is_refused(self):
        for sample in (0, 8, 100):
            with self.assertRaisesRegex(ValueError, "from 1 to 7"):
                rc.pick(ORIGINAL, sample, "s")


class Comparing(unittest.TestCase):
    def test_agreement_is_over_the_tasks_the_rerun_judged_and_disagreements_are_named(self):
        rerun = {"tasks": [{"task": "t0", "status": "passed"}, {"task": "t1", "status": "passed"}, {"task": "t2", "status": "failed"}, {"task": "t4", "status": "errored"}]}
        result = rc.compare(ORIGINAL, rerun, ["t0", "t1", "t2", "t4"])
        self.assertEqual((result["sampled"], result["rerun_judged"], result["agree"]), (4, 3, 2))
        self.assertAlmostEqual(result["agreement"], 2 / 3)
        self.assertEqual([row["task"] for row in result["tasks"] if not row["agree"]], ["t1", "t4"])
        self.assertEqual((result["original_passes"], result["rerun_passes"]), (2, 2))

    def test_when_nothing_could_be_judged_again_there_is_no_agreement_figure_rather_than_a_made_up_one(self):
        rerun = {"tasks": [{"task": "t0", "status": "errored"}]}
        result = rc.compare(ORIGINAL, rerun, ["t0", "t1"])
        self.assertIsNone(result["agreement"])
        self.assertEqual(result["rerun_judged"], 0)
        self.assertEqual(next(row for row in result["tasks"] if row["task"] == "t1")["rerun"], "not_run")


if __name__ == "__main__":
    unittest.main()
