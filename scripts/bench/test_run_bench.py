"""Tests for the benchmark runner, with a fake Harbor that writes trial results the way Harbor does.

    python -m unittest discover -s scripts/bench -p "test_run_bench.py"
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import run_bench as rb

DATASET = "ds@1.0"
CLOCK = lambda: datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)  # noqa: E731


def registry(tmp: Path, names: list[str]) -> Path:
    path = tmp / "registry.json"
    path.write_text(json.dumps([{"name": "ds", "version": "1.0", "tasks": [{"name": n} for n in names]}, {"name": "other", "version": "1.0", "tasks": [{"name": "zzz"}]}]))
    return path


class FakeHarbor:
    """Answers `docker info` and `harbor run`. `plan` maps a task to its outcomes, one per attempt: pass, fail, error,
    or a (reward, cost, tokens) tuple. A task not in the plan passes."""

    def __init__(self, plan: dict[str, list] | None = None, docker: list[int] | None = None, cost: float | None = 0.5, tokens: int = 1000, writes: bool = True) -> None:
        self.plan = plan or {}
        self.docker = list(docker or [])
        self.cost, self.tokens, self.writes = cost, tokens, writes
        self.waves: list[list[str]] = []
        self.attempts: dict[str, int] = {}
        self.docker_calls = 0
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], capture: bool = False, env: dict | None = None) -> int:
        if command[0] == "docker":
            self.docker_calls += 1
            return self.docker.pop(0) if self.docker else 0
        self.commands.append(command)
        tasks = [command[i + 1] for i, part in enumerate(command) if part == "-i"]
        self.waves.append(tasks)
        out = Path(command[command.index("-o") + 1])
        job = command[command.index("--job-name") + 1]
        if self.writes:
            for task in tasks:
                attempt = self.attempts.get(task, 0)
                self.attempts[task] = attempt + 1
                outcomes = self.plan.get(task, ["pass"])
                outcome = outcomes[min(attempt, len(outcomes) - 1)]
                self.write(out / job / f"{task}__{attempt}", task, outcome)
        return 0  # Harbor exits 0 whatever happened to the trials

    def write(self, folder: Path, task: str, outcome) -> None:
        folder.mkdir(parents=True)
        reward, cost = (1.0, self.cost) if outcome == "pass" else (0.0, self.cost) if outcome == "fail" else (None, self.cost)
        if isinstance(outcome, tuple):
            reward, cost, tokens = outcome
        else:
            tokens = self.tokens
        data = {
            "task_name": task, "trial_name": folder.name,
            "verifier_result": None if reward is None else {"rewards": {"reward": reward}},
            "exception_info": {"exception_type": "RuntimeError", "exception_message": "boom"} if outcome == "error" else None,
            "agent_result": None if outcome == "error" and False else {"n_input_tokens": tokens, "n_cache_tokens": 0, "n_output_tokens": 10, "cost_usd": cost, "metadata": {"hn_end": "done"}},
        }
        (folder / "result.json").write_text(json.dumps(data))


def settings(tmp: Path, names: list[str], **overrides) -> rb.Settings:
    package = tmp / "haven-harness-0.9.0.tgz"
    package.write_bytes(b"package")
    helpers = tmp / "helpers"
    helpers.mkdir(exist_ok=True)
    base = dict(dataset=DATASET, model="openai-compatible/fake", out=tmp / "out", hn_package=package, hn_helpers=helpers, base_url="http://h:1/v1", n_concurrent=2, max_tokens=10**9, registry_file=registry(tmp, names))
    base.update(overrides)
    return rb.Settings(**base)


def runner(s: rb.Settings, fake: FakeHarbor, env: dict | None = None) -> rb.Runner:
    r = rb.Runner(s, run=fake, sleep=lambda _s: None, env=env if env is not None else {}, now=CLOCK)
    r.harbor_version = lambda: rb.PINNED_HARBOR  # type: ignore[method-assign]
    return r


class Refusals(unittest.TestCase):
    def refused(self, s: rb.Settings, fake: FakeHarbor | None = None, env: dict | None = None, version: str = rb.PINNED_HARBOR) -> str:
        r = runner(s, fake or FakeHarbor(), env)
        r.harbor_version = lambda: version  # type: ignore[method-assign]
        with self.assertRaises(rb.Refused) as caught:
            r.run()
        return str(caught.exception)

    def test_it_never_runs_without_a_spend_cap_or_with_a_nonsense_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor()
            self.assertIn("Give a spend cap", self.refused(settings(Path(tmp), ["a"], max_usd=None, max_tokens=None), fake))
            self.assertIn("above zero", self.refused(settings(Path(tmp), ["a"], max_usd=0), fake))
            self.assertIn("above zero", self.refused(settings(Path(tmp), ["a"], max_tokens=-5), fake))
            self.assertEqual(fake.commands, [], "nothing ran")

    def test_an_anthropic_model_needs_its_key_and_a_missing_input_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIn("ANTHROPIC_API_KEY", self.refused(settings(Path(tmp), ["a"], model="anthropic/claude-opus-5-5"), env={}))
            self.assertIn("--hn-package", self.refused(settings(Path(tmp), ["a"], hn_package=Path(tmp) / "nope.tgz")))

    def test_the_pinned_harbor_is_required_unless_the_person_says_otherwise(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIn("pinned to 0.25.0", self.refused(settings(Path(tmp), ["a"]), version="0.26.0"))
            r = runner(settings(Path(tmp), ["a"], allow_other_harbor=True), FakeHarbor())
            r.harbor_version = lambda: "0.26.0"  # type: ignore[method-assign]
            self.assertEqual(r.run(), 0)
            self.assertEqual(json.loads((Path(tmp) / "out" / "report.json").read_text())["what"]["harbor"], "0.26.0", "and the report says which Harbor it was")

    def test_a_dataset_must_name_its_version_and_exist_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIn("name its version", self.refused(settings(Path(tmp), ["a"], dataset="ds")))
            self.assertIn("0 entries", self.refused(settings(Path(tmp), ["a"], dataset="ds@9.9")))
            self.assertIn("not in ds@1.0: nope", self.refused(settings(Path(tmp), ["a"], include=["nope"])))


class DockerReadiness(unittest.TestCase):
    def test_waits_through_the_seconds_when_docker_answers_but_is_not_ready(self):
        calls = [1, 1, 1, 0]
        slept: list[float] = []
        rb.docker_ready(lambda _c: calls.pop(0), slept.append)
        self.assertEqual(slept, [5, 5, 5])

    def test_gives_up_with_a_clear_message_and_never_starts_harbor(self):
        with self.assertRaisesRegex(rb.Refused, "did not answer within 20 s"):
            rb.docker_ready(lambda _c: 1, lambda _s: None, timeout_s=20, step_s=5)
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor(docker=[1] * 200)
            code = runner(settings(Path(tmp), ["a", "b"]), fake).run()
            self.assertEqual(code, 3)
            self.assertEqual(fake.commands, [], "harbor was never started")
            self.assertIn("Docker's engine", (Path(tmp) / "out" / "STOPPED.txt").read_text())


class MissingTools(unittest.TestCase):
    def test_a_missing_docker_is_a_clear_refusal_at_once_not_a_three_minute_wait(self):
        slept: list[float] = []
        with self.assertRaisesRegex(rb.Refused, "Docker was not found"):
            rb.docker_ready(lambda _c: rb.NOT_FOUND, slept.append)
        self.assertEqual(slept, [], "it did not wait")

    def test_a_missing_harbor_is_a_clear_refusal_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = rb.Runner(settings(Path(tmp), ["a"], harbor=["definitely-not-a-program-xyz"]), run=FakeHarbor(), sleep=lambda _s: None, env={}, now=CLOCK)
            with self.assertRaisesRegex(rb.Refused, "Harbor was not found"):
                r.run()


class ScoringAndClassification(unittest.TestCase):
    def test_a_pass_a_failure_and_an_error_are_three_different_things(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor({"b": ["fail"], "c": ["error", "error"]})
            code = runner(settings(Path(tmp), ["a", "b", "c"], retries=1), fake).run()
            report = json.loads((Path(tmp) / "out" / "report.json").read_text())
            self.assertEqual(report["counts"], {"passed": 1, "failed": 1, "errored": 1, "not_run": 0})
            self.assertAlmostEqual(report["score"], 1 / 3)
            self.assertEqual({row["task"]: row["status"] for row in report["tasks"]}, {"a": "passed", "b": "failed", "c": "errored"})
            self.assertEqual(code, 1, "an errored task is not a clean run")
            c = next(row for row in report["tasks"] if row["task"] == "c")
            self.assertEqual((c["trials"], c["exception"]), (2, "RuntimeError"), "retried once, then left as errored")

    def test_harbors_exit_code_is_never_the_judge(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor({"a": ["error", "error"]})  # the fake returns 0 for every wave
            self.assertEqual(runner(settings(Path(tmp), ["a"], retries=1), fake).run(), 1)

    def test_an_errored_trial_is_retried_and_a_later_pass_stands(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor({"a": ["error", "pass"]})
            self.assertEqual(runner(settings(Path(tmp), ["a"], retries=1), fake).run(), 0)
            self.assertEqual(fake.waves, [["a"], ["a"]])
            self.assertEqual(json.loads((Path(tmp) / "out" / "report.json").read_text())["counts"]["passed"], 1)
            with tempfile.TemporaryDirectory() as tmp2:
                none = FakeHarbor({"a": ["error", "pass"]})
                self.assertEqual(runner(settings(Path(tmp2), ["a"], retries=0), none).run(), 1)
                self.assertEqual(none.waves, [["a"]], "no retries asked, none made")

    def test_the_report_names_what_was_run_and_what_the_boundary_was(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner(settings(Path(tmp), ["a"]), FakeHarbor()).run()
            report = json.loads((Path(tmp) / "out" / "report.json").read_text())
            what = report["what"]
            self.assertEqual((what["dataset"], what["model"], what["harbor_pinned"]), (DATASET, "openai-compatible/fake", "0.25.0"))
            self.assertRegex(what["hn_package_sha256"], r"^[0-9a-f]{64}$")
            self.assertIn("its only boundary", what["container_boundary"])
            self.assertIn("never yolo", what["container_boundary"])
            md = (Path(tmp) / "out" / "report.md").read_text()
            self.assertIn("Score: 1 of 1 tasks passed (100.0%)", md)
            self.assertIn("its only boundary", md)
            self.assertTrue((Path(tmp) / "out" / "registry.json").exists(), "the task list it came from is kept")

    def test_a_task_that_never_ran_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = runner(settings(Path(tmp), ["a", "b", "c", "d"], max_tokens=1500, n_concurrent=1), FakeHarbor(tokens=2000)).run()
            report = json.loads((Path(tmp) / "out" / "report.json").read_text())
            self.assertEqual(code, 3)
            self.assertEqual(report["counts"], {"passed": 1, "failed": 0, "errored": 0, "not_run": 3})
            self.assertAlmostEqual(report["score"], 0.25, msg="scored over every task in the set")

    def test_the_command_pins_what_it_scores_and_uses_the_supported_agent_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor()
            runner(settings(Path(tmp), ["a", "b"], window=64000), fake).run()
            command = fake.commands[0]
            for part in ["-d", DATASET, "--agent", "harbor_agent:HavenHarnessAgent", "-m", "openai-compatible/fake", "-y", "-q", "hn_base_url=http://h:1/v1", "hn_window=64000"]:
                self.assertIn(part, command)
            self.assertNotIn("--agent-import-path", command)
            self.assertEqual([command[i + 1] for i, p in enumerate(command) if p == "-i"], ["a", "b"])


class Resuming(unittest.TestCase):
    def test_a_second_run_does_no_work_and_reports_the_same(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = settings(Path(tmp), ["a", "b", "c"], n_concurrent=2)
            first = FakeHarbor({"b": ["fail"]})
            runner(s, first).run()
            report = (Path(tmp) / "out" / "report.json").read_text()
            second = FakeHarbor()
            self.assertEqual(runner(s, second).run(), 0)
            self.assertEqual(second.waves, [], "every task already had a judged trial")
            self.assertEqual(json.loads((Path(tmp) / "out" / "report.json").read_text())["counts"], json.loads(report)["counts"])

    def test_after_a_stop_it_carries_on_with_only_what_is_left(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = FakeHarbor(tokens=600)
            self.assertEqual(runner(settings(Path(tmp), ["a", "b", "c", "d"], n_concurrent=2, max_tokens=1000), first).run(), 3)
            self.assertEqual(first.waves, [["a", "b"]], "the cap was checked after the first wave, and it was passed")
            self.assertTrue((Path(tmp) / "out" / "STOPPED.txt").exists())
            second = FakeHarbor()
            self.assertEqual(runner(settings(Path(tmp), ["a", "b", "c", "d"], n_concurrent=2, max_tokens=10**9), second).run(), 0)
            self.assertEqual(second.waves, [["c", "d"]], "a and b were not run again")
            self.assertEqual(json.loads((Path(tmp) / "out" / "report.json").read_text())["counts"]["passed"], 4)

    def test_a_resume_that_finishes_does_not_leave_an_earlier_stop_marker_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner(settings(Path(tmp), ["a", "b"], n_concurrent=1, max_tokens=1), FakeHarbor()).run()
            self.assertTrue((Path(tmp) / "out" / "STOPPED.txt").exists())
            self.assertEqual(runner(settings(Path(tmp), ["a", "b"], n_concurrent=1), FakeHarbor()).run(), 0)
            self.assertFalse((Path(tmp) / "out" / "STOPPED.txt").exists())
            self.assertIsNone(json.loads((Path(tmp) / "out" / "report.json").read_text())["stopped"])

    def test_job_names_continue_after_a_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner(settings(Path(tmp), ["a", "b", "c", "d"], n_concurrent=2, max_tokens=1), FakeHarbor()).run()
            second = FakeHarbor()
            runner(settings(Path(tmp), ["a", "b", "c", "d"], n_concurrent=2), second).run()
            self.assertEqual(second.commands[0][second.commands[0].index("--job-name") + 1], "wave-0002")


class SpendCap(unittest.TestCase):
    def test_the_cap_is_checked_between_waves_so_it_is_passed_by_at_most_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor(cost=0.6)
            code = runner(settings(Path(tmp), ["a", "b", "c", "d", "e", "f"], n_concurrent=2, max_tokens=None, max_usd=1.0), fake).run()
            self.assertEqual(code, 3)
            self.assertEqual(fake.waves, [["a", "b"]], "$1.20 was spent against a $1.00 cap, and not another task was started")
            self.assertIn("the cap of $1.00 was reached ($1.2000 spent)", (Path(tmp) / "out" / "STOPPED.txt").read_text())

    def test_a_dollar_cap_cannot_be_enforced_for_a_model_with_no_price_so_it_stops_after_one_wave(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor(cost=None)
            code = runner(settings(Path(tmp), ["a", "b", "c", "d"], n_concurrent=2, max_tokens=None, max_usd=50), fake).run()
            self.assertEqual(code, 3)
            self.assertEqual(len(fake.waves), 1)
            self.assertIn("cannot be enforced", (Path(tmp) / "out" / "STOPPED.txt").read_text())
            self.assertIsNone(json.loads((Path(tmp) / "out" / "report.json").read_text())["cost_usd"], "unknown stays unknown, never 0")
            table = (Path(tmp) / "out" / "report.md").read_text()
            self.assertIn("| unknown |", table, "an unpriced task shows unknown, not a blank or a zero")
            self.assertNotIn("$0.0000", table)

    def test_a_token_cap_works_for_a_model_with_no_price(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor(cost=None, tokens=400)
            code = runner(settings(Path(tmp), ["a", "b", "c", "d"], n_concurrent=1, max_tokens=900), fake).run()
            self.assertEqual(code, 3)
            self.assertEqual(fake.waves, [["a"], ["b"], ["c"]], "410 tokens a task: stops after the wave that passes 900")

    def test_a_cap_that_is_exactly_reached_stops_the_run_for_tokens_and_for_dollars(self):
        with tempfile.TemporaryDirectory() as tmp:
            # 490 in and 10 out is 500 tokens a task, against a cap of exactly 500.
            by_tokens = FakeHarbor(tokens=490)
            self.assertEqual(runner(settings(Path(tmp), ["a", "b", "c"], n_concurrent=1, max_tokens=500), by_tokens).run(), 3)
            self.assertEqual(by_tokens.waves, [["a"]], "reached is enough: it did not wait to exceed it")
        with tempfile.TemporaryDirectory() as tmp:
            by_dollars = FakeHarbor(cost=0.5)
            self.assertEqual(runner(settings(Path(tmp), ["a", "b", "c"], n_concurrent=1, max_tokens=None, max_usd=0.5), by_dollars).run(), 3)
            self.assertEqual(by_dollars.waves, [["a"]])

    def test_finishing_the_last_task_over_the_cap_is_not_a_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = runner(settings(Path(tmp), ["a"], max_tokens=1), FakeHarbor(tokens=5000)).run()
            self.assertEqual(code, 0)
            self.assertFalse((Path(tmp) / "out" / "STOPPED.txt").exists())


class NoProgress(unittest.TestCase):
    def test_a_harbor_that_leaves_no_results_is_not_repeated_for_ever(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeHarbor(writes=False)
            code = runner(settings(Path(tmp), ["a", "b"]), fake).run()
            self.assertEqual(code, 3)
            self.assertEqual(len(fake.waves), 2)
            self.assertIn("produced no trial results", (Path(tmp) / "out" / "STOPPED.txt").read_text())


class ReadingResults(unittest.TestCase):
    def test_a_job_level_result_a_torn_file_and_a_trial_with_no_reward_are_each_handled(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "jobs" / "j" / "a__1").mkdir(parents=True)
            (out / "jobs" / "j" / "a__1" / "result.json").write_text('{"task_name": "a", "trial_name": "a__1", "verifier_result": null}')
            (out / "jobs" / "j" / "b__1").mkdir(parents=True)
            (out / "jobs" / "j" / "b__1" / "result.json").write_text('{"task_name": "b", "trial_na')  # cut mid-write
            (out / "jobs" / "j" / "result.json").write_text('{"id": "job-level"}')
            (out / "jobs" / "j" / "c__1").mkdir(parents=True)
            (out / "jobs" / "j" / "c__1" / "result.json").write_text('{"task_name": "c", "trial_name": "c__1", "verifier_result": {"rewards": {"reward": 0.5}}}')
            found = rb.scan_trials(out)
            self.assertEqual(sorted(found), ["a", "c"])
            self.assertEqual(found["a"][0].status, "errored", "never judged")
            self.assertEqual(found["c"][0].status, "failed", "below 1 is a failure")


class Tasks(unittest.TestCase):
    def test_a_fixed_task_list_a_limit_and_an_include_all_work_and_are_sorted(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            reg = registry(tmp_path, ["delta", "alpha", "charlie", "bravo"])
            listing = tmp_path / "list.txt"
            listing.write_text("# fixed list\ncharlie\n\nalpha\n")
            self.assertEqual(rb.load_tasks(DATASET, reg, tmp_path / "o1", None, None, None), ["alpha", "bravo", "charlie", "delta"])
            (tmp_path / "o2").mkdir()
            self.assertEqual(rb.load_tasks(DATASET, reg, tmp_path / "o2", None, listing, None), ["alpha", "charlie"])
            (tmp_path / "o3").mkdir()
            self.assertEqual(rb.load_tasks(DATASET, reg, tmp_path / "o3", ["delta", "bravo"], None, None), ["bravo", "delta"])
            (tmp_path / "o4").mkdir()
            self.assertEqual(rb.load_tasks(DATASET, reg, tmp_path / "o4", None, None, 2), ["alpha", "bravo"])
            listing.write_text("alpha\nmissing\n")
            with self.assertRaisesRegex(rb.Refused, "not in ds@1.0: missing"):
                rb.load_tasks(DATASET, reg, tmp_path / "o2", None, listing, None)


class Arguments(unittest.TestCase):
    def test_a_path_to_harbor_is_kept_whole_even_with_backslashes_and_spaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            program = Path(tmp) / "my tools" / "harbor.exe"
            program.parent.mkdir()
            program.write_text("")
            s = rb.parse(["--dataset", DATASET, "--model", "m/x", "--out", tmp, "--hn-package", tmp, "--hn-helpers", tmp, "--harbor", str(program)])
            self.assertEqual(s.harbor, [str(program)], "shlex would have eaten the backslashes of a Windows path")

    def test_parsing_builds_the_settings_a_person_asked_for(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = rb.parse(["--dataset", DATASET, "--model", "anthropic/claude-opus-5-5", "--out", tmp, "--hn-package", tmp, "--hn-helpers", tmp, "--max-usd", "10", "--include", "a,b", "--harbor", "python -m harbor", "--tasks", "3"])
            self.assertEqual((s.max_usd, s.include, s.harbor, s.limit, s.n_concurrent, s.retries), (10.0, ["a", "b"], ["python", "-m", "harbor"], 3, 4, 1))


if __name__ == "__main__":
    unittest.main()
