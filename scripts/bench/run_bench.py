"""Score Haven Harness on a Harbor dataset with one command.

    python scripts/bench/run_bench.py --dataset terminal-bench@2.0 --model anthropic/claude-opus-5-5 \\
        --hn-package dist/haven-harness-0.9.0.tgz --hn-helpers dist/helpers --out runs/tb2-opus --max-usd 150

What it guarantees, each of which has a test:

* It does not run without a spend cap (``--max-usd`` or ``--max-tokens``), and it checks the cap between waves, so it
  can be passed by at most one wave. A cap in dollars needs a model with a price: when the cost comes back unknown it
  stops after the first wave and says so, instead of spending without a limit.
* It resumes. A task that has a trial the verifier judged is never run again; a task whose trial errored is retried up
  to ``--retries`` times and then stays errored. Run it again with the same ``--out`` after a crash and it carries on.
* It reads every trial's ``result.json`` and never trusts Harbor's exit code, which is 0 even when a trial failed to
  start. A task is ``passed`` (reward 1), ``failed`` (judged, below 1) or ``errored`` (never judged), and the report
  keeps them apart: an error is not a failure.
* It waits for Docker's engine to be ready before each wave (the first answer to ``docker version`` can come a few
  seconds before the Linux pipe is ready, and a run started then fails in three seconds with exit code 0).
* The report names exactly what was run: hn's package hash, Harbor's and the dataset's versions, the model, the date,
  the command, and what the container boundary was.

Exit code: 0 every task was judged; 1 some errored; 2 refused to start; 3 stopped at the spend cap.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

NOT_FOUND = 127  # what a shell answers for a program that is not there
PINNED_HARBOR = "0.25.0"
REGISTRY_URL = "https://raw.githubusercontent.com/laude-institute/harbor/main/registry.json"
HERE = Path(__file__).resolve().parent

CONTAINER_STATEMENT = (
    "hn ran unattended inside Harbor's task container, which was its only boundary; hn does not verify it. It ran with "
    "--benchmark-container, capped at dont-ask with the allow list bash, write_file and edit_file, never yolo. The model "
    "key was present in hn's process environment, as with any agent in a benchmark container."
)


class Refused(Exception):
    """The run was refused before it started, with a reason a person can act on."""


@dataclass
class Trial:
    task: str
    trial: str
    status: str  # passed | failed | errored
    reward: float | None
    exception: str | None
    input_tokens: int | None
    cache_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    hn_end: str | None
    job: str


@dataclass
class Totals:
    tokens: int = 0
    dollars: float | None = 0.0
    cost_known: bool = True

    def add(self, trial: Trial) -> None:
        self.tokens += (trial.input_tokens or 0) + (trial.output_tokens or 0)
        if trial.cost_usd is None:
            if (trial.input_tokens or 0) + (trial.output_tokens or 0) > 0:
                self.cost_known = False
                self.dollars = None
        elif self.dollars is not None:
            self.dollars += trial.cost_usd


# ----------------------------------------------------------------------------------------------------- reading results


def read_trial(path: Path, job: str) -> Trial | None:
    """A trial's result.json as a Trial, or None when it is not one (a job-level result, a partial write)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or "task_name" not in data or "trial_name" not in data:
        return None
    verifier = data.get("verifier_result")
    rewards = verifier.get("rewards") if isinstance(verifier, dict) else None
    reward = None
    if isinstance(rewards, dict) and isinstance(rewards.get("reward"), (int, float)):
        reward = float(rewards["reward"])
    exception = data.get("exception_info")
    agent = data.get("agent_result") or {}
    meta = agent.get("metadata") or {}
    status = "errored" if reward is None else ("passed" if reward >= 1.0 else "failed")
    return Trial(
        task=str(data["task_name"]),
        trial=str(data["trial_name"]),
        status=status,
        reward=reward,
        exception=exception.get("exception_type") if isinstance(exception, dict) else None,
        input_tokens=agent.get("n_input_tokens"),
        cache_tokens=agent.get("n_cache_tokens"),
        output_tokens=agent.get("n_output_tokens"),
        cost_usd=agent.get("cost_usd"),
        hn_end=meta.get("hn_end") if isinstance(meta, dict) else None,
        job=job,
    )


def scan_trials(out: Path) -> dict[str, list[Trial]]:
    """Every trial under out/jobs, by task, oldest job first."""
    found: dict[str, list[Trial]] = {}
    jobs = out / "jobs"
    if not jobs.is_dir():
        return found
    for job in sorted(path for path in jobs.iterdir() if path.is_dir()):
        for result in sorted(job.glob("*/result.json")):
            trial = read_trial(result, job.name)
            if trial is not None:
                found.setdefault(trial.task, []).append(trial)
    return found


def settled(trials: list[Trial], retries: int) -> Trial | None:
    """The trial that stands for a task, or None when the task still has to run: the latest judged trial, or the latest
    errored one once its retries are spent."""
    judged = [trial for trial in trials if trial.status != "errored"]
    if judged:
        return judged[-1]
    return trials[-1] if len(trials) > retries else None


# ------------------------------------------------------------------------------------------------------- preflight


def docker_ready(run: Callable[[list[str]], int], sleep: Callable[[float], None], timeout_s: float = 180, step_s: float = 5) -> None:
    """Waits until `docker info` answers, or refuses."""
    waited = 0.0
    while True:
        code = run(["docker", "info", "--format", "{{.ServerVersion}}"])
        if code == 0:
            return
        if code == NOT_FOUND:
            raise Refused("Docker was not found. Install Docker, start it, and run this again; finished tasks are kept.")
        if waited >= timeout_s:
            raise Refused(f"Docker's engine did not answer within {int(timeout_s)} s. Start Docker Desktop and run this again; finished tasks are kept.")
        sleep(step_s)
        waited += step_s


def load_tasks(dataset: str, registry_file: Path | None, out: Path, include: list[str] | None, task_list: Path | None, limit: int | None) -> list[str]:
    """The tasks to score, sorted by name, and the registry they came from kept beside the results."""
    name, _, version = dataset.partition("@")
    if not version:
        raise Refused(f"The dataset must name its version, like terminal-bench@2.0, so the run says what it scored (got {dataset!r}).")
    text = registry_file.read_text(encoding="utf-8") if registry_file is not None else urllib.request.urlopen(REGISTRY_URL, timeout=60).read().decode("utf-8")  # noqa: S310 - a pinned https URL
    out.mkdir(parents=True, exist_ok=True)
    saved = out / "registry.json"
    if not saved.exists():
        saved.write_text(text, encoding="utf-8")
    entries = [entry for entry in json.loads(text) if entry.get("name") == name and str(entry.get("version")) == version]
    if len(entries) != 1:
        raise Refused(f"The registry has {len(entries)} entries for {dataset}; it must have exactly one.")
    names = sorted(str(task["name"]) for task in entries[0]["tasks"])
    if task_list is not None:
        wanted = [line.strip() for line in task_list.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        unknown = sorted(set(wanted) - set(names))
        if unknown:
            raise Refused(f"These tasks are not in {dataset}: {', '.join(unknown)}.")
        names = sorted(set(wanted))
    if include:
        unknown = sorted(set(include) - set(names))
        if unknown:
            raise Refused(f"These tasks are not in {dataset}: {', '.join(unknown)}.")
        names = sorted(set(include))
    return names[:limit] if limit is not None else names


# ------------------------------------------------------------------------------------------------------------ the run


@dataclass
class Settings:
    dataset: str
    model: str
    out: Path
    hn_package: Path
    hn_helpers: Path
    base_url: str | None = None
    window: int | None = None
    n_concurrent: int = 4
    wave: int | None = None
    retries: int = 1
    max_usd: float | None = None
    max_tokens: int | None = None
    harbor: list[str] = field(default_factory=lambda: ["harbor"])
    registry_file: Path | None = None
    include: list[str] | None = None
    task_list: Path | None = None
    limit: int | None = None
    allow_other_harbor: bool = False
    extra_harbor_args: list[str] = field(default_factory=list)


def harbor_command(settings: Settings, job: str, tasks: list[str]) -> list[str]:
    command = [
        *settings.harbor, "run", "-d", settings.dataset, "--agent", "harbor_agent:HavenHarnessAgent", "-m", settings.model,
        "--ak", f"hn_package={settings.hn_package}", "--ak", f"hn_helpers={settings.hn_helpers}",
        "-n", str(settings.n_concurrent), "-o", str(settings.out / "jobs"), "--job-name", job, "-y", "-q",
    ]
    if settings.base_url is not None:
        command += ["--ak", f"hn_base_url={settings.base_url}"]
    if settings.window is not None:
        command += ["--ak", f"hn_window={settings.window}"]
    for task in tasks:
        command += ["-i", task]
    return [*command, *settings.extra_harbor_args]


class Runner:
    def __init__(self, settings: Settings, run: Callable[..., int] | None = None, sleep: Callable[[float], None] = time.sleep, env: dict[str, str] | None = None, now: Callable[[], datetime] | None = None) -> None:
        self.s = settings
        self._run = run or self._subprocess_run
        self._sleep = sleep
        self._env = dict(os.environ if env is None else env)
        self._now = now or (lambda: datetime.now(timezone.utc))

    def _subprocess_run(self, command: list[str], capture: bool = False, env: dict[str, str] | None = None) -> int:
        try:
            return subprocess.run(command, env=env or self._env, stdout=subprocess.DEVNULL if not capture else None, stderr=subprocess.DEVNULL if not capture else None, check=False).returncode  # noqa: S603
        except FileNotFoundError:
            return NOT_FOUND

    def check(self) -> None:
        s = self.s
        if s.max_usd is None and s.max_tokens is None:
            raise Refused("Give a spend cap: --max-usd or --max-tokens. This never runs without one.")
        for cap, name in ((s.max_usd, "--max-usd"), (s.max_tokens, "--max-tokens")):
            if cap is not None and cap <= 0:
                raise Refused(f"{name} must be above zero.")
        if s.model.startswith("anthropic/") and not self._env.get("ANTHROPIC_API_KEY"):
            raise Refused("ANTHROPIC_API_KEY is not set, and the model needs it. Use a key made for this run, with a spend cap, and revoke it afterwards.")
        for path, what in ((s.hn_package, "--hn-package"), (s.hn_helpers, "--hn-helpers")):
            if not path.exists():
                raise Refused(f"{what} {path} does not exist.")
        version = self.harbor_version()
        if version != PINNED_HARBOR and not s.allow_other_harbor:
            raise Refused(f"Harbor {version} is installed, but this run is pinned to {PINNED_HARBOR} so a score names the tool that made it. Install {PINNED_HARBOR}, or pass --allow-other-harbor and the report will say so.")

    def harbor_version(self) -> str:
        try:
            done = subprocess.run([*self.s.harbor, "--version"], capture_output=True, text=True, check=False)  # noqa: S603
        except FileNotFoundError as missing:
            raise Refused(f"Harbor was not found ({' '.join(self.s.harbor)}). Install it, or give its path with --harbor.") from missing
        return (done.stdout or "").strip().split()[-1] if done.returncode == 0 and (done.stdout or "").strip() else "unknown"

    def over_cap(self, totals: Totals) -> str | None:
        s = self.s
        if s.max_tokens is not None and totals.tokens >= s.max_tokens:
            return f"the token cap of {s.max_tokens} was reached ({totals.tokens} used)"
        if s.max_usd is not None:
            if not totals.cost_known:
                return "the cost of this model is unknown (it has no price), so --max-usd cannot be enforced; give prices in hn's prices.json, or use --max-tokens"
            if (totals.dollars or 0) >= s.max_usd:
                return f"the cap of ${s.max_usd:.2f} was reached (${totals.dollars:.4f} spent)"
        return None

    def run(self) -> int:
        s = self.s
        self.check()
        s.out.mkdir(parents=True, exist_ok=True)
        tasks = load_tasks(s.dataset, s.registry_file, s.out, s.include, s.task_list, s.limit)
        started = self._now()
        stop: str | None = None
        empty_waves = 0
        wave_size = s.wave or s.n_concurrent
        wave_number = len([p for p in (s.out / "jobs").glob("wave-*")]) if (s.out / "jobs").is_dir() else 0
        while True:
            by_task = scan_trials(s.out)
            totals = self.totals(by_task)
            stop = self.over_cap(totals)
            todo = [task for task in tasks if settled(by_task.get(task, []), s.retries) is None]
            if stop is not None and todo:
                break
            stop = None
            if not todo:
                break
            wave = todo[:wave_size]
            wave_number += 1
            try:
                docker_ready(lambda command: self._run(command), self._sleep)
            except Refused as refusal:
                stop = str(refusal)
                break
            job = f"wave-{wave_number:04d}"
            print(f"[{job}] {len(wave)} task(s): {', '.join(wave)}", flush=True)
            before = {task: len(by_task.get(task, [])) for task in wave}
            # Harbor's exit code says nothing about the trials, so it is not looked at: the results are.
            self._run(harbor_command(s, job, wave), env=self._env)
            after = scan_trials(s.out)
            # A wave that left no trial result behind (Harbor could not start, the adapter would not import) must not
            # be repeated for ever: two in a row stop the run, and the job folder says why.
            if any(len(after.get(task, [])) > before[task] for task in wave):
                empty_waves = 0
            else:
                empty_waves += 1
                if empty_waves >= 2:
                    stop = f"Harbor produced no trial results in the last {empty_waves} waves; look in {s.out / 'jobs'} for why"
                    break
            self.progress(tasks)
        by_task = scan_trials(s.out)
        report = self.report(tasks, by_task, started, stop)
        (s.out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (s.out / "report.md").write_text(render_markdown(report), encoding="utf-8")
        # The marker describes this run only: a resume that finishes must not leave an earlier run's stop behind.
        (s.out / "STOPPED.txt").unlink(missing_ok=True)
        if stop is not None:
            (s.out / "STOPPED.txt").write_text(stop + "\n", encoding="utf-8")
            print(f"Stopped: {stop}", flush=True)
            return 3
        return 0 if report["counts"]["errored"] == 0 and report["counts"]["not_run"] == 0 else 1

    def totals(self, by_task: dict[str, list[Trial]]) -> Totals:
        totals = Totals()
        for trials in by_task.values():
            for trial in trials:
                totals.add(trial)
        return totals

    def progress(self, tasks: list[str]) -> None:
        by_task = scan_trials(self.s.out)
        done = sum(1 for task in tasks if settled(by_task.get(task, []), self.s.retries) is not None)
        tmp = self.s.out / "progress.json.part"
        tmp.write_text(json.dumps({"tasks": len(tasks), "settled": done, "updated": self._now().isoformat()}) + "\n", encoding="utf-8")
        tmp.replace(self.s.out / "progress.json")

    def report(self, tasks: list[str], by_task: dict[str, list[Trial]], started: datetime, stop: str | None) -> dict[str, Any]:
        s = self.s
        rows = []
        counts = {"passed": 0, "failed": 0, "errored": 0, "not_run": 0}
        for task in tasks:
            trials = by_task.get(task, [])
            standing = settled(trials, s.retries) or (trials[-1] if trials else None)
            if standing is None:
                counts["not_run"] += 1
                rows.append({"task": task, "status": "not_run"})
                continue
            counts[standing.status] += 1
            rows.append({"task": task, "status": standing.status, "reward": standing.reward, "exception": standing.exception, "tokens_in": standing.input_tokens, "tokens_out": standing.output_tokens, "cost_usd": standing.cost_usd, "hn_end": standing.hn_end, "trials": len(trials), "trial": standing.trial})
        totals = self.totals(by_task)
        package = s.hn_package
        return {
            "what": {
                "dataset": s.dataset,
                "model": s.model,
                "harbor": self.harbor_version(),
                "harbor_pinned": PINNED_HARBOR,
                "hn_package": package.name,
                "hn_package_sha256": hashlib.sha256(package.read_bytes()).hexdigest() if package.is_file() else None,
                "hn_commit": git_commit(),
                "started": started.isoformat(),
                "finished": self._now().isoformat(),
                "command": shlex.join(sys.argv),
                "base_url": s.base_url,
                "window": s.window,
                "n_concurrent": s.n_concurrent,
                "retries": s.retries,
                "caps": {"max_usd": s.max_usd, "max_tokens": s.max_tokens},
                "container_boundary": CONTAINER_STATEMENT,
            },
            "counts": counts,
            "tasks_in_set": len(tasks),
            # Passed over every task in the set: an errored or unrun task is not a pass.
            "score": counts["passed"] / len(tasks) if tasks else 0.0,
            "tokens": totals.tokens,
            "cost_usd": totals.dollars if totals.cost_known else None,
            "stopped": stop,
            "tasks": rows,
        }


def git_commit() -> str | None:
    """The commit this script comes from, with `-dirty` when the tree has changes, or None outside a checkout.
    Git refuses to read a repository owned by another account (a reinstalled Windows, a copied folder); the exception is
    named for this one folder only, for two read-only questions."""
    root = HERE.parents[1]
    base = ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root)]
    try:
        sha = subprocess.run([*base, "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()  # noqa: S603
        dirty = subprocess.run([*base, "status", "--porcelain"], capture_output=True, text=True, check=False).stdout.strip()  # noqa: S603
    except OSError:
        return None
    return f"{sha}{'-dirty' if dirty else ''}" if sha else None


def render_markdown(report: dict[str, Any]) -> str:
    what, counts = report["what"], report["counts"]
    cost = "unknown (a model has no price)" if report["cost_usd"] is None else f"${report['cost_usd']:.2f}"
    lines = [
        f"# {what['dataset']} with {what['model']}",
        "",
        f"**Score: {counts['passed']} of {report['tasks_in_set']} tasks passed ({report['score']:.1%}).** "
        f"{counts['failed']} failed, {counts['errored']} errored (never judged), {counts['not_run']} not run. Cost {cost}, {report['tokens']} tokens.",
        "",
        f"Run {what['started'][:10]} with Harbor {what['harbor']}, hn package {what['hn_package']} (sha256 {what['hn_package_sha256']}), commit {what['hn_commit']}.",
        "",
        f"> {what['container_boundary']}",
        "",
    ]
    if report["stopped"]:
        lines += [f"**Stopped early:** {report['stopped']}", ""]
    lines += ["| Task | Result | Reward | Tokens in/out | Cost | Note |", "|---|---|---|---|---|---|"]
    for row in report["tasks"]:
        note = row.get("exception") or row.get("hn_end") or ""
        used_tokens = (row.get("tokens_in") or 0) + (row.get("tokens_out") or 0)
        cost_cell = f"${row['cost_usd']:.4f}" if row.get("cost_usd") is not None else ("unknown" if used_tokens > 0 else "")
        lines.append(f"| {row['task']} | {row['status']} | {'' if row.get('reward') is None else row['reward']} | {row.get('tokens_in') or ''}/{row.get('tokens_out') or ''} | {cost_cell} | {note} |")
    return "\n".join(lines) + "\n"


def parse(argv: list[str]) -> Settings:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dataset", required=True, help="name@version, for example terminal-bench@2.0")
    p.add_argument("--model", required=True, help="provider/model: anthropic/..., ollama/..., openai-compatible/...")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--hn-package", required=True, type=Path)
    p.add_argument("--hn-helpers", required=True, type=Path)
    p.add_argument("--base-url")
    p.add_argument("--window", type=int)
    p.add_argument("--n-concurrent", type=int, default=4)
    p.add_argument("--wave", type=int, help="tasks per wave (default: --n-concurrent); the cap is checked between waves")
    p.add_argument("--retries", type=int, default=1, help="extra tries for a task whose trial errored")
    p.add_argument("--max-usd", type=float)
    p.add_argument("--max-tokens", type=int)
    p.add_argument("--harbor", default="harbor", help="the Harbor command (may have arguments)")
    p.add_argument("--registry", type=Path, help="a local registry.json instead of downloading it")
    p.add_argument("--include", help="comma-separated task names")
    p.add_argument("--task-list", type=Path, help="a file with one task name per line")
    p.add_argument("--tasks", type=int, help="run only the first N tasks, by name")
    p.add_argument("--allow-other-harbor", action="store_true")
    a = p.parse_args(argv)
    return Settings(
        dataset=a.dataset, model=a.model, out=a.out.resolve(), hn_package=a.hn_package.resolve(), hn_helpers=a.hn_helpers.resolve(),
        base_url=a.base_url, window=a.window, n_concurrent=a.n_concurrent, wave=a.wave, retries=a.retries, max_usd=a.max_usd,
        max_tokens=a.max_tokens, harbor=[a.harbor] if Path(a.harbor).exists() else shlex.split(a.harbor, posix=os.name != "nt"), registry_file=a.registry, include=a.include.split(",") if a.include else None,
        task_list=a.task_list, limit=a.tasks, allow_other_harbor=a.allow_other_harbor,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        settings = parse(sys.argv[1:] if argv is None else argv)
        # The adapter module lives beside this script, and Harbor imports it by name.
        os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, [str(HERE), os.environ.get("PYTHONPATH")]))
        return Runner(settings).run()
    except Refused as refusal:
        print(f"Refused: {refusal}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
