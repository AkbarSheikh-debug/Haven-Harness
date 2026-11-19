"""Haven Harness as a Harbor agent.

Run it with Harbor's import path, so Harbor itself is never patched::

    PYTHONPATH=scripts/bench harbor run -d terminal-bench@2.0 \\
        --agent harbor_agent:HavenHarnessAgent -m anthropic/claude-opus-5-5 \\
        --ak hn_package=dist/haven-harness-0.9.0.tgz --ak hn_helpers=dist/helpers

``hn_package`` is the npm tarball from ``scripts/pack-npm.ts`` and ``hn_helpers`` the folder of signed ``hn-sandbox``
files from ``scripts/sandbox-manifest.ts``. The package pins its own signing key; the helper is verified against it
by ``hn setup --from`` exactly as on any machine. Nothing is downloaded from GitHub, so no release has to exist.

How hn is trusted here (see docs/guide/benchmarks.md): the benchmark container is the only boundary, and
hn cannot verify it from inside. It runs with ``--benchmark-container``, which needs an allow entry in hn's home, the
variable ``HN_BENCH_CONTAINER=1`` and a process that really is in a Linux container, and which caps the run at
``dont-ask`` with an explicit allow list, never yolo. Results say so.

The model key (ANTHROPIC_API_KEY, only for an Anthropic model) is given to hn in its process environment and is never
written to a file. Measured in a real container on 2026-11-19: hn removes it from everything it starts, so the model's
own commands do not see it in ``env`` or in their own process environment, and it is in no result or session log. **It
is still in hn's own starting environment, which a model that goes looking can read from /proc/<pid>/environ** (as hn's
own source says, on Linux a process's starting environment stays readable). Every agent installed in a benchmark
container has this exposure. Use a key made for the benchmark, with a spend cap, and revoke it afterwards.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from harbor.agents.installed.base import BaseInstalledAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext, ModelUsage

# Node is fetched once on the host and checked against a pinned hash there, then uploaded into the container: the
# task image's package manager and network are not needed, which matters because some images are old (the two qemu
# tasks are Debian 11, whose package archive no longer serves curl or git). The .tar.gz build is used because it
# needs only tar and gzip, which every image has. These are the SHA-256 of node-v24.22.3-linux-<arch>.tar.gz from
# https://nodejs.org/dist/v24.22.3/SHASUMS256.txt (LTS, released 2026-11-10).
NODE_VERSION = "24.22.3"
NODE_SHA256 = {
    "x64": "061ec3e3062115705b56b51fa9cc330ab50d34b6969387d4e4b1a50c6809acc2",
    "arm64": "261af2af250dfd7e9f25cf151d1b2713a0adf8f10a9ad116c4947f68627affe8",
}
NODE_ARCH = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}


def node_url(arch: str) -> str:
    return f"https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-linux-{arch}.tar.gz"


def verified_node_tarball(arch: str, cache_dir: Path, download: Callable[[str], bytes] | None = None) -> Path:
    """The Node tarball for this architecture on the host, downloaded once and checked against the pinned hash. A copy
    in the cache is checked again every time it is used, and a download that does not match is refused and not kept."""
    if arch not in NODE_SHA256:
        raise ValueError(f"No pinned Node build for {arch!r} (have {', '.join(sorted(NODE_SHA256))}).")
    path = cache_dir / f"node-v{NODE_VERSION}-linux-{arch}.tar.gz"
    if path.exists():
        if hashlib.sha256(path.read_bytes()).hexdigest() == NODE_SHA256[arch]:
            return path
        path.unlink()  # a damaged or swapped cache entry is not trusted, and not reused
    data = (download or _download)(node_url(arch))
    got = hashlib.sha256(data).hexdigest()
    if got != NODE_SHA256[arch]:
        raise RuntimeError(f"The Node download for {arch} has SHA-256 {got}, not the pinned {NODE_SHA256[arch]}, so it was refused.")
    cache_dir.mkdir(parents=True, exist_ok=True)
    part = path.with_suffix(".part")
    part.write_bytes(data)
    part.replace(path)
    return path


def _download(url: str) -> bytes:
    if not url.startswith("https://nodejs.org/"):
        raise ValueError("Node is only downloaded from https://nodejs.org/.")
    with urllib.request.urlopen(url, timeout=300) as response:  # noqa: S310 - the scheme and host are checked above
        return response.read()

HN_HOME = "/tmp/hn-home"
INSTALL_DIR = "/tmp/hn-install"
RESULT_FILE = "hn-result.json"

# The tools a benchmark task needs that hn will not run on its own: the shell and the two that change files.
# Reading, searching and listing need no entry.
ALLOW = "bash,write_file,edit_file"


def hn_model_args(model_name: str | None, base_url: str | None, window: int | None) -> list[str]:
    """Harbor names a model ``provider/model``; hn names it by route. Returns hn's flags for it."""
    if not model_name:
        raise ValueError("A model is required: pass -m provider/model (for example anthropic/claude-opus-5-5).")
    provider, _, model = model_name.partition("/")
    if not model:
        raise ValueError(f"The model must be provider/model, got {model_name!r}.")
    if provider == "anthropic":
        if base_url is not None:
            raise ValueError("An Anthropic model is reached directly; hn_base_url applies to ollama and openai-compatible models.")
        args = ["--model", model]
    elif provider == "ollama":
        args = ["--model", f"ollama/{model}"]
    elif provider in ("openai", "openai-compatible"):
        if base_url is None:
            raise ValueError("An openai-compatible model needs --ak hn_base_url=<address>.")
        args = ["--model", model]
    else:
        raise ValueError(f"No hn route for provider {provider!r} (use anthropic, ollama or openai-compatible).")
    if base_url is not None:
        args += ["--base-url", base_url]
    if window is not None:
        args += ["--window", str(window)]
    return args


def context_from_result(text: str, context: AgentContext) -> bool:
    """Fills Harbor's context from hn's ``-p --json`` output. Returns False when there is no usable result."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    try:
        result = json.loads(lines[-1])
        cost = result["cost"]
        total = cost["total"]
        # Harbor counts input tokens including the cache; hn reports fresh input and the cache separately.
        n_input = int(total["input"]) + int(total["cacheRead"]) + int(total["cacheWrite"])
        n_cache = int(total["cacheRead"])
        n_output = int(total["output"])
        # Unknown stays unknown: a model with no price is None, never 0.
        dollars = None if total["dollars"] is None else float(total["dollars"])
        usage = {
            row["model"]: ModelUsage(
                n_input_tokens=int(row["input"]) + int(row["cacheRead"]) + int(row["cacheWrite"]),
                n_cache_tokens=int(row["cacheRead"]),
                n_output_tokens=int(row["output"]),
                cost_usd=None if row["dollars"] is None else float(row["dollars"]),
            )
            for row in cost.get("byModel", [])
        }
        metadata = {
            "hn_end": result.get("end"),
            "hn_steps": result.get("steps"),
            "hn_session": result.get("sessionId"),
            "cost_by_role": cost.get("byRole", []),
            "cost_unpriced_models": total.get("unpriced", []),
            "prices": cost.get("prices"),
        }
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        # Not a result, or a malformed one: nothing is half-filled, and the caller treats it as no result. (Every
        # malformed shape raises one of these first, a list or a string indexed by name being a TypeError, so an
        # AttributeError cannot reach here.)
        return False
    context.n_input_tokens, context.n_cache_tokens, context.n_output_tokens, context.cost_usd = n_input, n_cache, n_output, dollars
    context.model_usage = usage
    context.metadata = metadata
    return True


class HavenHarnessAgent(BaseInstalledAgent):
    """hn, installed from a locally packed npm tarball, run once per task with the task's instruction."""

    DEFAULT_SETUP_TIMEOUT_SEC = 900.0

    def __init__(
        self,
        *args: Any,
        hn_package: str | None = None,
        hn_helpers: str | None = None,
        hn_base_url: str | None = None,
        hn_window: str | int | None = None,
        hn_cache: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        if hn_package is None or hn_helpers is None:
            raise ValueError("Pass --ak hn_package=<haven-harness-x.y.z.tgz> and --ak hn_helpers=<folder of signed hn-sandbox files>.")
        self._package = Path(hn_package).expanduser().resolve()
        self._helpers = Path(hn_helpers).expanduser().resolve()
        for path, what in ((self._package, "hn_package"), (self._helpers, "hn_helpers")):
            if not path.exists():
                raise FileNotFoundError(f"{what} {path} does not exist.")
        self._base_url = hn_base_url
        self._window = None if hn_window is None else int(hn_window)
        # Where the verified Node tarball is kept between runs.
        self._cache_dir = Path(hn_cache).expanduser() if hn_cache else Path.home() / ".cache" / "hn-bench"
        # Validated now, so a bad model fails the job before any container starts.
        hn_model_args(self.model_name, self._base_url, self._window)

    @staticmethod
    def name() -> str:
        return "haven-harness"

    def version(self) -> str | None:
        return self._version

    def get_version_command(self) -> str | None:
        return "hn --version"

    def parse_version(self, stdout: str) -> str:
        return stdout.strip().split()[-1]

    async def install(self, environment: BaseEnvironment) -> None:
        # git is useful to hn where a task is a repository, and never required: an old image's package archive may be
        # gone (two qemu tasks are Debian 11), and that must not stop the run.
        try:
            await self.ensure_system_dependencies(environment, ("git",))
        except Exception as exc:  # noqa: BLE001 - best effort, said and carried on
            self.logger.warning("git could not be installed, continuing without it: %s", str(exc)[:200])
        await self.exec_as_root(environment, command=f"mkdir -p {INSTALL_DIR} && chmod 777 {INSTALL_DIR}")
        if (await environment.exec(command=NODE_OK, user="root")).return_code != 0:
            arch = NODE_ARCH.get(((await environment.exec(command="uname -m", user="root")).stdout or "").strip())
            if arch is None:
                raise RuntimeError("This container's architecture has no pinned Node build.")
            await environment.upload_file(verified_node_tarball(arch, self._cache_dir), f"{INSTALL_DIR}/node.tar.gz")
            await self.exec_as_root(environment, command=NODE_UNPACK)
        await environment.upload_file(self._package, f"{INSTALL_DIR}/haven-harness.tgz")
        await environment.upload_dir(self._helpers, f"{INSTALL_DIR}/helpers")
        await self.exec_as_root(
            environment,
            command=(
                f"chmod -R a+rX {INSTALL_DIR} && "
                f"npm install -g {INSTALL_DIR}/haven-harness.tgz >/tmp/hn-npm.log 2>&1 || (cat /tmp/hn-npm.log; exit 1); "
                'ln -sf "$(npm prefix -g)/bin/hn" /usr/local/bin/hn'
            ),
        )
        # hn's own home, owned by the user the agent runs as: the signed helper, and the operator's allow entry that
        # --benchmark-container requires (a project cannot write here).
        await self.exec_as_agent(
            environment,
            command=f"mkdir -p {HN_HOME} && hn setup --from {INSTALL_DIR}/helpers && touch {HN_HOME}/benchmark-container-allowed",
            env={"HN_HOME": HN_HOME},
        )

    async def run(self, instruction: str, environment: BaseEnvironment, context: AgentContext) -> None:
        env = {"HN_HOME": HN_HOME, "HN_BENCH_CONTAINER": "1", "HN_INSTRUCTION": self.render_instruction(instruction)}
        # The model key goes in the process environment only: hn takes it from there and keeps it out of what the
        # model's commands see, and it is never written to a file.
        provider = (self.model_name or "").partition("/")[0]
        if provider == "anthropic":
            key = self._extra_env.get("ANTHROPIC_API_KEY") or _host_env("ANTHROPIC_API_KEY")
            if key is None:
                raise ValueError("ANTHROPIC_API_KEY is not set, and the model needs it.")
            env["ANTHROPIC_API_KEY"] = key
        flags = shlex.join(["--json", "--benchmark-container", "--mode", "dont-ask", "--allow", ALLOW, *hn_model_args(self.model_name, self._base_url, self._window)])
        logs = str(self.environment_logs_dir)
        # hn's exit code is kept, not raised on: a task hn worked on is judged by what it left behind, whether hn
        # finished, failed, ran out of budget or was refused by its model. What must never pass for a failed task is
        # hn not working on it at all (refused to start, crashed, killed): that has no result, and is raised below.
        await self.exec_as_agent(
            environment,
            command=(
                f'hn -p "$HN_INSTRUCTION" {flags} > {logs}/{RESULT_FILE} 2> {logs}/hn-stderr.txt; '
                f"echo $? > {logs}/hn-exit-code; "
                # hn's own session log (HMAC-chained), kept with the result for the record.
                f"cp -r {HN_HOME}/sessions {logs}/hn-sessions 2>/dev/null; true"
            ),
            env=env,
        )
        code = await self._exit_code(environment, logs)
        # Read through the environment, so this holds whether or not Harbor mounts its log folder on the host.
        result = await environment.exec(command=f"cat {logs}/{RESULT_FILE}")
        if not context_from_result(result.stdout or "", context):
            stderr = await environment.exec(command=f"tail -c 600 {logs}/hn-stderr.txt")
            raise RuntimeError(f"hn did not work on the task (exit {code}): {(stderr.stdout or '').strip()}")
        context.metadata = {**(context.metadata or {}), "hn_exit_code": code}

    async def _exit_code(self, environment: BaseEnvironment, logs: str) -> int | None:
        result = await environment.exec(command=f"cat {logs}/hn-exit-code")
        try:
            return int((result.stdout or "").strip())
        except ValueError:
            return None

    def populate_context_post_run(self, context: AgentContext) -> None:
        path = self.logs_dir / RESULT_FILE
        if path.exists():
            context_from_result(path.read_text(encoding="utf-8", errors="replace"), context)


def _host_env(name: str) -> str | None:
    import os

    return os.environ.get(name)


# Exits 0 when the image already has a Node new enough for hn (24.14 or later), and so needs none uploaded.
NODE_OK = "command -v node >/dev/null 2>&1 && [ \"$(node -p \"(([a,b])=>a>24||(a===24&&b>=14))(process.versions.node.split('.').map(Number))\")\" = true ]"
# Unpacks the uploaded tarball, which the host has already checked against the pinned hash.
NODE_UNPACK = (
    f"set -eu; mkdir -p /opt/node && tar -xzf {INSTALL_DIR}/node.tar.gz -C /opt/node --strip-components=1 && rm {INSTALL_DIR}/node.tar.gz; "
    "ln -sf /opt/node/bin/node /usr/local/bin/node; ln -sf /opt/node/bin/npm /usr/local/bin/npm; ln -sf /opt/node/bin/npx /usr/local/bin/npx"
)
