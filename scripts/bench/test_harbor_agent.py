"""Tests for the Harbor adapter, with a fake environment that records every command. Needs Harbor installed:

    <python with harbor> -m unittest discover -s scripts/bench -p "test_*.py"
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import harbor_agent
from harbor.models.agent.context import AgentContext

RESULT = {
    "sessionId": "s1",
    "end": "done",
    "steps": 3,
    "text": "all done",
    "cost": {
        "total": {"input": 300, "output": 30, "cacheRead": 700, "cacheWrite": 100, "cacheHitRatio": 0.636, "dollars": 0.0123, "unpriced": []},
        "byRole": [
            {"role": "main", "input": 200, "output": 20, "cacheRead": 700, "cacheWrite": 100, "cacheHitRatio": 0.7, "dollars": 0.01, "unpriced": []},
            {"role": "scout", "input": 100, "output": 10, "cacheRead": 0, "cacheWrite": 0, "cacheHitRatio": 0, "dollars": 0.0023, "unpriced": []},
        ],
        "byModel": [
            {"model": "claude-opus-5-5", "input": 200, "output": 20, "cacheRead": 700, "cacheWrite": 100, "cacheHitRatio": 0.7, "dollars": 0.01, "unpriced": []},
            {"model": "claude-haiku-5-5", "input": 100, "output": 10, "cacheRead": 0, "cacheWrite": 0, "cacheHitRatio": 0, "dollars": 0.0023, "unpriced": []},
        ],
        "prices": {"source": "built-in", "checked": None, "models": []},
    },
}


class FakeEnvironment:
    """Records what the adapter runs, and answers `cat` of the result and exit-code files."""

    def __init__(self, result_text: str | None = None, exit_code: str = "0", stderr: str = "", has_node: bool = False, machine: str = "x86_64") -> None:
        self.has_node, self.machine = has_node, machine
        self.calls: list[dict] = []
        self.uploads: list[tuple[str, str]] = []
        self._answers = {"hn-result.json": result_text or "", "hn-exit-code": exit_code, "hn-stderr.txt": stderr}
        self.default_user = None

    async def exec(self, command: str, cwd=None, env=None, timeout_sec=None, user=None):
        self.calls.append({"command": command, "env": dict(env or {}), "user": user})
        if command == harbor_agent.NODE_OK:
            return SimpleNamespace(stdout="", stderr="", return_code=0 if self.has_node else 1)
        if command == "uname -m":
            return SimpleNamespace(stdout=f"{self.machine}\n", stderr="", return_code=0)
        for name, text in self._answers.items():
            if name in command and (command.lstrip().startswith("cat") or command.lstrip().startswith("tail")):
                return SimpleNamespace(stdout=text, stderr="", return_code=0)
        return SimpleNamespace(stdout="", stderr="", return_code=0)

    async def upload_file(self, source, target):
        self.uploads.append((str(source), target))

    async def upload_dir(self, source, target):
        self.uploads.append((str(source), target))


def make_agent(tmp: str, model: str = "openai-compatible/fake", **kwargs) -> harbor_agent.HavenHarnessAgent:
    package = Path(tmp) / "haven-harness-0.9.0.tgz"
    package.write_bytes(b"not really a tarball")
    helpers = Path(tmp) / "helpers"
    helpers.mkdir(exist_ok=True)
    options = {"hn_package": str(package), "hn_helpers": str(helpers)}
    if model.startswith("openai"):
        options["hn_base_url"] = "http://host.docker.internal:9999/v1"
    options.update(kwargs)
    return harbor_agent.HavenHarnessAgent(logs_dir=Path(tmp) / "logs", model_name=model, **options)


def run(coro):
    return asyncio.run(coro)


class ModelFlags(unittest.TestCase):
    def test_each_route_gets_the_flags_hn_expects(self):
        self.assertEqual(harbor_agent.hn_model_args("anthropic/claude-opus-5-5", None, None), ["--model", "claude-opus-5-5"])
        self.assertEqual(harbor_agent.hn_model_args("ollama/qwen3:14b", "http://host.docker.internal:11434", 32000), ["--model", "ollama/qwen3:14b", "--base-url", "http://host.docker.internal:11434", "--window", "32000"])
        self.assertEqual(harbor_agent.hn_model_args("openai-compatible/qwen", "http://h:1/v1", None), ["--model", "qwen", "--base-url", "http://h:1/v1"])

    def test_a_model_hn_cannot_reach_is_refused_before_any_container_starts(self):
        for model, base, message in [
            (None, None, "A model is required"),
            ("claude-opus-5-5", None, "provider/model"),
            ("mystery/model", None, "No hn route"),
            ("openai-compatible/x", None, "needs --ak hn_base_url"),
            ("anthropic/claude-opus-5-5", "http://x/v1", "reached directly"),
        ]:
            with self.assertRaisesRegex(ValueError, message):
                harbor_agent.hn_model_args(model, base, None)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "No hn route"):
                make_agent(tmp, "mystery/model")
            with self.assertRaisesRegex(ValueError, "hn_package"):
                harbor_agent.HavenHarnessAgent(logs_dir=Path(tmp) / "l", model_name="anthropic/claude-opus-5-5")
            with self.assertRaisesRegex(FileNotFoundError, "hn_package"):
                harbor_agent.HavenHarnessAgent(logs_dir=Path(tmp) / "l", model_name="anthropic/claude-opus-5-5", hn_package=str(Path(tmp) / "nope.tgz"), hn_helpers=tmp)


class ContextFromResult(unittest.TestCase):
    def test_fills_harbors_context_with_input_counted_the_way_harbor_counts_it(self):
        context = AgentContext()
        self.assertTrue(harbor_agent.context_from_result("noise first\n" + json.dumps(RESULT) + "\n", context))
        self.assertEqual(context.n_input_tokens, 300 + 700 + 100, "harbor's input includes the cache")
        self.assertEqual(context.n_cache_tokens, 700)
        self.assertEqual(context.n_output_tokens, 30)
        self.assertAlmostEqual(context.cost_usd, 0.0123)
        self.assertEqual(sorted(context.model_usage), ["claude-haiku-5-5", "claude-opus-5-5"])
        self.assertEqual(context.model_usage["claude-opus-5-5"].n_input_tokens, 1000)
        self.assertEqual([row["role"] for row in context.metadata["cost_by_role"]], ["main", "scout"])
        self.assertEqual(context.metadata["hn_end"], "done")

    def test_an_unknown_price_stays_unknown_and_is_never_zero(self):
        unpriced = json.loads(json.dumps(RESULT))
        unpriced["cost"]["total"]["dollars"] = None
        unpriced["cost"]["total"]["unpriced"] = ["fake"]
        unpriced["cost"]["byModel"][0]["dollars"] = None
        context = AgentContext()
        self.assertTrue(harbor_agent.context_from_result(json.dumps(unpriced), context))
        self.assertIsNone(context.cost_usd)
        self.assertIsNone(context.model_usage["claude-opus-5-5"].cost_usd)
        self.assertEqual(context.metadata["cost_unpriced_models"], ["fake"])

    def test_anything_that_is_not_a_result_is_not_one(self):
        for text in ["", "   \n", "not json", "{}", json.dumps({"end": "done"}), json.dumps({"cost": {"total": 5}}), "[1,2]"]:
            context = AgentContext()
            self.assertFalse(harbor_agent.context_from_result(text, context), repr(text))
            self.assertTrue(context.is_empty(), repr(text))


class RunningHn(unittest.TestCase):
    INSTRUCTION = 'Fix "it"; $(touch /tmp/pwned) `id` && rm -rf / # and a newline\nsecond line'

    def run_agent(self, model: str, env_key: str | None = None, **env_kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            agent = make_agent(tmp, model)
            environment = FakeEnvironment(**env_kwargs)
            context = AgentContext()
            with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": env_key} if env_key else {}, clear=False):
                if env_key is None:
                    os.environ.pop("ANTHROPIC_API_KEY", None)
                error = None
                try:
                    run(agent.run(self.INSTRUCTION, environment, context))
                except Exception as exc:  # noqa: BLE001 - the tests look at which one
                    error = exc
            return environment, context, error

    def test_runs_hn_unattended_with_the_narrow_claim_and_an_explicit_allow_list(self):
        environment, context, error = self.run_agent("openai-compatible/fake", result_text=json.dumps(RESULT))
        self.assertIsNone(error)
        command = environment.calls[0]["command"]
        for flag in ["--json", "--benchmark-container", "--model fake", "--base-url http://host.docker.internal:9999/v1"]:
            self.assertIn(flag, command)
        # The two flags that cap what hn may do are compared exactly, not as substrings: a longer allow list or another
        # mode must fail here, because they are the safety limit on an unattended run.
        words = shlex.split(command.split(" > ")[0])
        self.assertEqual(words[words.index("--allow") + 1], "bash,write_file,edit_file")
        self.assertEqual(words[words.index("--mode") + 1], "dont-ask")
        self.assertEqual(words.count("--allow"), 1)
        self.assertEqual(words.count("--mode"), 1)
        self.assertNotIn("yolo", command)
        self.assertNotIn("--external-sandbox", command)
        env = environment.calls[0]["env"]
        self.assertEqual(env["HN_BENCH_CONTAINER"], "1")
        self.assertEqual(env["HN_HOME"], harbor_agent.HN_HOME)
        self.assertEqual(context.n_output_tokens, 30)
        self.assertEqual(context.metadata["hn_exit_code"], 0)

    def test_the_instruction_travels_in_the_environment_and_never_inside_the_shell_line(self):
        environment, _, _ = self.run_agent("openai-compatible/fake", result_text=json.dumps(RESULT))
        self.assertEqual(environment.calls[0]["env"]["HN_INSTRUCTION"], self.INSTRUCTION)
        self.assertIn('hn -p "$HN_INSTRUCTION"', environment.calls[0]["command"])
        for hostile in ["pwned", "rm -rf", "second line", "`id`"]:
            self.assertNotIn(hostile, environment.calls[0]["command"], "the task text must not be part of the shell command")

    def test_the_model_key_is_in_the_environment_only_and_only_for_a_model_that_needs_it(self):
        environment, _, error = self.run_agent("anthropic/claude-opus-5-5", env_key="sk-ant-TEST-SECRET", result_text=json.dumps(RESULT))
        self.assertIsNone(error)
        self.assertEqual(environment.calls[0]["env"]["ANTHROPIC_API_KEY"], "sk-ant-TEST-SECRET")
        self.assertNotIn("TEST-SECRET", environment.calls[0]["command"])
        self.assertNotIn("--base-url", environment.calls[0]["command"])
        local, _, _ = self.run_agent("openai-compatible/fake", env_key="sk-ant-TEST-SECRET", result_text=json.dumps(RESULT))
        self.assertNotIn("ANTHROPIC_API_KEY", local.calls[0]["env"], "a local or compatible model is never handed the Anthropic key")

    def test_a_model_that_needs_a_key_refuses_to_start_without_one(self):
        _, _, error = self.run_agent("anthropic/claude-opus-5-5", env_key=None, result_text=json.dumps(RESULT))
        self.assertIsInstance(error, ValueError)
        self.assertIn("ANTHROPIC_API_KEY", str(error))

    def test_a_run_that_ended_badly_is_still_judged_but_one_that_never_started_is_an_error(self):
        # hn exit 1 (failed) with a result: the verifier judges what it left behind.
        _, context, error = self.run_agent("openai-compatible/fake", result_text=json.dumps({**RESULT, "end": "max_turns"}), exit_code="1")
        self.assertIsNone(error)
        self.assertEqual(context.metadata["hn_exit_code"], 1)
        self.assertEqual(context.metadata["hn_end"], "max_turns")
        # hn refused to start (no result at all): that must not look like the model failing the task.
        _, _, error = self.run_agent("openai-compatible/fake", result_text="", exit_code="2", stderr="--benchmark-container needs a user-level allow entry")
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("hn did not work on the task (exit 2)", str(error))
        self.assertIn("allow entry", str(error))

    def install(self, tmp: str, **env):
        agent = make_agent(tmp, hn_cache=str(Path(tmp) / "cache"))
        environment = FakeEnvironment(**env)
        tarball = Path(tmp) / "node.tar.gz"
        tarball.write_bytes(b"node")
        with mock.patch.object(harbor_agent.HavenHarnessAgent, "ensure_system_dependencies", new=mock.AsyncMock()), mock.patch.object(harbor_agent, "verified_node_tarball", return_value=tarball) as node:
            run(agent.install(environment))
        return environment, node

    def test_install_uploads_node_the_package_and_helpers_and_sets_up_the_operators_allow_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            environment, node = self.install(tmp)
            self.assertEqual([target for _, target in environment.uploads], [f"{harbor_agent.INSTALL_DIR}/node.tar.gz", f"{harbor_agent.INSTALL_DIR}/haven-harness.tgz", f"{harbor_agent.INSTALL_DIR}/helpers"])
            node.assert_called_once()
            self.assertEqual(node.call_args.args[0], "x64")
            joined = "\n".join(call["command"] for call in environment.calls)
            self.assertIn("npm install -g", joined)
            self.assertIn(f"hn setup --from {harbor_agent.INSTALL_DIR}/helpers", joined)
            self.assertIn("benchmark-container-allowed", joined)
            for fetched in ("github.com", "curl", "wget", "apt-get", "nodejs.org"):
                self.assertNotIn(fetched, joined, f"the container fetches nothing itself ({fetched})")

    def test_an_image_that_already_has_a_new_enough_node_gets_none_uploaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            environment, node = self.install(tmp, has_node=True)
            node.assert_not_called()
            self.assertNotIn(f"{harbor_agent.INSTALL_DIR}/node.tar.gz", [target for _, target in environment.uploads])

    def test_an_arm_container_gets_the_arm_build_and_an_unknown_machine_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, node = self.install(tmp, machine="aarch64")
            self.assertEqual(node.call_args.args[0], "arm64")
            with self.assertRaisesRegex(RuntimeError, "no pinned Node build"):
                self.install(tmp, machine="riscv64")

    def test_a_task_image_whose_package_archive_is_gone_does_not_stop_the_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = make_agent(tmp, hn_cache=str(Path(tmp) / "cache"))
            environment = FakeEnvironment(has_node=True)
            broken = mock.AsyncMock(side_effect=RuntimeError("Command failed (exit 100): apt-get install git: 404 Not Found"))
            with mock.patch.object(harbor_agent.HavenHarnessAgent, "ensure_system_dependencies", new=broken):
                run(agent.install(environment))
            self.assertTrue(any("npm install -g" in call["command"] for call in environment.calls), "it carried on to install hn")


class NodeInstall(unittest.TestCase):
    PAYLOAD = b"a pretend node tarball"

    def pinned(self):
        return mock.patch.dict(harbor_agent.NODE_SHA256, {"x64": hashlib.sha256(self.PAYLOAD).hexdigest()})

    def test_the_pinned_hashes_are_sha256_for_both_architectures_from_the_official_gz_builds(self):
        self.assertEqual(sorted(harbor_agent.NODE_SHA256), ["arm64", "x64"])
        for digest in harbor_agent.NODE_SHA256.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(harbor_agent.node_url("x64"), f"https://nodejs.org/dist/v{harbor_agent.NODE_VERSION}/node-v{harbor_agent.NODE_VERSION}-linux-x64.tar.gz")
        self.assertIn("tar -xzf", harbor_agent.NODE_UNPACK, "gz needs only tar and gzip, which every image has")

    def test_a_download_is_checked_on_the_host_and_kept_only_when_it_matches(self):
        with tempfile.TemporaryDirectory() as tmp, self.pinned():
            cache = Path(tmp) / "cache"
            fetched: list[str] = []
            path = harbor_agent.verified_node_tarball("x64", cache, lambda url: (fetched.append(url), self.PAYLOAD)[1])
            self.assertEqual(path.read_bytes(), self.PAYLOAD)
            self.assertEqual(len(fetched), 1)
            harbor_agent.verified_node_tarball("x64", cache, lambda url: self.fail("a good cache entry is not downloaded again"))

    def test_a_download_with_the_wrong_hash_is_refused_and_not_kept(self):
        with tempfile.TemporaryDirectory() as tmp, self.pinned():
            cache = Path(tmp) / "cache"
            with self.assertRaisesRegex(RuntimeError, "not the pinned .* so it was refused"):
                harbor_agent.verified_node_tarball("x64", cache, lambda url: b"something else")
            self.assertFalse(cache.exists() and any(cache.iterdir()), "nothing unverified is left behind")

    def test_a_tampered_cache_entry_is_not_trusted_and_is_replaced(self):
        with tempfile.TemporaryDirectory() as tmp, self.pinned():
            cache = Path(tmp) / "cache"
            path = harbor_agent.verified_node_tarball("x64", cache, lambda url: self.PAYLOAD)
            path.write_bytes(b"swapped after the download")
            again = harbor_agent.verified_node_tarball("x64", cache, lambda url: self.PAYLOAD)
            self.assertEqual(again.read_bytes(), self.PAYLOAD)
            path.write_bytes(b"swapped again")
            with self.assertRaises(RuntimeError):
                harbor_agent.verified_node_tarball("x64", cache, lambda url: b"and the new download is wrong too")

    def test_an_architecture_without_a_pinned_build_and_a_download_from_anywhere_else_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "No pinned Node build"):
                harbor_agent.verified_node_tarball("riscv64", Path(tmp), lambda url: b"")
        for url in ["http://nodejs.org/x", "https://evil.example/node.tar.gz", "https://nodejs.org.evil.example/x", "file:///etc/passwd"]:
            with self.assertRaisesRegex(ValueError, "only downloaded from https://nodejs.org/"):
                harbor_agent._download(url)


if __name__ == "__main__":
    unittest.main()
