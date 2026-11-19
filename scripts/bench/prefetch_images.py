"""Pull the Docker images of a dataset's tasks ahead of a run.

    python scripts/bench/prefetch_images.py --registry runs/tb2/registry.json --dataset terminal-bench@2.0 --min-free-gb 100

A run spends most of its wall time downloading each task's image before the task starts, and a download is limited by
bandwidth, not by the model. Pulling the images while the agent works on an earlier task overlaps the two. This reads the
image of each task from its task.toml at the exact commit the registry pins, pulls them one at a time, skips what is
already here, and **stops before the disk is low** (``--min-free-gb``), because filling a person's disk is not a price a
benchmark may charge. It only pulls: it runs nothing, and a failed pull is recorded and skipped, not retried for ever.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tomllib
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

RAW = "https://raw.githubusercontent.com"


class Refused(Exception):
    pass


def raw_url(git_url: str, commit: str, path: str) -> str:
    """The raw task.toml of a task, from a github.com repository at a fixed commit. Nothing else is fetched."""
    prefix, suffix = "https://github.com/", ".git"
    if not git_url.startswith(prefix) or not git_url.endswith(suffix):
        raise Refused(f"Only https://github.com/<owner>/<repo>.git task sources are read (got {git_url!r}).")
    repo = git_url[len(prefix):-len(suffix)]
    if not all(part and all(c.isalnum() or c in "-_." for c in part) for part in repo.split("/")) or repo.count("/") != 1:
        raise Refused(f"{repo!r} is not an owner/repository name.")
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise Refused("A task source must be pinned to a full commit id.")
    if not path or path.startswith("/") or ".." in path.split("/"):
        raise Refused(f"{path!r} is not a path inside the repository.")
    return f"{RAW}/{repo}/{commit}/{path}/task.toml"


def image_of(toml_text: str) -> str | None:
    """The prebuilt image a task names, or None when it is built from its own Dockerfile."""
    image = tomllib.loads(toml_text).get("environment", {}).get("docker_image")
    return image if isinstance(image, str) and image else None


def tasks_of(registry_text: str, dataset: str) -> list[dict[str, Any]]:
    name, _, version = dataset.partition("@")
    if not version:
        raise Refused(f"The dataset must name its version, like terminal-bench@2.0 (got {dataset!r}).")
    entries = [entry for entry in json.loads(registry_text) if entry.get("name") == name and str(entry.get("version")) == version]
    if len(entries) != 1:
        raise Refused(f"The registry has {len(entries)} entries for {dataset}; it must have exactly one.")
    return list(entries[0]["tasks"])


def prefetch(
    tasks: list[dict[str, Any]],
    *,
    min_free_gb: float,
    fetch: Callable[[str], str],
    present: Callable[[str], bool],
    pull: Callable[[str], bool],
    free_gb: Callable[[], float],
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    result: dict[str, Any] = {"pulled": [], "already": [], "built_locally": [], "failed": [], "stopped": None}
    for task in sorted(tasks, key=lambda item: item["name"]):
        image = image_of(fetch(raw_url(task["git_url"], task["git_commit_id"], task["path"])))
        if image is None:
            result["built_locally"].append(task["name"])
            continue
        if present(image):
            result["already"].append(image)
            continue
        free = free_gb()
        if free < min_free_gb:
            result["stopped"] = f"free disk is {free:.0f} GB, below the {min_free_gb:.0f} GB kept free; stopped before pulling {image}"
            log(result["stopped"])
            break
        log(f"pulling {image} ({task['name']}), {free:.0f} GB free")
        (result["pulled"] if pull(image) else result["failed"]).append(image)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--min-free-gb", type=float, required=True, help="stop before the free space on the Docker drive falls below this")
    parser.add_argument("--drive", default=str(Path.home().anchor or "/"), help="the drive that holds Docker's images (default: the home drive)")
    parser.add_argument("--out", type=Path, help="write what was pulled, skipped and failed to this JSON file")
    args = parser.parse_args(argv)
    if args.min_free_gb < 10:
        print("Refused: --min-free-gb below 10 would let this fill the disk.", file=sys.stderr)
        return 2

    def fetch(url: str) -> str:
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - raw_url only builds raw.githubusercontent.com urls
            return response.read().decode("utf-8")

    def present(image: str) -> bool:
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False).returncode == 0  # noqa: S603, S607

    def pull(image: str) -> bool:
        return subprocess.run(["docker", "pull", "--quiet", image], capture_output=True, check=False).returncode == 0  # noqa: S603, S607

    try:
        tasks = tasks_of(args.registry.read_text(encoding="utf-8"), args.dataset)
        result = prefetch(tasks, min_free_gb=args.min_free_gb, fetch=fetch, present=present, pull=pull, free_gb=lambda: shutil.disk_usage(args.drive).free / 1e9, log=lambda line: print(line, flush=True))
    except Refused as refusal:
        print(f"Refused: {refusal}", file=sys.stderr)
        return 2
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Pulled {len(result['pulled'])}, already here {len(result['already'])}, built locally {len(result['built_locally'])}, failed {len(result['failed'])}." + (f" Stopped: {result['stopped']}" if result["stopped"] else ""))
    return 1 if result["failed"] or result["stopped"] else 0


if __name__ == "__main__":
    sys.exit(main())
