"""Draw a fixed subset of a Harbor dataset, once, by a seed.

    python scripts/bench/draw_tasks.py --registry registry.json --dataset swebench-verified@1.0 --count 50 \\
        --seed haven-harness-phase-10 --out scripts/bench/swebench-verified-50.txt

The draw ranks every task by SHA-256 of ``<seed>:<task name>`` and keeps the first N. It depends on nothing but the seed
and the names, so anyone can regenerate the list and get the same one, and nobody can pick tasks: the list is committed
before any run and is never swapped afterwards (a swap after seeing a failure would make a score mean nothing). The file
records the dataset, the seed, and the SHA-256 of the registry it was drawn from, and ``--check`` verifies a committed
list against them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def draw(names: list[str], count: int, seed: str) -> list[str]:
    """The first ``count`` names ranked by SHA-256 of seed and name, returned sorted by name."""
    if count < 1 or count > len(names):
        raise ValueError(f"The count must be from 1 to {len(names)}, got {count}.")
    if len(set(names)) != len(names):
        raise ValueError("The dataset lists a task name twice.")
    ranked = sorted(names, key=lambda name: hashlib.sha256(f"{seed}:{name}".encode()).hexdigest())
    return sorted(ranked[:count])


def dataset_names(registry_text: str, dataset: str) -> list[str]:
    name, _, version = dataset.partition("@")
    if not version:
        raise ValueError(f"The dataset must name its version, like swebench-verified@1.0 (got {dataset!r}).")
    entries = [entry for entry in json.loads(registry_text) if entry.get("name") == name and str(entry.get("version")) == version]
    if len(entries) != 1:
        raise ValueError(f"The registry has {len(entries)} entries for {dataset}; it must have exactly one.")
    return [str(task["name"]) for task in entries[0]["tasks"]]


def render(tasks: list[str], dataset: str, seed: str, count: int, registry_sha256: str) -> str:
    header = [
        f"# {count} tasks of {dataset}, drawn once by seed and never swapped.",
        f"# seed: {seed}",
        f"# registry sha256: {registry_sha256}",
        "# regenerate: python scripts/bench/draw_tasks.py --registry <registry.json> --dataset " + dataset + f" --count {count} --seed {seed} --out <this file>",
    ]
    return "\n".join([*header, *tasks]) + "\n"


def parse_header(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("# seed: "):
            found["seed"] = line[len("# seed: "):]
        elif line.startswith("# registry sha256: "):
            found["registry"] = line[len("# registry sha256: "):]
        elif line.startswith("# ") and " tasks of " in line:
            found["dataset"] = line.split(" tasks of ", 1)[1].split(",", 1)[0]
            found["count"] = line[2:].split(" ", 1)[0]
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--check", action="store_true", help="verify the existing --out file instead of writing it")
    args = parser.parse_args(argv)
    text = args.registry.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    wanted = render(draw(dataset_names(text, args.dataset), args.count, args.seed), args.dataset, args.seed, args.count, digest)
    if args.check:
        have = args.out.read_text(encoding="utf-8")
        if have == wanted:
            print(f"{args.out} is the draw for seed {args.seed}.")
            return 0
        print(f"{args.out} is NOT the draw for seed {args.seed} from this registry.", file=sys.stderr)
        return 1
    if args.out.exists():
        print(f"{args.out} already exists. A drawn list is never replaced; delete it on purpose, and say why, to draw again.", file=sys.stderr)
        return 2
    args.out.write_text(wanted, encoding="utf-8")
    print(f"Wrote {args.count} tasks to {args.out}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
