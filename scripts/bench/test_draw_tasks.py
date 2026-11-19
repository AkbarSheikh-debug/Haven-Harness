"""Tests for the seeded task draw."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import draw_tasks as dt

NAMES = [f"repo__issue-{n}" for n in range(1, 101)]


def registry(names: list[str] = NAMES) -> str:
    return json.dumps([{"name": "swe", "version": "1.0", "tasks": [{"name": n} for n in names]}, {"name": "other", "version": "1.0", "tasks": [{"name": "zzz"}]}])


class Draw(unittest.TestCase):
    def test_the_same_seed_gives_the_same_tasks_in_any_order_the_dataset_lists_them(self):
        first = dt.draw(NAMES, 10, "seed-a")
        self.assertEqual(first, dt.draw(list(reversed(NAMES)), 10, "seed-a"))
        self.assertEqual(first, sorted(first), "returned sorted by name")
        self.assertEqual(len(set(first)), 10)

    def test_another_seed_gives_another_draw_and_nobody_can_choose(self):
        self.assertNotEqual(dt.draw(NAMES, 10, "seed-a"), dt.draw(NAMES, 10, "seed-b"))
        # The ranking is the hash and nothing else: a task's place does not depend on which others are in the list.
        ranked = sorted(NAMES, key=lambda n: hashlib.sha256(f"seed-a:{n}".encode()).hexdigest())
        self.assertEqual(dt.draw(NAMES, 10, "seed-a"), sorted(ranked[:10]))

    def test_a_count_out_of_range_and_a_duplicated_name_are_refused(self):
        for count in (0, -1, 101):
            with self.assertRaises(ValueError):
                dt.draw(NAMES, count, "s")
        with self.assertRaisesRegex(ValueError, "twice"):
            dt.draw(["a", "a", "b"], 1, "s")

    def test_the_dataset_must_name_its_version_and_exist_once(self):
        self.assertEqual(len(dt.dataset_names(registry(), "swe@1.0")), 100)
        with self.assertRaisesRegex(ValueError, "name its version"):
            dt.dataset_names(registry(), "swe")
        with self.assertRaisesRegex(ValueError, "0 entries"):
            dt.dataset_names(registry(), "swe@9")


class Files(unittest.TestCase):
    def run_main(self, tmp: Path, *extra: str) -> int:
        return dt.main(["--registry", str(tmp / "registry.json"), "--dataset", "swe@1.0", "--count", "5", "--seed", "s1", "--out", str(tmp / "list.txt"), *extra])

    def test_it_writes_a_list_that_records_where_it_came_from_and_never_replaces_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "registry.json").write_text(registry())
            self.assertEqual(self.run_main(path), 0)
            text = (path / "list.txt").read_text()
            header = dt.parse_header(text)
            self.assertEqual((header["seed"], header["dataset"], header["count"]), ("s1", "swe@1.0", "5"))
            self.assertEqual(header["registry"], hashlib.sha256(registry().encode()).hexdigest())
            self.assertEqual(len([line for line in text.splitlines() if line and not line.startswith("#")]), 5)
            self.assertEqual(self.run_main(path), 2, "an existing list is not replaced")
            self.assertEqual((path / "list.txt").read_text(), text)

    def test_check_passes_for_the_real_draw_and_fails_for_a_swapped_task_or_another_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "registry.json").write_text(registry())
            self.run_main(path)
            self.assertEqual(self.run_main(path, "--check"), 0)
            lines = (path / "list.txt").read_text().splitlines()
            swapped = [("repo__issue-1" if line == lines[-1] and not line.startswith("#") else line) for line in lines]
            (path / "list.txt").write_text("\n".join(swapped) + "\n")
            self.assertEqual(self.run_main(path, "--check"), 1, "one swapped task is caught")
            (path / "list.txt").write_text("\n".join(lines) + "\n")
            (path / "registry.json").write_text(registry(NAMES[:-1] + ["repo__a-new-task"]))
            self.assertEqual(self.run_main(path, "--check"), 1, "a different registry is not the same draw")


if __name__ == "__main__":
    unittest.main()
