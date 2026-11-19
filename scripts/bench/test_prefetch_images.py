"""Tests for the image prefetch."""

from __future__ import annotations

import unittest

import prefetch_images as pf

COMMIT = "69671fbaac6d67a7ef0dfec016cc38a64ef7a77c"
GIT = "https://github.com/laude-institute/terminal-bench-2.git"


def task(name: str) -> dict:
    return {"name": name, "git_url": GIT, "git_commit_id": COMMIT, "path": name}


def toml(image: str | None) -> str:
    return '[environment]\n' + (f'docker_image = "{image}"\n' if image else 'cpus = 1\n')


class Urls(unittest.TestCase):
    def test_only_a_pinned_github_task_toml_is_ever_fetched(self):
        self.assertEqual(pf.raw_url(GIT, COMMIT, "bn-fit-modify"), f"https://raw.githubusercontent.com/laude-institute/terminal-bench-2/{COMMIT}/bn-fit-modify/task.toml")
        for git, commit, path, why in [
            ("https://evil.example/x/y.git", COMMIT, "a", "Only https://github.com"),
            ("http://github.com/a/b.git", COMMIT, "a", "Only https://github.com"),
            ("https://github.com/a/b", COMMIT, "a", "Only https://github.com"),
            ("https://github.com/a/b/c.git", COMMIT, "a", "owner/repository"),
            ("https://github.com/a b/c.git", COMMIT, "a", "owner/repository"),
            (GIT, "main", "a", "full commit id"),
            (GIT, COMMIT[:-1], "a", "full commit id"),
            (GIT, COMMIT.upper(), "a", "full commit id"),
            (GIT, COMMIT, "../x", "not a path inside"),
            (GIT, COMMIT, "/etc", "not a path inside"),
            (GIT, COMMIT, "", "not a path inside"),
        ]:
            with self.assertRaisesRegex(pf.Refused, why):
                pf.raw_url(git, commit, path)


class Parsing(unittest.TestCase):
    def test_the_image_comes_from_task_toml_and_a_task_with_none_is_built_locally(self):
        self.assertEqual(pf.image_of(toml("alexgshaw/bn-fit-modify:20251031")), "alexgshaw/bn-fit-modify:20251031")
        self.assertIsNone(pf.image_of(toml(None)))
        self.assertIsNone(pf.image_of('[environment]\ndocker_image = ""\n'))
        self.assertIsNone(pf.image_of('[environment]\ndocker_image = 5\n'))
        self.assertIsNone(pf.image_of("version = '1.0'\n"))

    def test_the_dataset_must_name_its_version_and_exist_once(self):
        registry = '[{"name": "tb", "version": "2.0", "tasks": [{"name": "a"}]}]'
        self.assertEqual(pf.tasks_of(registry, "tb@2.0"), [{"name": "a"}])
        with self.assertRaisesRegex(pf.Refused, "name its version"):
            pf.tasks_of(registry, "tb")
        with self.assertRaisesRegex(pf.Refused, "0 entries"):
            pf.tasks_of(registry, "tb@9")


class Pulling(unittest.TestCase):
    def run_prefetch(self, tasks, images, *, have=(), free=500.0, min_free=100.0, failing=()):
        pulled: list[str] = []
        disk = [free]

        def pull(image):
            pulled.append(image)
            disk[0] -= 40  # each image takes 40 GB in this world
            return image not in failing

        result = pf.prefetch(tasks, min_free_gb=min_free, fetch=lambda url: toml(images[url.split("/")[-2]]), present=lambda image: image in have, pull=pull, free_gb=lambda: disk[0], log=lambda line: None)
        return result, pulled

    def test_it_pulls_in_name_order_skips_what_is_here_and_notes_what_is_built_locally(self):
        images = {"a": "img/a", "b": "img/b", "c": None, "d": "img/d"}
        result, pulled = self.run_prefetch([task("d"), task("a"), task("c"), task("b")], images, have=("img/b",))
        self.assertEqual(pulled, ["img/a", "img/d"])
        self.assertEqual((result["pulled"], result["already"], result["built_locally"], result["failed"], result["stopped"]), (["img/a", "img/d"], ["img/b"], ["c"], [], None))

    def test_it_stops_before_the_disk_is_low_and_pulls_nothing_more(self):
        images = {name: f"img/{name}" for name in "abcdef"}
        result, pulled = self.run_prefetch([task(name) for name in "abcdef"], images, free=250.0, min_free=100.0)
        self.assertEqual(pulled, ["img/a", "img/b", "img/c", "img/d"], "250, 210, 170 and 130 GB free were all above the 100 GB kept; 90 was not")
        self.assertIn("below the 100 GB kept free; stopped before pulling img/e", result["stopped"])

    def test_it_never_starts_a_pull_when_the_disk_is_already_below_the_limit(self):
        result, pulled = self.run_prefetch([task("a")], {"a": "img/a"}, free=50.0, min_free=100.0)
        self.assertEqual(pulled, [])
        self.assertIsNotNone(result["stopped"])

    def test_a_failed_pull_is_recorded_and_skipped_not_retried_and_does_not_stop_the_rest(self):
        result, pulled = self.run_prefetch([task("a"), task("b")], {"a": "img/a", "b": "img/b"}, failing=("img/a",))
        self.assertEqual((result["failed"], result["pulled"]), (["img/a"], ["img/b"]))
        self.assertEqual(pulled.count("img/a"), 1)


class Arguments(unittest.TestCase):
    def test_a_free_space_floor_that_would_let_it_fill_the_disk_is_refused(self):
        self.assertEqual(pf.main(["--registry", "x", "--dataset", "tb@2.0", "--min-free-gb", "5"]), 2)


if __name__ == "__main__":
    unittest.main()
