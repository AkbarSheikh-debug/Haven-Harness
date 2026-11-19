# Local Terminal-Bench-format tasks

Five small tasks in the layout Terminal-Bench 2 uses with Harbor: `instruction.md`, `task.toml`, `environment/`,
`tests/`, `solution/`. They are not Terminal-Bench tasks and not Harbor-runnable: Docker is off on the machine this was
built on, and the public tasks are Linux images. These run under `hn bench`, which puts the agent and each test in the
Windows native box. A test writes its reward (0 or 1) to the file `$env:HN_REWARD`, as a Harbor test writes
`/logs/verifier/reward.txt`. `environment/workspace` is the starting folder. `hn bench --oracle` runs
`solution/solve.ps1` instead of the agent, to show each task can be solved and that its test can tell.
