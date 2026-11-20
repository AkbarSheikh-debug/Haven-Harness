# The GitHub Action: a labelled issue becomes a pull request

A maintainer adds a label (default `hn`) to an issue. Haven Harness works on it in a **verified box** and opens a pull
request whose description is a report of exactly what the session did. Nobody can make it run by opening an issue, and
nothing it writes runs in CI until a person has read it.

## What is and is not verified

- **Verified, locally and in CI on all three OSes:** the three stages run in order with real `hn` in its verified native
  box, a scripted model, a fake GitHub and real git repositories. A labelled issue becomes a branch and a pull request
  whose body is the session report; a label from someone without write access runs nothing (the model is never called);
  an issue that steers the model into planting `.github/workflows/evil.yml` ends with no such file in any branch; a
  session that changes nothing opens no pull request. The entry points are run as GitHub runs them (environment
  variables, `GITHUB_OUTPUT`), and the workflow files are checked for the properties below.
- **Not verified:** the Action has **never run on GitHub**. In particular it has not been tried with a real `issues`
  event, with a real model, or against GitHub's real API. Three things rest on GitHub's documentation, not on a test:
  that `GET /repos/{repo}/collaborators/{login}/permission` answers for the workflow's token with only `contents: read`;
  that a pull request opened with the workflow's own token does not start other workflows; and that Ubuntu runners allow
  the sysctl the box needs (`kernel.apparmor_restrict_unprivileged_userns=0`, the same setting this repository's own CI
  uses). **Try it on a throwaway repository, watching, before you rely on it.**
- **Not published.** There is no tagged release and hn is not on npm yet, so the Action builds `hn` from the repository
  at the commit you pin. That is slow (a dependency install and a Rust build) and goes away once there is a signed
  package to install.

## How it is built

Three jobs, so that **the model's job holds no write token**:

| Job | Runs | Token | Does |
|---|---|---|---|
| `gate` | no model, no repository code | `contents: read` | Decides if anything runs at all. |
| `agent` | hn, in a verified box | `contents: read`, no write | Works on the issue; produces a patch and a report as files. |
| `publish` | no model, no command the model chose | `contents`, `pull-requests`, `issues` write | Checks the patch, pushes a branch, opens the pull request. |

A prompt-injected agent therefore cannot push, tag, edit a workflow, or comment: it has nothing to do those with. The
agent job's checkout is made with `persist-credentials: false`, so no token is left in the git config either.

### Who can start it

Only a **label, added by a person with write access** to the repository, on an open issue. The gate asks GitHub for the
labeler's role and accepts `admin`, `maintain` or `write`; any other answer, a role it has never heard of, a bot, and a
failing API (which fails the job loudly) are all refusals. The label's name proves nothing, since people with triage
rights can add labels, and the issue's author and text are nobody's authority.

The gate reads the event from the file GitHub writes. Issue text is **never pasted into a shell command or an
expression**, which is the usual way an issue title becomes code.

### What the model is told

The label is the instruction, and the instruction is fixed text. The issue's title and body come after it, as data, in
a frame the issue cannot close (a `</untrusted>` in the text is made inert), and the whole prompt is given to hn as an
`event`, not as the user's words (`hn -p --prompt-origin event`, which can only lower trust). That keeps the powers that
belong to a person's own typing, such as fetching a URL, away from it, and the session is recorded as having taken in
untrusted input.

### Where it runs

`hn -p --sandbox native`: a verified box on a copy of the project. hn **refuses to start** unless the box passes its
outside-in check (see [verified on every OS](sandbox-verified.md)), so there is no unboxed fallback. The environment hn is
started with holds only the basics and the model key you name: **not** the GitHub token or any other secret.

### What the patch may not touch

The publish job does not believe the patch. It reads it as `git apply` will, and refuses the whole patch (it does not
trim it to something that passes) if it has any of:

- a path under `.github/`, `.githooks/` or `.husky/`, or any `CODEOWNERS`, `.gitmodules`, `.gitattributes`, `.npmrc`,
  `.yarnrc`, `.yarnrc.yml` or `.pnpmfile.cjs`, plus any you add with the `protected-paths` input (a repository that runs
  its own copy of the Action from a local `./action` folder should add that folder);
- a symbolic link, a submodule, an unusual file mode, a binary change, a rename or copy;
- a path inside `.git`, an absolute path, or one that leaves the repository;
- more than 100 files, 10,000 changed lines, or 2 MB.

A refused patch is not dropped silently: the issue gets a comment naming each path and the rule, and the patch stays
attached to the workflow run for a person to read and apply by hand.

hn's own hand-back to the project also holds some files back for a person (such as anything under `.github/workflows/`,
because CI runs those with the repository's secrets). Those are **listed in the pull request description** as changes the
agent made that are not in it.

### The pull request

Titled `hn: resolve #N` (never from the issue's words), made from a branch `hn/issue-N-<run id>`, with the report as the
description. **CI does not run on it automatically**, because GitHub does not start workflows for a pull request opened
with a workflow's own token. Push to the branch, or re-run checks, once you have read the diff.

`hn report <session id>` makes the report from the session's HMAC-chained log: where it ran, the files changed, every
command and its result (a command that was refused is marked "not run"), every call the gate refused and why, and every
approval asked. A log that fails its integrity check is refused and nothing in it is reported. Everything a model or a
file wrote is shown only inside inline code, with backticks and line breaks neutralized and a length cap, so it cannot
become a link, an image, HTML, a heading or an `@name` that notifies someone.

## Set it up

1. Make a model key **for this**, with a spend cap, and add it as the repository secret `ANTHROPIC_API_KEY`. A model that
   goes looking can read its own environment; hn removes the key from everything it starts, but a cap is the real limit.
2. Copy [examples/github-action/hn-issue.yml](../../examples/github-action/hn-issue.yml) to
   `.github/workflows/hn-issue.yml`, and replace each `<commit sha>` with a full commit of Haven Harness that you have
   read. Do not point it at a branch or tag you do not control.
3. Create a label named `hn`. Only people with write access to the repository can make it do anything.

Run `hn report <session id>` yourself to see a report: it prints the markdown the pull request carries (add `--json` for
the structured form).

## Known limits

- The agent runs once per label event. Re-labelling an issue runs it again (a new branch each time); concurrent runs for
  one issue are queued.
- There is no network inside the box, so an issue that needs the agent to download something cannot be resolved by it.
- Cost is the model key's: set the cap. The report shows the cost hn counted; it is not a billing record.
- Merging is never automatic.
