# Replay and audit a session

Every hn session writes a log of what happened: each message, each tool the model asked for, the decision the permission
gate made about it, each approval and who answered, each time untrusted text entered the session, and the result. The log
is chained with a secret key (an HMAC over each record and the one before it), so editing, removing, reordering or adding a
record without the key is detected.

`hn serve --replay` opens a screen that steps through any of those logs, one event at a time. It is for the person who has
to answer "what did the agent actually do, and was it allowed to?": a reviewer, a security team, or you the next morning.

## Open it

From the folder the sessions were run in:

```
hn serve --replay
```

hn prints an address and a token. Open the address, paste the token into the login form (it is deliberately not in the
address), and choose a session. This mode starts **no** model session, needs no model key, and can only read: it answers
`GET` requests and nothing else, so there is nothing on the page that can run a command or change a file. Press Ctrl+C to
stop it.

The same screen is part of a normal `hn serve` at `/replay`, behind the same login.

## What you see

- **Whether the log verifies.** A green "Log verified" says the chain over every recorded event checks out. A red
  **REFUSED** says it does not: the log may have been edited, cut, reordered or forged, and *nothing* of it is shown, not even
  the part before the break. A story told from a file that cannot be trusted is worse than none.
- **A summary:** turns, tool calls, how many the gate refused, approvals asked and denied, the files changed, and the step
  at which untrusted input first entered the session.
- **The steps.** Each is one thing that happened. Use the buttons, the slider, the arrow keys (or `j` and `k`), `Home` and
  `End`. **Next refusal** and **Next taint change** jump to the moments that matter. The filters show only gate decisions,
  approvals, taint changes, file changes, commands or refusals.
- **For each step:** what happened, when, and where the text came from (the user, the model, a tool, the web). A gate
  refusal shows which check stopped the call and why. An approval shows who answered: a person, the automatic reviewer, or hn
  itself. Everything that happened to one tool call (the request, the approval, the decision, the result) is linked, so you
  can follow it.
- **A file change as a diff.** An edit shows the text that was replaced and its replacement. A new file or a full rewrite
  shows the new contents, and says that what the file held before was not recorded.
- **The state of the session after each step:** whether untrusted input is in it, whether private data was in reach, the
  mode, where it ran (a verified box, a claimed one, or none, so the gate alone), and the counts of calls, refusals,
  approvals and files so far. Step back across the line where "Untrusted input" changes from *no* to *YES* to see the exact
  moment.

The address contains the session and step (`#<session>:<step>`), so you can send someone the exact moment.

## What is and is not verified

- **Verified:** the replay model against real session logs altered byte by byte, with a frame removed, moved, repeated or
  added, with the wrong key and with a crashed tail; the server over real HTTP (login, Host and Origin checks, read-only,
  session ids that try to leave the folder); and the screen itself in a **real Chrome** (headless): stepping, filters,
  keyboard, the diff, a refused log, and a command written to look like HTML and script, which is shown as the characters it
  is, with no element made, no script run, no dialog opened and nothing fetched from another address. CI runs this on
  Windows, Linux and macOS. The attacks are listed, with their tests, in the [attack catalog](attacks.md) (names starting
  `replay_` and `forged_log_`).
- **Not verified:** any browser other than Chrome (the page uses plain, old features, but it has not been run elsewhere).

## What it can and cannot prove

- **It proves the log was not changed by anything that does not have the key.** The key is `log.key` in your hn folder. The
  model, a sandbox, a tool, a repository or another user cannot change a record without the screen showing REFUSED.
- **It does not prove anything to someone who does not trust the machine.** Whoever holds the key can write a log that
  verifies. A log copied from another computer, with another key, shows as REFUSED here: this screen cannot tell "forged" from
  "made elsewhere". For a team that needs more, the [broker](team-mode.md) keeps its own audit chain with an anchor that
  cannot go back, and [team audit](team-audit.md) shows how an auditor reads and checks it. To watch a running session, start
  with `hn serve --replay --follow` (see that page).
- **A file change made by a shell command is not in "Files changed".** Only the file tools (`write_file`, `edit_file`) are
  listed as file changes. A command that writes a file is in the list of commands, with its text and result.
- **Long text is cut.** A command, result or diff longer than a screenful is shortened for display and says so. A log with
  more than 10,000 steps shows the first 10,000 and says so; a log file over 256 MB is not opened.
- **Hidden characters are written out, not removed.** A right-to-left override, a zero-width space or a control character
  in a command appears as `\u{202e}` and so on, so what you read is what was written.
- It reads logs; it cannot resume, edit, delete or annotate one.

## Related

- `hn report <session id>` writes the same kind of account as markdown, for a pull request.
- [The attack catalog](attacks.md) and the [hall of fame](hall-of-fame.md).
