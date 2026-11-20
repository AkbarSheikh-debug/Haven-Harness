# Haven Harness in VS Code

An extension that lets you ask the Haven Harness agent to work on the folder you have open, and shows every change it
wants to make as a diff, in VS Code's own diff editor, before anything is written. It starts `hn acp` (hn's door for
editors, the Agent Client Protocol) and talks to it over a pipe. It adds no new way for the agent to act: the gate, the
approvals and the limits are hn's own.

## What is and is not verified

- **Verified:** the extension, packed as a `.vsix`, installed into a real **VS Code 1.147.0** with VS Code's own
  installer, driving a real `hn acp` process with a scripted model. On that VS Code: the diff editor shows the exact
  change; the file is written only after **Allow once**; reject, a closed question and a cancelled turn write nothing;
  in a folder you have not trusted VS Code does not run the extension at all; and a folder's own settings file cannot
  change which `hn` runs or which model server is used. CI runs the same tests on Windows, Linux (under a virtual
  display) and macOS, against the same pinned build.
- **Not verified:** any other VS Code version (the manifest asks for `^1.147.0` because that is the only one tested),
  VS Code forks, remote and web editors (the extension does not support virtual or remote workspaces), and the real
  modal's look: the tests answer the question programmatically, because a modal cannot be clicked from a test.
- **Not in this version:** the extension has no box. A session started from the editor runs with the permission gate
  and your approvals as its only boundary (the status bar says "no box"). The verified sandbox is for `hn -p` and the
  command line; see [verified on every OS](sandbox-verified.md).
- **Not published.** There is no Marketplace listing. You build it and install it yourself, as below.

## Install

You need `hn` installed first ([install](install.md)), and a copy of the repository to build from. From the repository:

```
pnpm install --frozen-lockfile
node --disable-proto=throw scripts/pack-vsix.ts --version 0.1.0 --out dist-vsix
code --install-extension dist-vsix/haven-harness-0.1.0.vsix
```

The second command compiles the extension (plain JavaScript, no runtime dependency) and writes the `.vsix`. Two packs of
the same source are byte-identical, and it prints the file's SHA-256 so you can compare it.

## Use

Open a folder and **trust** it when VS Code asks. Then open the command palette and type `hn`:

| Command | What it does |
|---|---|
| hn: Ask the agent | Asks for a task. The answer streams into the **hn** output panel. |
| hn: Start a new session | Starts a fresh session in the open folder. |
| hn: Resume a session | Continues an earlier session by its id (shown in the output panel when it starts). |
| hn: Stop the running turn | Cancels the running turn. An approval still waiting counts as a no. |
| hn: Close hn | Ends the `hn` process. |
| hn: Show the session output | Opens the output panel. |

The status bar item says what state the session is in and where it runs, for example `hn: idle · safe · no box`. Click
it to open the output.

## What you are asked

When the agent wants to change a file, the extension opens VS Code's diff editor on the change and asks one question
with one button, **Allow once**. Closing the question, pressing Escape or anything else is a no.

- For an edit you see the **whole file before and after**. For a file too big to show (over 64,000 characters) you see
  only the changed part, and the question says so; if a side was cut, it says that too.
- For a new file, the left side is empty.
- **Hidden characters are shown, not removed.** A right-to-left override, a zero-width space or a control character in
  the text you are shown is written out as `\u{202e}` and so on. Stripping them would show you text that differs from what
  is written, which is the trick an approval screen exists to stop.
- For other actions (a command, a web fetch) there is no file to compare; the question describes the action.
- "Always allow" is never offered. If an agent offers it anyway, the extension still answers only with the plain
  allow-once or reject option.

After a turn, every tool call is marked `completed` only if it worked. A call you refused, the gate refused or that
failed is marked `failed`.

## Settings

All three are read only from **your own user settings**. A folder's `.vscode/settings.json` cannot set them, because a
folder you just cloned must not choose which program runs or where your code and prompts are sent.

| Setting | Meaning |
|---|---|
| `hn.path` | The `hn` command. Default `hn`. On Windows, the `hn.cmd` that npm makes works; values that could be read as shell syntax are refused. |
| `hn.model` | The model to ask for (`--model`). Empty uses hn's default. |
| `hn.baseUrl` | A model server to use instead of the default (`--base-url`), for example a local Ollama. |

## Why it is built this way

- **No web view.** Nothing the agent writes is ever drawn as HTML, so there is no page for it to script. Output goes to a
  plain output panel.
- **Untrusted folders get nothing.** hn reads instruction files, skills and hooks from the folder, which are text from
  whoever wrote the folder. The extension declares that it does not support untrusted workspaces, so VS Code does not
  load it there, and the code refuses again if asked.
- **The agent is treated as another program.** The extension's end of the pipe drops a malformed or oversized line
  without stopping, shows only text it has stripped or made visible, caps what it shows, answers no request for files or
  terminals (it offers neither), ignores text for sessions it did not open, and never selects an option the agent
  marked as anything but allow-once or reject-once. The attacks this covers are listed, with their tests, in the
  [attack catalog](attacks.md) (names starting `editor_`).
- **Your editor's MCP servers are not sent to the agent.** hn uses only the ones in your own `~/.hn/mcp.json`.
- **No bundled copy of hn.** The extension starts the `hn` you installed and checked; a second copy would be a second
  thing to sign and update.

## Known limits

- One session at a time, in the first workspace folder (or the folder of the file you have open).
- The agent's reasoning text is not shown. Its answers, the tools it calls and their outcome are.
- The approval question names what the agent wants in its own words (the tool's description). The diff beside it is
  built from the arguments that will run, not from the agent's words.
- A very large file the agent replaces in full is shown cut at 64,000 characters, and says so; the whole content is still
  what is written if you allow it.
