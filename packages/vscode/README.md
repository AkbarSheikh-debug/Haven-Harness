# Haven Harness for VS Code

Ask the Haven Harness agent to work on the folder you have open. Each change it wants to make opens in VS Code's own diff editor, and nothing is written until you press **Allow once**.

## What you need

- `hn` installed (see the Haven Harness README). The extension starts `hn acp` itself; it does not bundle a copy.
- A folder you have **trusted**. Haven Harness reads instruction files, skills and hooks from the folder, which are text from whoever wrote it, so the extension does nothing in an untrusted folder.

## Commands

Open the command palette and type `hn`.

| Command | What it does |
|---|---|
| hn: Ask the agent | Asks for a task. The answer streams into the **hn** output panel. |
| hn: Start a new session | Starts a fresh session in the open folder. |
| hn: Resume a session | Continues an earlier session by its id (shown in the output panel). |
| hn: Stop the running turn | Cancels the turn that is running. Any approval still waiting counts as a no. |
| hn: Close hn | Ends the `hn` process. |
| hn: Show the session output | Opens the output panel. |

## What you are asked, and what is shown

- **A file change** opens in the diff editor, with the whole file before and after (or only the changed part for a very large file, and the title says so). The question has one button, **Allow once**. Closing the question, pressing Escape or anything else is a no.
- **Hidden characters** (a right-to-left override, a zero-width space, a control character) in what you are shown are written out as `\u{202e}`, never removed, so a diff cannot read differently from what is written.
- **Other actions** (a command, a fetch) are described in the question; there is no file change to compare.
- The **status bar** says where the session runs. In this version a session runs with no box: the permission gate and your approvals are the boundary. It says so.

## Settings

All three are read only from **your own user settings**, never from a folder's `.vscode/settings.json`, because a folder you opened must not choose what program runs or where your code and prompts are sent.

| Setting | Meaning |
|---|---|
| `hn.path` | The `hn` command. Default `hn`. |
| `hn.model` | The model to ask for. Empty uses hn's default. |
| `hn.baseUrl` | A model server, for example a local Ollama. Empty uses hn's default. |

## What it does not do

It has no web view and draws no HTML. It does not send your editor's MCP servers to the agent (hn uses only the ones in your own `~/.hn/mcp.json`). It does not give the agent access to your editor's files or terminals. It never offers "always allow".
