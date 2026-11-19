# Choosing the model for each role

A session can hand work to sub-agents, each with a role: `scout`, `planner`, `worker`, `reviewer`, or roles of your own. By default the scout runs on a cheap model and the others on the main one. `routing.json` lets you change that, so a cheap or local model can do the reading while a strong one plans and reviews.

Create `~/.hn/routing.json` (or `$HN_HOME/routing.json`):

```json
{
  "cheap": "ollama/qwen3:4b",
  "roles": {
    "planner": "claude-opus-5-5",
    "reviewer": "main"
  }
}
```

| Setting | Meaning |
|---|---|
| `cheap` | The model the `cheap` slot means. The built-in scout uses it, and so does any role you point at `cheap`. Without it, the built-in cheap tier is used. |
| `roles` | A model for a role, by role name. The value is a model name, `main` (the session's own model) or `cheap`. |

A role's model in its own file (`model:` in an agents file) still works. `routing.json` wins over it, role by role.

## What is checked, and when

The file is checked when the session opens. **If anything in it is wrong, the session does not start**, and every problem is listed. Nothing is ignored and no role quietly falls back to another model:

- a setting that is not `cheap` or `roles` (a typo such as `cheep`),
- a role that does not exist (the roles that do are listed),
- a model your policy does not allow, including a team's policy,
- a model the session could not reach. A child inherits its parent's address, so a session on a local Ollama model cannot hand a role to a Claude model, and a session on an OpenAI-compatible address cannot hand one to a Claude or `ollama/` model. A hosted session can use a local `ollama/` model for a role.

The start of the session says what was routed, for example `Model routing from routing.json: cheap = ollama/qwen3:4b, planner = claude-opus-5-5.`

## What it does not do

- **Only your own home folder counts.** A `routing.json` inside a project is ignored, so a repository cannot send your work to a model you did not choose.
- **It changes only which model answers.** A role keeps the tools and mode it has, and a child never holds more than its parent.
- **It does not change summaries.** The model that writes compaction summaries is chosen separately.
- A sub-agent never reads `routing.json`: only the session you opened routes.

The cost of each role is reported by role and model ([what a run cost](cost.md)), so you can see what a routing saved.
