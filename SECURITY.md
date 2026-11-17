# Security policy

Haven Harness is a security-focused project, so reports are taken seriously and handled first.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead: go to the repository's **Security** tab and
choose **Report a vulnerability**. Include what you did, what happened, what you expected, and the OS, Node version
and commit you used. A proof of concept helps a great deal.

You should get an acknowledgement within a week. Fixes for confirmed issues are prioritised over new work, and you will
be credited in the fix unless you ask not to be.

## What counts

Anything that lets the agent, a model, a web page, an MCP server, a repository or a child agent get past a boundary
the project claims, for example:

- escaping a verified sandbox, or a sandbox passing the verifier when it should not;
- a tool call that runs without the gate, or with a decision it should not get;
- untrusted text that loses its origin or taint, or that is shown to a person as if the harness wrote it;
- reading or writing outside the project through the file tools;
- reaching a private network, cloud metadata or the host through the egress policy, the browser or a proxy;
- a forged or edited session log that is trusted;
- secrets that reach a log, a model or a child process.

## What does not count

- Anything that needs the attacker to already control your user account.
- Running with no sandbox and a permissive mode, and the agent doing what that mode allows.
- Issues in third-party models or services themselves.

## Supported versions

The project is early: only the latest commit on `main` is supported.
