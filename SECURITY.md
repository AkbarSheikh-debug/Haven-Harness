# Security policy

Haven Harness is a security-focused project, so reports are taken seriously and handled first.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead: go to the repository's **Security** tab and
choose **Report a vulnerability**. Include what you did, what happened, what you expected, and the OS, Node version
and commit you used. A proof of concept helps a great deal.

You should get an acknowledgement within a week. Fixes for confirmed issues are prioritised over new work.

## What happens to a report

1. **Acknowledged** within 7 days, with whether it looks like a real hole or needs more from you.
2. **Confirmed or declined** within 30 days. If it is declined, you get the reason, and you are free to disagree.
3. **Fixed with a test.** Every confirmed hole becomes a named attack in the [attack catalog](docs/guide/attacks.md), with a
   test that fails without the fix, so it cannot quietly come back.
4. **Disclosed together.** We ask you to keep the details private until a fix is released, or for 90 days from your
   report, whichever is first. If a fix is taking longer than that, tell us and we will agree a date with you.

## Credit

Once it is fixed we will ask how you want to be named: by your GitHub name, by a name you choose, or not at all. If you
agree, you are added to the [hall of fame](docs/guide/hall-of-fame.md), with what the hole was, the commit that fixed
it and the test that guards it. We never publish your email address and never list anyone who did not say yes. There is
no money: this is a volunteer project and a credit is what we can give.

## Safe harbour

If you act in good faith, against your own installation, and stay within what this policy describes (you do not access
other people's data, do not degrade a service you do not own, and give us the chance to fix it before you tell anyone
else), we will not take legal action against you and will say so to anyone who asks.

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
