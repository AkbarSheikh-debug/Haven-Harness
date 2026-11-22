# Team audit: who did what, who approved it, and is the record whole

[Team mode](team-mode.md) puts every decision in a keyed hash chain on the broker. This page is for the people who have to
**read** that chain: a security team, or an outside auditor. You can search it, see each approval as one line, follow it
live, and take an export away and check it **offline**, without trusting the people who run the broker.

It is built on the same idea as the [session replay screen](replay.md), but across a whole team, and from the broker's
record rather than one machine's log.

## What the broker's audit holds

Each row is one decision the broker made: a login, a session started, a model call (who, which model, what it cost), a
model call refused (and why), an approval asked, decided, used or refused, a refused token, an anchor that went backwards,
and every time someone read the audit.

It does **not** hold what an agent did on someone's laptop. The broker never sees a session's commands, files or
conversation. It sees one thing about each session: the *head* of that session's own audit chain, which the session sends
as it writes (an "anchor"). That is enough to catch a laptop's record that has been cut, as below, but it is not the
record itself. For one session's content you need that session's log (see [`hn audit check-session`](#check-one-laptops-session-against-the-broker)
and the [replay screen](replay.md)).

## Who may read it

Nobody, until the signed policy names them. Add a `readers` list to a layer of the policy tree and sign a new serial:

```json
"org": { "version": 1, "name": "org", "audit": { "readers": { "roles": ["auditor"], "users": ["dana@example.com"] } } }
```

- A person is a reader if the layers that name readers include them (a lower layer can only narrow, as everywhere in
  policy). Silence means no, unlike approvers.
- Reading needs your **login** token (from `hn login`). The token a running agent session holds is refused, so a
  model-driven session can never read the team's audit.
- Every read, export and live follow is itself a row: who looked, and the filter they used. A refused attempt is a row too.

## Day to day

```bash
hn login https://broker.example.com            # once; a reader, as named in the policy

hn audit search --user ana@example.com --type broker/model --since 2026-11-21T00:00:00Z
hn audit approvals                               # one line per approval: asked, by whom, decided by whom, used or refused
hn audit approvals --state pending --user cy@example.com
hn audit sessions --user ana@example.com         # model calls, cost, and the head each session anchored
hn audit tail                                    # follow it live; --from <row> resumes with no gap and no repeat
hn serve --audit --pub audit-public.pem          # the same, in a browser on your own machine
```

Search is by person, session, type prefix and time. There is no free-text search of row contents. Pages are at most 500
rows; follow `--after <row>`. Everything printed has hidden characters (a right-to-left override, a zero-width space, a
terminal escape) written out as `\u{...}` instead of acted on, because some of the text in a row was chosen by the person
it is about (an approval's action text, for example).

`hn serve --audit` is a loopback-only page like the replay screen: a token on your terminal, an HttpOnly cookie, strict
headers, read-only. The broker serves no web page at all. Your login token stays on your machine and never reaches the
browser.

## Taking an export away and checking it

The audit key is symmetric: whoever holds it can write rows that look genuine. So an export is checked with two things.

1. **The rows**, linked by the key. The operator gives the auditor the key for the engagement.
2. **Checkpoints**, signed by the broker with an Ed25519 key whose public half the auditor keeps. The broker signs the head
   of the chain every 100 rows, every minute while rows are being added, whenever an export is made, and when it stops.
   A key holder can still write rows, but cannot write a signed head, and the head depends on every row before it.

The operator, once the broker has run:

```bash
hn broker audit-key <the broker's state folder> ./for-the-auditor
# writes audit-public.pem and audit.key. Tell the auditor the key id by another channel (a call, a signed message),
# and give them audit.key only for the checking.
```

The auditor:

```bash
hn audit pin ./audit-pins --pub audit-public.pem        # keeps the key and the checkpoints the broker has signed so far
hn audit export --out audit-2026-11.json                # the whole chain, or --from/--to
hn audit verify audit-2026-11.json --key-file audit.key --pub audit-public.pem --pins audit-pins/pins.jsonl
```

`verify` needs no login and no network. It exits non-zero, and names the row, when:

| The export has | Result |
|---|---|
| a row edited | refused: that row |
| a row removed, moved or repeated (even with the header changed to match) | refused |
| its end cut off (with or without the broker's old signed word left in) | refused |
| rows added or rewritten by someone who holds the audit key | refused: the new head is not signed |
| a checkpoint signed by another key, or edited | refused |
| the wrong audit key or the wrong public key | refused |
| a *filtered view* instead of an export | never "verified": it says it is a subset |
| an end before a checkpoint you pinned, or a row that disagrees with one | refused |

`pin` never replaces the key it already holds. If the broker's signing key is not the one you were given or pinned, it
stops and tells you; it also refuses if the broker now signs a different head for a row it signed before.

### What a verified export proves, and what it does not

- **It proves** the rows are the ones the broker had when it signed the head, that none were edited, removed, reordered or
  added after, and (with pins) that the broker has not rewritten history since your last visit.
- **It does not prove** the broker was honest before it signed, or that rows outside the exported range are unchanged. A
  broker that is compromised can sign anything from then on. Pin often; the pins are what make a later rewrite visible.
- **It does not prove** anything about what happened on a laptop. The broker only records its own decisions.
- The audit key lets its holder forge *rows*, so hand it only to the auditor, for the check. The signed checkpoints are what
  stop a holder from passing off rows the broker never had.
- Exports are limited to 50,000 rows each; export a longer chain in ranges (`--from`, `--to`).
- Rotating the audit-signing key is built (see [key rotation](key-rotation.md)): `hn broker rotate-audit-key` retires the key at
  a row, a root-signed roster lists each key with the rows it signed for, and an auditor who pinned the root
  (`hn audit pin <folder> --root ...`, `hn audit verify ... --trust <folder>`) follows it. Without a root, the single pinned key still
  works for a broker that never rotated; losing or replacing the key without a roster breaks the checks for older exports.

## Check one laptop's session against the broker

A session in team mode sends the head of its own audit chain to the broker as it writes (best effort: an unreachable
broker never stops a tool call). If a laptop's copy is cut, rewritten or replaced, it no longer matches:

```bash
hn audit check-session ~/.hn/audit/<session id>.jsonl --user ana@example.com --key-file <ana's log.key>
```

| Result | Meaning |
|---|---|
| `MATCH` | the file ends exactly where the broker last saw the session, and that row is the same |
| `AHEAD` | the row the broker saw is the same; the file has more after it (the newest rows may not have been sent yet) |
| `BEHIND` | the file ends before the broker's last anchor: rows were removed from the end, and it says how many |
| `DIFFERS` | the row the broker saw is not the same: the file was rewritten |
| `UNKNOWN` | the broker never saw this session; a cut tail cannot be ruled out |
| `REFUSED` | the file does not verify with that key at all |

The file's own chain is checked with the key from the person's laptop (`log.key`), so you need that person's cooperation, or
their machine. The broker cannot check it alone.

## Following a session live in the replay screen

```bash
hn serve --replay --follow
```

opens the newest session and keeps it up to date. Each refresh checks the **whole** log again from its first record, so a
forged record anywhere turns the screen to REFUSED and nothing from it is sent. A record still being written is waited for
(it is not shown, and not called forged). The part already shown must not change: a log that gets shorter, or tells a
different story about steps you were already shown, is refused too. Logs over 32 MB are not followed live; open them again
when the session has ended.

## Tested, and not tested

Every attack on this page is in the [attack catalog](attacks.md), with the test that proves it (names starting `audit_`,
`laptop_audit_` and `followed_log_`). The auditor screen is tested in a real Chrome (search, approvals, a live row, an
export check, an approval written to look like markup and script, shown as the characters it is); it has not been run in
any other browser. Nothing here has been reviewed by anyone outside the project.
