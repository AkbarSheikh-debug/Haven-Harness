# Replacing and revoking signing keys

Three keys in Haven Harness sign things other people trust:

| Key | Signs | Who trusts it |
|---|---|---|
| **Release key** | the package, the update archives, the sandbox helper's manifest | every installed copy, on every start and every `hn update` |
| **Policy key** | the team policy the broker serves | the broker, and each laptop at the start of every `--team` session |
| **Audit-signing key** | the broker's audit checkpoints | an auditor checking an export offline |

Until now each was trusted for ever once pinned. This page is about replacing one on a schedule, and about what to do when one leaks.

## The idea: a root key signs a roster

Next to the signing keys there is a **root key**. It signs nothing else. It lives offline (a USB stick, a safe, a laptop that is never online), and it is used a few times a year.

The root signs a **roster** for each purpose: a short, signed list of the signing keys trusted for that purpose and the keys that are revoked. A machine pins the root once and then follows rosters. That is the whole design, and it is built on one rule: **a signing key can never change what is trusted.** If any signing key could add or revoke keys, a thief with the leaked key would revoke the good ones and add their own.

A roster is checked against the root the machine **already** pins. It never brings its own root. These always hold:

- the serial only goes up; an older roster, or a different one with the same serial, is refused;
- a revoked key can never be trusted again, by its id or by its public key under a new id: a replacement needs a new key;
- every roster leaves at least one key that can sign;
- every purpose has its own roster; a policy roster is refused where a release roster is asked for.

Each machine keeps what it knows in a small record (`<home>/trust/<purpose>.trust.json`, with a MAC under a key only that machine holds). If that record is edited or damaged, hn **refuses** instead of falling back to the keys the package shipped, because the fallback would quietly forget a revocation.

## Set it up once

```bash
hn trust keygen-root ./root          # writes root-key.pem (keep it offline) and root-public.pem; prints a suggested root id
```

Then, for each purpose, write a draft and sign it. A draft names keys by file:

```json
{
  "purpose": "release",
  "serial": 1,
  "keys": [{ "keyId": "rel-2026", "publicKeyFile": "release-key.pub.pem" }],
  "revoked": []
}
```

```bash
hn trust sign draft.json ./root/root-key.pem root-1 roster.json
```

| Purpose | Where the root and roster go |
|---|---|
| **release** | `node scripts/release.ts ... --root root-public.pem --root-id root-1 --roster roster.json` (and the same three flags for `scripts/pack-npm.ts`) put `RELEASE-ROOT.json` and `RELEASE-ROSTER.json` in the package. A release built without them behaves exactly as before. |
| **policy** | in `broker.json`, `policy.root` is `{ "keyId": "root-1", "publicKey": "<PEM>" }`; the signed roster is the file `policy-roster.json` in the broker's state folder (or `policy.roster`). Laptops pin the root the **first** time they log in. After you add a root to an existing broker, each person runs `hn logout` and `hn login` once (a broker you are already logged in to cannot hand you a new root). |
| **audit** | the roster is `audit-roster.json` in the broker's state folder. The auditor pins the root: `hn audit pin <folder> --root root-public.pem`. |

## A routine rotation

**Release or policy key.** Make the new key. Sign a roster (serial up by one) that lists both keys. Put it where the purpose says: for a release, beside the archive as `<archive name>.roster.json` (or `hn update <archive> --roster <file>`), or `hn trust update <roster file or https URL>` on each machine; for policy, replace `policy-roster.json` and reload the broker. Laptops pick it up at their next session. Once everyone has it, sign the next policy or release with the new key, and in a later roster leave the old key out.

**Audit key.** Stop the broker, then:

```bash
hn broker rotate-audit-key <broker state folder> <folder for the draft>
```

The old key signs one last checkpoint at the newest row, is retired at that row (the broker keeps accepting its older checkpoints and never lets it sign again), and is deleted from the state folder. A new key starts at the next row. The command writes a draft roster listing every key with the rows it signed for; sign it with the root (`hn trust sign`), put it at `audit-roster.json`, and start the broker. Auditors run `hn audit pin <folder>` and follow it.

## When a key leaks

Act in this order. Do not wait to build a release.

1. **Make a new key** and sign a roster, with the root, that lists the new key and names the leaked one under `revoked` with a reason.
2. **Hand the roster out.** Release: `hn trust update <file or https URL>` on each machine, or beside the next update. Policy: put it at `policy-roster.json` and reload. Audit: put it at `audit-roster.json`.
3. **Sign what comes next with the new key.**

What a revocation does, by key:

| Key | After the revoke |
|---|---|
| **Release** | an update archive, a sandbox helper manifest or an installed copy signed by the revoked key is refused, and `hn doctor` fails with "signed by a revoked key". **The sandbox helper is not trusted until the person updates to a release signed by a current key**, so box sessions stop until then. hn itself keeps starting. |
| **Policy** | the broker refuses to load a policy bundle the revoked key signed (and keeps the one it has), and a laptop refuses one at the start of a session. The serial rule alone could not stop this: a thief with the key can sign a higher serial. |
| **Audit** | give `afterRow`, the last row you still trust the key for (the row the leak began at). Checkpoints it signed up to that row still count as history; any it signs after are refused by `hn audit verify`. An auditor who kept an older roster does not get the key back from a bundle that carries one. |

For an audit key, the leak can also have been used to rewrite history before the row you choose. Choose `afterRow` from when the leak began, not from when you found out.

## When the root leaks

**A leaked root cannot be fixed by a roster**, because whoever holds it can sign rosters too. The fix is by hand: make a new root, pin it again (a fresh install for a release, `hn logout` and `hn login` for the policy root, `hn audit pin --root` into a new folder for audit), and say so to your people out of band. Every revocation a machine already held is kept when it re-pins.

A routine change of root is different and needs no hand work: the current root signs a roster that names a successor. From then on only the new root is accepted, and the old one can never be used again.

## What this does not do

- It does **not** make a leaked key harmless before you notice. Anything signed with it up to the revoke is still signed with it. For audit keys, `afterRow` is how you say where trust ends; for the others, the serial and version rules limit replays, and a revoke stops anything new.
- A machine that has **never seen** a newer roster can be served an older one by whoever controls its network. Releases and the policy come from places you control; an auditor should keep the folder `hn audit pin` makes and pin often.
- Deleting a machine's trust record reverts it to the keys its package or login shipped until the next roster arrives. `hn trust show` says when there was no record.
- There is **no threshold**: one offline root key signs. Keeping it safe, and having a second person present when it is used, is your process.
- It does not revoke a model provider key, a git token or an OIDC key. Those are credentials the broker holds, and you rotate them with the provider.
- Nothing here has had an outside review.

## Commands

```text
hn trust keygen-root <folder>
hn trust sign <draft.json> <root-key.pem> <root key id> <out.json>
hn trust show [--purpose release|policy|audit]
hn trust update <roster file or https URL>
hn update <archive> [--roster <file>]
hn broker rotate-audit-key <state folder> <folder>
hn audit pin <folder> --root <root-public.pem>
hn audit verify <bundle> --key-file <audit key> --trust <folder>
```
