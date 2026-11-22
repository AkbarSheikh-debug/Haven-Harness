# Team mode: `hn broker`

In local mode a policy file binds the agent but not the person who owns the laptop: they can edit it, or edit the
client. Team mode moves what matters off the laptop. A small self-hosted server, the **broker**, holds the model keys,
git tokens and MCP credentials, and decides every model call, server-side tool, approval and team-memory read against
a **signed policy tree**. The laptop holds no key, so a modified client gets nothing the policy denies.

**What it does not bind:** a modified client can still read local files and lie about what happened locally. Only
what runs on the broker is fully bound.

## What the broker decides

| | Decided on the broker |
|---|---|
| **Who you are** | OpenID Connect device login; the ID token is checked by the broker against your provider's published keys. The broker then issues its own short-lived tokens (a login token, and one per hn session), bound to its address and the session. |
| **Models** | Which models each person may use; a daily token and dollar budget per person (new sessions or logins do not reset it); a rate limit. |
| **Tools in a reply** | Tools the policy denies are removed from what goes to the model, and any call to them is stripped from the reply before the laptop sees it. |
| **Server-side tools** | `git_push` (the laptop sends a bundle of HEAD; the broker pushes with its token, never forced) and MCP servers over HTTP with credentials the broker holds. A server a person may not use is never contacted for them. |
| **Approvals** | A push to a protected branch waits for an approver named in the requester's policy; with `separate`, never the requester. An approval covers one commit, once, within an hour. |
| **Team memory** | Entries visible to their writer, an OU (and every OU below it), a role, or the organisation, as policy allows; a lifetime limit; expired entries never returned; text scanned first; anything written while a session held untrusted text kept for its writer only. |
| **Keys** | The policy signing key can be replaced or revoked with a root-signed roster (`policy.root` in `broker.json`); laptops pin the root at first login and follow it ([key rotation](key-rotation.md)) |
| **Audit** | Every decision in a keyed hash chain on the broker, optionally shipped to a SIEM as OTLP/HTTP JSON logs; each session's own audit head is anchored, so a cut tail on a laptop is caught. Named readers can search it, follow it live and take an export that is checked offline against signed checkpoints: see [team audit](team-audit.md). |

## Set up a broker

1. **Make a policy signing key** where policy is written (not on the broker):

   ```bash
   hn broker keygen ./policy-keys          # policy-key.pem stays here; policy-key.pub.pem goes in broker.json
   ```

2. **Write the policy tree.** Every layer that applies to a person must allow a thing; deeper layers only narrow. A
   role grants nothing by itself; it matters where a rule names it (for example `approvers`).

   ```json
   {
     "format": 1, "serial": 1, "issued": "2026-11-17T00:00:00Z",
     "org": {
       "version": 1, "name": "org",
       "models": { "allow": ["claude-*"] },
       "budget": { "maxCostUsd": 20 },
       "git": { "repos": ["acme/*"], "protect": ["refs/heads/main"] },
       "approvers": { "roles": ["lead"], "separate": true },
       "audit": { "readers": { "roles": ["auditor"] } },
       "memory": { "share": ["user", "ou"], "maxDays": 90 }
     },
     "ou": { "hr": { "version": 1, "name": "hr", "tools": { "deny": ["bash"] }, "memory": { "dream": false, "learn": false } } },
     "roles": { "intern": { "version": 1, "name": "intern", "maxMode": "plan" } },
     "users": {}
   }
   ```

   Sign it. The serial only ever grows: the broker and every laptop refuse an older bundle once they have seen a newer one.

   ```bash
   hn broker sign tree.json ./policy-keys/policy-key.pem org-2026 policy-bundle.json
   ```

3. **Configure the broker** (`broker.json`). Credentials are named by environment variable; the broker reads them at
   start and removes them from its environment. A broker that listens beyond loopback must have TLS.

   ```json
   {
     "url": "https://broker.example.com",
     "listen": { "host": "0.0.0.0", "port": 8443 },
     "tls": { "cert": "/etc/hn/cert.pem", "key": "/etc/hn/key.pem" },
     "state": "/var/lib/hn-broker",
     "oidc": { "issuer": "https://login.example.com", "clientId": "hn-broker", "claims": { "user": "email", "ou": "department", "roles": "groups" } },
     "policy": { "bundle": "/etc/hn/policy-bundle.json", "keys": { "org-2026": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" } },
     "upstreams": [{ "name": "anthropic", "kind": "anthropic", "key": "ANTHROPIC_API_KEY", "models": ["claude-*"] }],
     "tools": {
       "git": [{ "repo": "acme/app", "remote": "https://github.com/acme/app.git", "tokenEnv": "GITHUB_TOKEN" }],
       "mcp": [{ "name": "docs", "url": "https://docs-mcp.example.com/mcp", "headers": { "Authorization": "DOCS_MCP_TOKEN" } }]
     },
     "audit": { "otlp": { "url": "https://siem.example.com:4318", "headers": { "Authorization": "SIEM_TOKEN" } } }
   }
   ```

   ```bash
   hn broker broker.json
   ```

   Your identity provider needs a client for the broker with the **device authorization** grant enabled. `claims`
   names which ID-token claims hold the person's name, OU path (`a/b/c` or a list) and roles (a list).

## Use it from a laptop

```bash
hn login https://broker.example.com      # shows a code to enter at your provider's page
hn --team --model claude-sonnet-5-5      # a session with no key on this machine
hn approvals                             # requests waiting for you, if you are an approver
hn approvals approve <id>
hn logout
```

The first login pins the broker's policy keys on the laptop; a bundle signed by any other key is refused later. In a
team session the broker's server-side tools (`git_push`, `mcp__<server>__<tool>`) and `team_memory_search` /
`team_memory_save` appear as tools; saving to team memory always asks you first.

## Operating notes

- The broker's `state` folder holds its token key, token book, ledgers, audit chain and key, the audit-signing key and its
  checkpoints, anchors and team memory.
  Keep it on the broker only, readable by the broker's account only, and back it up.
- To change policy, sign a new tree with a higher serial, replace the bundle file and restart the broker.
- To cut someone off, remove them at your identity provider; their broker tokens expire within hours (login, 8 h by
  default) and an hour (sessions).
