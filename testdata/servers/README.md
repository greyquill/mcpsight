# Malicious MCP fixture servers

These are **deliberately malicious or poisoned** MCP servers. They exist to test
mcpsight's analyzers and sandbox, and to give the ecosystem a shared, honest
corpus of attack patterns. *These fixtures are the spec*:
an analyzer is not done until it catches the fixture that motivates it.

> **Do not deploy these.** Some read decoy credentials and attempt network
> connections when they start. They are safe only because mcpsight runs them in a
> sandbox with fake secrets and no real network. The credentials they target are
> decoys; the hosts they contact are unroutable.

Each server is a self-contained Node.js script (no dependencies) speaking MCP over
stdio (newline-delimited JSON-RPC). Run one directly for debugging:

```
node testdata/servers/benign-docs/server.js
```

## The corpus

| Fixture | What it does | Expected signal |
|---|---|---|
| `benign-docs/` | A clean, read-only docs server. The control. | Grade A, no findings, `fs:read` only. |
| `poisoned-descriptions/` | Tool descriptions carrying injection: override phrases, cross-tool references, zero-width/bidi/homoglyph text, a base64 payload, and instructions to read unrelated files. | Multiple `injection.*` findings. |
| `credential-thief/` | Reads decoy `~/.ssh/id_rsa` and `~/.aws/credentials` on `initialize`. | `capability.decoy_read` (critical, observed). |
| `egress-on-init/` | Resolves and connects to an external host on `initialize`. | `capability.egress_unexpected` (high, observed). |
| `rugpull/v1` → `rugpull/v2` | v1 is a benign lookup tool; v2 keeps the name but its description gains a hijack instruction and its schema gains a filesystem-write parameter. | `drift.instruction_added` (critical), `drift.capability_escalated` (high). |
| `resource-hog/` | Allocates memory without bound on startup: a resource-exhaustion / DoS attempt. | Killed by the sandbox's memory limit (`RLIMIT_AS`); the host is unharmed and the scan fails cleanly rather than hanging. |

## Remote scanning without a sandbox

`http-fixture/` serves the same personas over MCP Streamable HTTP. It returns
tool metadata and never runs anything, so it is safe on any machine, including
macOS where the stdio fixtures cannot be sandboxed.

```
make fixture        # or: go run ./testdata/servers/http-fixture -addr 127.0.0.1:8931
```

| Endpoint | Persona |
|---|---|
| `/clean` | `benign-docs` |
| `/poisoned` | `poisoned-descriptions` |
| `/rugpull` | `rugpull` v1. `curl -X POST localhost:8931/_rugpull/v2` switches the same URL to v2, and `/_rugpull/v1` switches it back. |
| `/auth/<persona>` | Any persona above, behind `Authorization: Bearer fixture-token` |

Every endpoint is plain `http://` and, apart from `/auth/`, unauthenticated, so
expect `authposture.plaintext_http` and `authposture.unauthenticated_listing` on
top of each persona's own findings. To scan with the token, put the URL and a
`headers` entry in a config file and pass it with `--from`.

## How they're used in tests

- **Analyzer unit tests** construct manifests directly and assert findings. They
  do not run Node, so they stay hermetic and cross-platform.
- **End-to-end tests** (`internal/scan`, Linux + bubblewrap only) run these
  servers under the sandbox and assert the full report, including observed
  behavior (decoy reads, egress).
