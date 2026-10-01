<h1 align="center">mcpsight</h1>

<p align="center"><strong>An X-ray machine for MCP servers.</strong></p>

<p align="center">
  <em>Inspect any MCP server before you trust it: what it costs, what it can reach,<br/>and whether it changed under you.</em>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://golang.org"><img alt="Go 1.26+" src="https://img.shields.io/badge/go-1.26%2B-00ADD8.svg?logo=go&logoColor=white"></a>
  <a href=".github/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/badge/CI-vet%20%C2%B7%20test%20%C2%B7%20build-success.svg"></a>
  <a href="docs/rubric.md"><img alt="Rubric v1" src="https://img.shields.io/badge/rubric-v1-informational.svg"></a>
  <a href="#safety-untrusted-code-runs-in-a-sandbox"><img alt="Sandboxed" src="https://img.shields.io/badge/untrusted%20code-sandboxed-critical.svg"></a>
  <br/>
  <img alt="No API key required" src="https://img.shields.io/badge/API%20key-not%20required-brightgreen.svg">
  <img alt="Runs offline" src="https://img.shields.io/badge/runs-offline-brightgreen.svg">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-linux%20%C2%B7%20macOS%20%C2%B7%20windows-lightgrey.svg">
</p>

<p align="center">
  <a href="#start-here-scan-the-servers-you-already-have">Quickstart</a> ·
  <a href="MANUAL.md">Manual</a> ·
  <a href="#what-it-checks">What it checks</a> ·
  <a href="docs/rubric.md">Rubric</a> ·
  <a href="docs/threat-model.md">Threat model</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  A <a href="https://www.greyquill.io">Greyquill Software</a> open-source project · Apache-2.0 · no account, no API key
</p>

---

`mcpsight` is a single command that inspects an MCP server before you trust it.
It answers three questions:

1. How many tokens its tool definitions burn in *every* request.
2. What it can actually reach: filesystem, shell, network, credentials. The
   README's claim is not evidence.
3. Whether it quietly changed its tool descriptions since you installed it.

## Start here: scan the servers you already have

Point it at the MCP config you already have and it scans every server in it:

```console
$ mcpsight scan --from claude_desktop_config.json
```

Or scan one server directly. This is real terminal output, and token counts are
estimates until real BPE tokenizers land:

```console
$ mcpsight scan npx:@modelcontextprotocol/server-postgres

  @modelcontextprotocol/server-postgres
  Server        @modelcontextprotocol/server-postgres  (0.6.2, via bubblewrap)
  Grade         B  (80/100)  rubric v1

  Context cost  ~4,180 tokens  (11 tools)   ~$0.013 per request @ Claude Sonnet  (est.)
  Capabilities  fs:read  net:egress
  Drift         baseline recorded (first scan)

  Findings
  HIGH      Tool description issues an imperative instruction to the model [injection.imperative_instruction]
      tool: query
      fix: Descriptions should not tell the model what to do before/after other tools.

  Report: .mcpsight/report.json  |  SARIF: .mcpsight/report.sarif
```

Then, in CI, fail the build if a server drifts from the baseline you committed:

```console
$ mcpsight verify        # exits non-zero if a server changed under you
```

This is `npm audit` for MCP.

## Install

Download a binary for macOS, Linux, or Windows from
[releases](https://github.com/greyquill/mcpsight/releases), or:

```console
$ brew install --cask greyquill/tap/mcpsight      # macOS
$ go install github.com/greyquill/mcpsight/cmd/mcpsight@latest
```

Every release is signed. [MANUAL.md](MANUAL.md#verifying-a-download) shows how to
check yours before you run it.

Scanning **stdio** servers (npx/uvx) executes untrusted code, so it needs a
sandbox backend: [bubblewrap](https://github.com/containers/bubblewrap) on Linux
(`apt-get install bubblewrap`, plus `strace` for observed-capability findings),
or Docker for `docker:` targets. Scanning **remote** (`https://`) servers needs
neither and works on any OS, because the binary cross-compiles everywhere.
Without a sandbox, stdio scans are refused instead of run unprotected, so on
macOS and Windows you scan remote targets.

> On Ubuntu 24.04, `apparmor_restrict_unprivileged_userns` blocks bubblewrap.
> See [`docs/ci.md`](docs/ci.md) for the scoped AppArmor profile that fixes it
> without weakening userns confinement machine-wide.

## Command reference

### `mcpsight scan [target…]`
Targets: `npx:@scope/name@ver`, `uvx:pkg`, `docker:img:tag`, `https://host/sse`,
or `--from <mcp-config.json>` to scan every server you already have.

| Flag | Purpose |
|---|---|
| `--from <file>` | scan every server in an MCP config file |
| `--json` / `--sarif` / `--markdown` | write JSON / SARIF / Markdown to stdout instead of the summary |
| `--fail-on <sev>` | exit non-zero at/above this severity (default `high`) |
| `--update-baseline` | record the current manifest as the new baseline |
| `--offline` | skip the network analyzer (supply-chain) |
| `--rules <file>` | use a custom injection rule file instead of the embedded set |
| `--allow-net` | let a local stdio server use the network on startup |
| `--no-sandbox` | DANGEROUS: run stdio servers unsandboxed (warns loudly) |
| `--timeout <dur>` | per-server budget (default 30s) · `--dir <path>` · `--no-color` |

Every flag, every rule ID, and every exit code is documented in the
**[manual](MANUAL.md)**.

Every scan also writes `.mcpsight/report.json` and `.mcpsight/report.sarif`, and
records or updates `.mcpsight/baseline.json`. Commit that last one, because a
changed baseline is a changed server.

### `mcpsight verify [target…]`
Re-scans and exits non-zero if any server drifted from the committed baseline.
Never writes the baseline. This is the CI gate, documented in
[`docs/ci.md`](docs/ci.md).

### `mcpsight version`
Prints the version, commit, and rubric version.

## What it checks

| Analyzer | Answers |
|---|---|
| Context cost | Tokens per tool, per model family, cost per request, and which schemas are bloated. |
| Capability | Declared (from schemas) *and* observed (from a sandbox run). The gap is itself a finding. |
| Injection | Prompt-injection and tool-poisoning patterns hidden in tool *descriptions*. Rule-based, offline, no LLM required. |
| Drift | A structural diff against a committed baseline. Severity depends on the *direction* of change. |
| Supply chain | Source availability, install scripts, dependency CVEs (OSV.dev), typosquatting. |
| Auth posture | For remote servers: does `tools/list` answer with no credentials? TLS basics. |

Scoring comes from a published, versioned rubric
([`docs/rubric.md`](docs/rubric.md)) derived from a stated threat model
([`docs/threat-model.md`](docs/threat-model.md)). Anyone can recompute a grade by
hand from the findings. Reproducibility is the credibility.

## Safety: untrusted code runs in a sandbox

Scanning a local (stdio) server **executes its code**. `mcpsight` runs it inside
a network-denied [bubblewrap](https://github.com/containers/bubblewrap) sandbox
with a tmpfs filesystem and a fake home seeded with decoy credentials. If the
server reads a decoy `~/.ssh/id_rsa`, that is a critical finding. If no sandbox
backend is available, `mcpsight` refuses to run stdio targets. It will not
execute untrusted code unprotected. `--no-sandbox` exists, warns loudly, and is
never the default.

See [`docs/phase0-spike.md`](docs/phase0-spike.md) for the proof-of-concept that
established this design.

## Documentation

| Document | What it covers |
|---|---|
| [MANUAL.md](MANUAL.md) | The complete reference: every flag, rule ID, exit code, and limitation |
| [docs/rubric.md](docs/rubric.md) | The score, in full, versioned. Recompute any grade by hand |
| [docs/threat-model.md](docs/threat-model.md) | What we defend against, and what we deliberately do not |
| [docs/ci.md](docs/ci.md) | Ready-to-use CI workflows |
| [docs/analyzers/README.md](docs/analyzers/README.md) | Writing your own analyzer |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and pull requests |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability, and how to verify a release |

## Non-goals

Stated up front, and never quietly moved:

- This is not a malware scanner. We do not claim to detect novel malicious code.
  We detect risk surface and change. Overclaiming here would destroy credibility
  permanently.
- This is not a gateway. No proxying of live traffic in v1.
- This is not a registry. We do not host servers or replace the official one.
- This is not an eval framework. We measure what a tool costs and what it can
  reach, not whether it is good.

## Self-host the index

The Registry Security Index is the CLI run at scale over a whole registry. It is
a second binary, `mcpsight-index`, sharing the same analyzers, so any number it
publishes is reproducible by anyone holding the binary. Config is environment
variables (`MCPSIGHT_DSN` for Postgres, `MCPSIGHT_ADDR`, `MCPSIGHT_WEB`).

```console
# Preview the static site locally, no database (opens your browser).
# Until a snapshot exists in web/data/, it shows the "coming soon" page:
$ make preview

# Run the whole index, Postgres and service together, in one command:
$ docker compose -f deploy/docker-compose.yml up --build     # http://localhost:8080

# Populate and publish (needs a Postgres DSN; stdio scans need the sandbox):
$ mcpsight-index scan-batch --seed testdata/index-seed.json  # crawl+scan+store
$ mcpsight-index snapshot -o web/data/snapshot.json          # static data for the site
```

Subcommands: `migrate | crawl | scan-batch | snapshot | serve | preview`. A Helm
chart is in [`deploy/helm`](deploy/helm), and the public site publishes to GitHub
Pages via [`.github/workflows/pages.yml`](.github/workflows/pages.yml).

## Output formats

Implemented: terminal (default), `--json`, `--sarif` (native GitHub code
scanning), and `--markdown` (for PR comments). Planned: `--sbom` (CycloneDX).
Exit codes are CI-friendly: `0` clean, `1` findings above `--fail-on`, `2` scan error.

## Status

Pre-release. Every planned phase is built.

| Phase | What shipped |
|---|---|
| 0, sandbox spike | Passed. See [`docs/phase0-spike.md`](docs/phase0-spike.md). |
| 1, v0.1 | `scan` and `verify` over remote (Streamable HTTP) and local (stdio, bubblewrap-sandboxed) servers, with the context-cost, declared-capability, and drift analyzers, a transparent score, terminal and JSON output, and committable baselines. |
| 2, launch | Full observed-capability sandbox (decoy-read and egress findings), the offline injection analyzer with its YAML rule set, the supply-chain analyzer (OSV CVEs, install scripts, typosquat), SARIF output, a CI workflow, and the malicious `testdata/servers/` fixtures. |
| 3, the index | Postgres store, a pluggable registry crawler, the batch scan runner, the `mcpsight-index` service (JSON API and snapshot), and a static site ([`web/`](web/)) that publishes to GitHub Pages. One OCI image and `docker compose up` self-hosts the whole thing ([`deploy/`](deploy/)). Preview it with `make preview`. |
| 4, durability | Auth-posture analyzer, `--markdown` output, contributor docs, live npx/uvx/docker target execution, sandbox resource limits, and cross-platform builds. |

One deep item is tracked as future work: the hardened out-of-sandbox observation
(netns proxy, `fanotify`, seccomp) that would replace `strace`. See
[`docs/threat-model.md`](docs/threat-model.md).

## Open-core boundary

Individual and open-ecosystem use is free forever under Apache-2.0: the CLI,
every analyzer, the full sandbox, SARIF and CI gating, local baselines, and the
public index. Organizational control planes (org-wide policy, central drift
alerting, attestations, SSO and RBAC) are the commercial
[Greyquill](https://www.greyquill.io) Enterprise layer. The line is clean and
will not move quietly.

---

<p align="center">
  © 2026 Greyquill Software Private Limited · Licensed under
  <a href="LICENSE">Apache-2.0</a> · <a href="NOTICE">NOTICE</a>
</p>
