<h1 align="center">
  <a href="https://mcpsight.dev">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="web/brand/lockup-dark.svg">
      <img src="web/brand/lockup.svg" alt="mcpsight" width="236" height="52">
    </picture>
  </a>
</h1>

<p align="center"><strong>An X-ray machine for MCP servers.</strong></p>

<p align="center">
  <em>Inspect any MCP server before you trust it: what it costs, what it can reach,<br/>and whether it changed under you.</em>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://golang.org"><img alt="Go 1.26+" src="https://img.shields.io/badge/go-1.26%2B-00ADD8.svg?logo=go&logoColor=white"></a>
  <a href="https://github.com/greyquill/mcpsight/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/greyquill/mcpsight/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="docs/rubric.md"><img alt="Rubric v1" src="https://img.shields.io/badge/rubric-v1-informational.svg"></a>
  <a href="#safety-untrusted-code-runs-in-a-sandbox"><img alt="Sandboxed" src="https://img.shields.io/badge/untrusted%20code-sandboxed-critical.svg"></a>
  <br/>
  <img alt="No API key required" src="https://img.shields.io/badge/API%20key-not%20required-brightgreen.svg">
  <img alt="Runs offline" src="https://img.shields.io/badge/runs-offline-brightgreen.svg">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-linux%20%C2%B7%20macOS%20%C2%B7%20windows-lightgrey.svg">
</p>

<p align="center">
  <a href="#start-here-scan-the-servers-you-already-have">Quickstart</a> ·
  <a href="https://mcpsight.dev/docs/">Docs</a> ·
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

Or scan one remote server by its URL. This works on macOS, Linux, and Windows:

```console
$ mcpsight scan https://mcp.example.com/mcp
```

Local servers (`npx:`, `uvx:`, or a command) run untrusted code, so mcpsight runs
them in a sandbox. That needs Linux with bubblewrap. On macOS and Windows those
entries are refused, and remote ones still scan.

Here is real output from one of the practice servers in this repo, which hides a
different trick in each tool description. Token counts are estimates, and the
output says so:

```console
$ mcpsight scan http://127.0.0.1:8931/poisoned

  poisoned-descriptions
  Server        poisoned-descriptions  (0.1.0, via remote)
  Grade         F  (0/100)  rubric v1

  Context cost  ~462 tokens  (5 tools)   ~$0.001 per request @ Claude Sonnet  (est.)
  Capabilities  code:eval  fs:read  fs:write
  Drift         baseline recorded (first scan)

  Findings
  CRITICAL  Tool description tries to override the model's instructions [injection.override_instruction]
      tool: summarize
      fix: Remove instruction-like text from the description; a tool description should
      describe the tool, not command the model.
  HIGH      Tool description instructs reading sensitive or unrelated paths [injection.unrelated_path]
      tool: weather
      fix: Remove references to credential or system files; a tool's description should
      not point the model at ~/.ssh, ~/.aws, .env, or similar.
  ...

  Report: .mcpsight/report.json  |  SARIF: .mcpsight/report.sarif
```

To run it yourself, clone the repo, start the practice servers with `make fixture`,
and follow the [walkthrough](https://mcpsight.dev/docs/practice-servers.html).

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

Every release is signed. [Verify a download](https://mcpsight.dev/docs/verify-download.html) shows how to
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
**[docs](https://mcpsight.dev/docs/commands.html)**.

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
| [Documentation](https://mcpsight.dev/docs/) | Install, walkthroughs, CI, and the full reference: every flag, rule, and exit code |
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

Pre-release. What works today:

- `scan` and `verify` for remote servers on macOS, Linux, and Windows.
- Local `npx:`, `uvx:`, and command servers on Linux, sandboxed with bubblewrap and
  watched with strace. `docker:` images wherever Docker runs.
- Six analyzers: context cost, capabilities (declared and observed), injection,
  drift, supply chain, and auth posture. The score follows a published
  [rubric](docs/rubric.md).
- Terminal, JSON, SARIF, and Markdown output, CI-friendly exit codes, and baselines
  you commit next to your config.
- `mcpsight-index`, which runs the same analyzers over a whole registry. You can
  self-host it today. The public index is not published yet.

What it does not do yet is in the [threat model](docs/threat-model.md) and
[docs](https://mcpsight.dev/docs/protection.html). The biggest one is that code
written to dodge strace can hide what it does.

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
