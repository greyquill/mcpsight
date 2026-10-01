# mcpsight manual

The complete reference. Read the [README](README.md) for the two-minute version.
Open this one when you need the exact behavior of a flag or the meaning of a rule ID.

*Greyquill Software Private Limited · Apache-2.0*

---

## Contents

- [Install](#install)
- [Concepts](#concepts)
- [Targets](#targets)
- [Commands](#commands)
- [Output and artifacts](#output-and-artifacts)
- [Exit codes](#exit-codes)
- [The analyzers](#the-analyzers)
- [Scoring](#scoring)
- [The sandbox](#the-sandbox)
- [Continuous integration](#continuous-integration)
- [The Registry Security Index](#the-registry-security-index)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)

---

## Install

Download a release for your platform from
[GitHub releases](https://github.com/greyquill/mcpsight/releases), unpack it, and put
`mcpsight` on your `PATH`. Builds exist for macOS, Linux, and Windows on amd64 and arm64.

On macOS, Homebrew works too:

```console
$ brew install --cask greyquill/tap/mcpsight
```

With Go 1.26 or later:

```console
$ go install github.com/greyquill/mcpsight/cmd/mcpsight@latest
```

Or build from source:

```console
$ git clone https://github.com/greyquill/mcpsight && cd mcpsight
$ make build                 # -> bin/mcpsight
```

`make all` runs `vet`, `test`, and `build`. The other targets are `build-index`,
`preview`, `test`, `vet`, `fmt`, `tidy`, and `clean`.

### Verifying a download

You are about to run a tool that runs other people's code, so check it first. Each
release has a `checksums.txt`, signed by our release workflow with
[Sigstore](https://www.sigstore.dev). With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
installed, download `checksums.txt`, `checksums.txt.sig`, and `checksums.txt.pem`
next to your archive, then:

```console
$ cosign verify-blob checksums.txt \
    --signature checksums.txt.sig --certificate checksums.txt.pem \
    --certificate-identity-regexp '^https://github.com/greyquill/mcpsight/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
$ shasum -a 256 --ignore-missing -c checksums.txt
```

Both must pass. The first proves `checksums.txt` came from our release workflow. The
second proves your archive matches it. With the GitHub CLI, one command checks the
archive's build provenance instead:

```console
$ gh attestation verify mcpsight_*_darwin_arm64.tar.gz --repo greyquill/mcpsight
```

### Platform support

The binary cross-compiles to macOS, Linux, and Windows on amd64 and arm64. What
you can *scan* depends on the platform, because scanning a local server means
executing its code:

| Target kind | macOS | Windows | Linux |
|---|---|---|---|
| `https://` remote | yes | yes | yes |
| `npx:` / `uvx:` / local command | no | no | yes, with bubblewrap |
| `docker:` | with Docker | with Docker | with Docker |

Remote scanning needs nothing beyond the binary. For stdio servers on Linux:

```console
$ apt-get install bubblewrap strace     # strace enables observed-capability findings
```

Without a sandbox backend, `mcpsight` refuses to scan stdio targets. It will not
run untrusted code unprotected. See [The sandbox](#the-sandbox).

---

## Concepts

### The manifest

A probe starts the server, completes the MCP `initialize` handshake, calls
`tools/list`, `resources/list`, and `prompts/list`, then normalizes the result
into a canonical JSON document with deterministic key order, whitespace, and
unicode normalization. Every analyzer reads the manifest, and the manifest is
what gets hashed.

### The baseline

The manifest hash plus enough structure to diff against, stored in
`.mcpsight/baseline.json`. Commit this file. A changed baseline in a pull request
diff is a server that changed under you, which is the event this tool exists to
make visible.

### Findings

Each analyzer returns zero or more findings. A finding carries a stable rule ID
(`<analyzer>.<rule>`), a severity (`critical | high | medium | low | info`), the
tool it applies to, and a remediation. Rule IDs never change meaning, so you can
suppress or track them.

### The score

100 points minus a penalty per finding, mapped to a letter grade. The rubric is
published and versioned so anyone can recompute a grade by hand. See
[Scoring](#scoring).

### The sandbox

Scanning a local server executes untrusted code, so it runs inside a
network-denied namespace with a tmpfs filesystem and a fake home full of decoy
credentials. If the server reads a decoy, that is a critical finding.

---

## Targets

### Direct forms

| Form | Example | Runs code |
|---|---|---|
| npm | `npx:@modelcontextprotocol/server-postgres@0.6.2` | yes |
| PyPI | `uvx:some-mcp-server` | yes |
| OCI image | `docker:ghcr.io/org/server:tag` | yes |
| Remote | `https://mcp.example.com/sse` | no |

Version pinning follows each ecosystem's own syntax: `npx:pkg@1.2.3` for npm,
`docker:image:tag` for OCI. `http://` is accepted and produces an
`authposture.plaintext_http` finding.

Anything else is rejected:

```
unrecognized target "foo": expected npx:, uvx:, docker:, or an https:// URL
```

### From a config file

Point `mcpsight` at the MCP config you already have and it enumerates every
server in it. This is the common case:

```console
$ mcpsight scan --from claude_desktop_config.json
$ mcpsight scan --from .mcp.json
```

It reads an `mcpServers` object (falling back to `servers`), and understands both
entry shapes:

```jsonc
{
  "mcpServers": {
    "postgres": {                                  // stdio entry
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": { "DATABASE_URL": "postgres://..." }
    },
    "remote-docs": {                               // remote entry
      "url": "https://mcp.example.com/sse",
      "headers": { "Authorization": "Bearer ..." }
    }
  }
}
```

The server's key in the config (`postgres`, `remote-docs`) becomes its name, and
that name is the baseline key. Renaming a server in your config resets its drift
history. `npx` and `uvx` commands are recognized as such, so supply-chain
analysis still applies to config-file entries. Any other `command` is treated as
a local command and still runs sandboxed.

You can combine positional targets and `--from` in one invocation. Both sets are
scanned.

---

## Commands

### `mcpsight scan [target...]`

Probes each target, runs every analyzer, renders a report, and records or updates
baselines.

| Flag | Default | Meaning |
|---|---|---|
| `--from <file>` | | Scan every server in an MCP config file |
| `--json` | off | Write the report as JSON to stdout instead of the summary |
| `--sarif` | off | Write SARIF to stdout instead of the summary |
| `--markdown` | off | Write Markdown to stdout instead of the summary |
| `--fail-on <sev>` | `high` | Exit 1 if any finding is at or above this severity |
| `--update-baseline` | off | Record the current manifest as the new baseline |
| `--offline` | off | Skip analyzers needing network (supply chain) |
| `--rules <file>` | embedded | Use a custom injection rule file |
| `--allow-net` | off | Let a stdio server reach the network during startup |
| `--no-sandbox` | off | Dangerous. Run stdio servers with no isolation |
| `--timeout <dur>` | `30s` | Per-server wall-clock budget, e.g. `60s`, `2m` |
| `--dir <path>` | `.` | Project directory holding `.mcpsight/` |
| `--no-color` | off | Disable ANSI color |

Notes on the flags that surprise people:

- `--fail-on` decides the exit code, not the output. Every finding is rendered
  either way. The threshold only sets whether the process exits 1.
- `--update-baseline` is how you accept a change. The first scan records a
  baseline automatically. After that, drift is reported and the baseline is left
  alone until you pass this flag. Review the diff, then accept it.
- `--allow-net` weakens the scan. Some servers need the network to initialize,
  and once you allow it, egress can no longer be attributed. The capability
  analyzer suppresses those findings, because reporting them would mean standing
  behind a claim the trace cannot support.
- `--offline` makes the run hermetic. It skips OSV.dev lookups and registry
  metadata, so supply-chain findings do not run at all.
- `--no-sandbox` prints a red warning to stderr and is never the default. It
  exists for environments that provide isolation at another layer. If you are not
  certain you are in one, you are not in one.

Multiple targets are scanned in sequence. One failing target does not abort the
others. The run exits 2 at the end.

### `mcpsight verify [target...]`

Re-scans and compares against the committed baseline. It never writes a baseline.
This is the CI gate.

| Flag | Default | Meaning |
|---|---|---|
| `--from <file>` | | Verify every server in an MCP config file |
| `--offline` | off | Skip analyzers needing network (supply chain) |
| `--timeout <dur>` | `30s` | Per-server wall-clock budget |
| `--dir <path>` | `.` | Project directory holding `.mcpsight/` |
| `--no-color` | off | Disable ANSI color |

`verify` exits on drift alone, so `--offline` costs you nothing here and keeps
the gate fast. Prefer it in CI.

It exits 1 if any server drifted, and 2 if a server has no recorded baseline (run
`scan` first) or the probe failed. On success:

```
  All servers match their baselines.
```

### `mcpsight version`

Prints the version, commit, and the rubric version that build scores with:

```console
$ mcpsight version
mcpsight 0.1.0 (commit a1b2c3d, rubric v1)
```

The rubric version matters when comparing grades across time. See
[Scoring](#scoring).

---

## Output and artifacts

### Renderers

The default terminal renderer prints a human summary: grade, context cost,
capabilities, drift state, then findings with their remediation. Color is on only
when stdout is a terminal, and either `--no-color` or a `NO_COLOR` environment
variable turns it off ([no-color.org](https://no-color.org)).

`--json` writes the full report, including the canonical manifest, every finding
with its detail payload, and per-tool token counts. This is the stable
integration surface. You get one object for a single target and an array for
several.

`--sarif` writes SARIF 2.1.0, which GitHub code scanning ingests natively. Upload
it with `github/codeql-action/upload-sarif` and the findings appear inline on the
pull request.

`--markdown` writes a table suited to pasting into a pull request comment.

These flags are mutually exclusive in effect. The first one set wins, in the
order JSON, SARIF, Markdown.

### Files written

Every `scan` writes to `.mcpsight/` under `--dir`, whichever renderer you chose:

| File | Contents | Commit it? |
|---|---|---|
| `baseline.json` | Manifest hash and structure per server | Yes |
| `report.json` | Full report from the last scan | No |
| `report.sarif` | Same findings as SARIF | No |

`report.sarif` is written every time, so a CI job can upload it without anyone
remembering to pass a flag. A reasonable `.gitignore`:

```gitignore
.mcpsight/report.json
.mcpsight/report.sarif
```

---

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| `0` | clean | No finding at or above `--fail-on`, and no drift |
| `1` | findings | A finding met the threshold, or a server drifted |
| `2` | error | Probe failed, target unresolvable, no baseline, bad flag |

The split between 1 and 2 is deliberate. Exit 1 means the tool worked and you
have a problem. Exit 2 means the tool did not work. Never treat them the same in
CI. A broken scanner that quietly reports clean is worse than no scanner.

---

## The analyzers

Six analyzers, each independent and individually meaningful. Rule IDs are stable
and namespaced `<analyzer>.<rule>`.

### Context cost

How many tokens the server's tool definitions burn in *every* request, tokenized
the way a client injects them. Reports the total, the per-tool breakdown, the
worst offenders, and an estimated cost per request per model family.

| Rule | Severity | Fires when |
|---|---|---|
| `context.oversized_tool` | low | A single tool definition is disproportionately large |
| `context.schema_bloat` | low | Deeply nested or verbose JSON Schema that could be flattened |

Both are low on purpose. Token cost is a number you act on, not a moral failing,
and it does not linearly reduce the score.

> **Accuracy note.** Token counts come from a heuristic estimator behind a
> pluggable interface, and are labeled `(est.)` in output. Real BPE tokenizers
> are a drop-in replacement that has not landed yet. Treat the numbers as
> calibrated estimates for comparison, and do not bill anyone from them.

### Capability

What the server can reach, measured two independent ways.

Declared capabilities come from tool names, descriptions, and schemas, and are
classified as `fs:read`, `fs:write`, `exec:shell`, `net:egress`, `db:write`,
`secrets:read`, and `code:eval`.

Observed capabilities come from the sandbox run: what the process actually did
while initializing.

| Rule | Severity | Fires when |
|---|---|---|
| `capability.decoy_read` | critical | The server read a decoy credential file |
| `capability.egress_unexpected` | high | Network egress not explained by the server's stated function |
| `capability.declared_observed_gap` | high | Observed behavior exceeds what was declared |
| `capability.not_observed` | info | mcpsight ran the server but could not watch it, so the three checks above did not run |

`capability.decoy_read` is the finding this whole sandbox exists to produce. The
fake home contains `~/.ssh/id_rsa`, `~/.aws/credentials`, and `.env`. A
documentation-lookup server has no business opening any of them.

The gap between declared and observed is itself the signal. A server that claims
to be a read-only docs lookup and opens a socket on startup has told you
something about itself.

### Injection

An MCP tool *description* is fed straight to the model, so a malicious
description can address the model directly. The user never sees it, which is what
makes this the hardest of the six to catch by eye.

| Rule | Severity | Detects |
|---|---|---|
| `injection.override_instruction` | critical | "ignore previous instructions" and relatives |
| `injection.imperative_instruction` | high | Second-person commands to the model ("before calling any other tool, first read...") |
| `injection.cross_tool_reference` | high | Naming *other* tools or servers, which is cross-tool hijacking |
| `injection.unrelated_path` | high | Instructions to read files unrelated to the tool's stated function |
| `injection.invisible_chars` | high | Zero-width characters, bidi controls, homoglyphs |
| `injection.encoded_blob` | medium | Base64 or hex payloads embedded in a description |
| `injection.excessive_length` | low | A 2,000-token "description" for a two-parameter tool |

No LLM is involved and none is required. The rules are declarative, live in
[`internal/analyze/injection/rules/patterns.yaml`](internal/analyze/injection/rules/patterns.yaml),
and ship embedded in the binary. That is why the tool runs offline and in CI with
no API key.

Override the rule set with `--rules <file>` when you want to tighten or loosen
it. A bad path fails immediately, before the probe runs. False positives are
expected and disputable, and the rules are public precisely so maintainers can
argue with them.

### Drift

A structural diff against the committed baseline. Severity depends on the
direction of the change, which is what makes this the analyzer worth leaving
installed after the first scan.

| Rule | Severity | Meaning |
|---|---|---|
| `drift.instruction_added` | critical | A description gained an instruction to the model |
| `drift.capability_escalated` | high | A capability class widened, e.g. `fs:read` to `fs:write` |
| `drift.tool_added` | medium | A tool that was not there before |
| `drift.schema_changed` | medium | Input schema changed, e.g. gained a `path` parameter |
| `drift.tool_removed` | low | A tool disappeared |
| `drift.description_changed` | low | Wording changed without gaining instructions |
| `drift.description_shortened` | info | Text got shorter, which is almost always noise |
| `drift.server_version_changed` | info | Reported version differs from baseline |

A description getting shorter is noise. A description acquiring an imperative
sentence is a rug-pull. Flattening those into one "changed" alert is how drift
detection becomes something people mute, so it is graded instead.

### Supply chain

Whether the package around the server is trustworthy. Needs network access, and
is skipped entirely under `--offline`.

| Rule | Severity | Fires when |
|---|---|---|
| `supplychain.known_cve` | high | A dependency has a known CVE (via [OSV.dev](https://osv.dev), free, no key) |
| `supplychain.install_script` | high | A `postinstall` or equivalent runs at install time |
| `supplychain.typosquat` | high | The name is one or two edits from a well-known server, or is its name under another scope |
| `supplychain.no_source` | medium | No resolvable source repository, so you cannot audit it |
| `supplychain.single_maintainer` | low | Bus-factor of one |
| `supplychain.young_package` | low | Published very recently |
| `supplychain.metadata_unavailable` | info | Registry metadata could not be fetched |

The typosquat check compares the package name with a curated list of popular MCP
packages. It flags a name one or two edits away from one of them
(`@modelcontextprotocol/server-postgress`), and a popular name published under
another scope (`@evil/server-postgres`). A package on the list is never flagged,
even when it is close to another one, so `server-gitlab` is not a squat of
`server-github`. The list lives in `internal/analyze/supplychain/typosquat.go`.

### Auth posture

Remote targets only.

| Rule | Severity | Fires when |
|---|---|---|
| `authposture.unauthenticated_listing` | high | `tools/list` answers with no credentials at all |
| `authposture.plaintext_http` | high | The endpoint is `http://` |
| `authposture.weak_tls` | medium | TLS configuration is below current practice |

`unauthenticated_listing` is measured by deliberately re-probing without
credentials. Internet-exposed MCP servers often answer tool-listing requests from
anyone, and the operator is usually unaware.

---

## Scoring

The full rubric is [`docs/rubric.md`](docs/rubric.md), and it is versioned. This
is the summary.

A server starts at 100 points. Each finding subtracts by severity:

| Severity | Penalty |
|---|---:|
| critical | 40 |
| high | 20 |
| medium | 8 |
| low | 3 |
| info | 0 |

```
score = clamp(100 − Σ penalty(finding), 0, 100)
```

Each rule contributes at most once per tool, so one systemic issue cannot
subtract twenty times over.

| Grade | Score |
|---|---|
| A | 90 to 100 |
| B | 75 to 89 |
| C | 60 to 74 |
| D | 40 to 59 |
| F | 0 to 39 |

One critical finding costs 40 points, enough to drop an otherwise spotless server
to a D. That is intentional. A confirmed decoy credential read is not something a
good score elsewhere should offset.

Every scan records the tool version and the `rubric_version` that produced it.
When the rubric changes, old grades stay interpretable. Nothing is silently
re-graded. That is how a public index keeps trust.

---

## The sandbox

### What it does

Scanning a stdio server means executing code from a stranger. The sandbox assumes
that code is hostile:

- Network is denied by default. Egress is blocked and attempts are recorded.
  `--allow-net` opens it for servers that need it to initialize.
- The filesystem is tmpfs with no host mounts. The server's own code directories
  are bind-mounted read-only so it can actually run.
- `$HOME` is a decoy, seeded with `~/.ssh/id_rsa`, `~/.aws/credentials`, and
  `.env`. Reading any of them is a critical finding.
- Resource limits cover address space, CPU time, open files, file size, PID
  count, wall clock, and a 1 GiB cap on `/tmp`. A memory-hog server is killed and
  the host stays healthy.
- The host Docker socket is never exposed to the sandboxed process.

Backends: bubblewrap for `npx:`, `uvx:`, and local commands, and Docker with
cgroup limits for `docker:` targets. `strace` inside the sandbox turns syscalls
into observed-capability findings. Without it, scans still run, but the observed
half goes quiet.

### When it is unavailable

`mcpsight` refuses the target and says so. It does not fall back to running the
code unprotected, and it does not quietly skip the server and report success.
Remote targets and static analysis continue to work everywhere.

### Honest limits

Read [`docs/threat-model.md`](docs/threat-model.md) for the full statement. The
short version:

- `strace` can be evaded by code that is actively trying. The hardened
  replacement, a network-namespace recording proxy plus `fanotify` and a seccomp
  policy, is designed but not built, because it needs privileged setup. What
  ships holds up against the fixture corpus and against honest servers that do
  surprising things. That covers the threat we actually see.
- `npx:` and `uvx:` currently run with the network allowed inside the sandbox,
  because the package manager has to fetch the package. Egress findings are gated
  on the network actually having been denied, so they fire for local command
  targets but stay quiet for freshly installed packages. Correct attribution
  matters more than a bigger finding count. Splitting install from run is the
  fix, and it is planned.
- This is not a malware scanner. It detects risk surface and change, not novel
  malicious code. That boundary is in the README and will not move quietly.

---

## Continuous integration

Full workflows in [`docs/ci.md`](docs/ci.md). The pattern:

```yaml
- run: mcpsight scan --from .mcp.json --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: .mcpsight/report.sarif
```

Gate on drift separately, because that is the check which catches a server
changing under you between releases:

```yaml
- run: mcpsight verify --from .mcp.json --offline
```

Two habits make this work:

1. Commit `.mcpsight/baseline.json`. Without it, `verify` exits 2 and has nothing
   to compare against.
2. Accept changes deliberately. When `verify` fails legitimately, run
   `mcpsight scan --update-baseline`, read the diff in the pull request, and merge
   it as a reviewed change. The baseline diff *is* the review artifact.

Both commands take `--offline` for runners without egress. Supply-chain findings
are then skipped, and the job does not fail on them.

---

## The Registry Security Index

The index is the CLI run at scale over a whole registry, sharing the same
analyzer code. Any number it publishes is reproducible by anyone holding the
binary. It is a second command, `mcpsight-index`, and it is entirely optional.

```console
$ make preview       # serve the static site locally, no database, opens a browser
```

The site reads `web/data/snapshot.json`. Until one exists, it shows a
"coming soon" page instead of an empty table.

### Subcommands

| Subcommand | Purpose |
|---|---|
| `migrate` | Create or update the Postgres schema |
| `crawl` | Discover servers from the official registry or a seed file |
| `scan-batch` | Scan discovered servers and store results |
| `snapshot` | Emit the static JSON the site reads |
| `serve` | Run the JSON API and serve the site |
| `preview` | Serve the static site with no database |

### Configuration

Configuration is environment variables only. There is no config file.

| Variable | Default | Meaning |
|---|---|---|
| `MCPSIGHT_DSN` | | Postgres connection string (`DATABASE_URL` also accepted) |
| `MCPSIGHT_ADDR` | `:8080` | Listen address |
| `MCPSIGHT_WEB` | `web` | Directory containing the static site |

### Running it

```console
$ docker compose -f deploy/docker-compose.yml up --build      # http://localhost:8080
```

That brings up Postgres and the service together. A Helm chart for any Kubernetes
is in [`deploy/helm`](deploy/helm). There are no managed-service dependencies
anywhere. Postgres is Postgres, whether it is RDS, Cloud SQL, or a container.

To populate and publish:

```console
$ mcpsight-index migrate
$ mcpsight-index scan-batch --seed testdata/index-seed.json
$ mcpsight-index snapshot -o web/data/snapshot.json
```

Committing a refreshed `snapshot.json` redeploys the public site through
[`.github/workflows/pages.yml`](.github/workflows/pages.yml).

> The service image is deliberately minimal and can scan remote targets only.
> Stdio scanning needs bubblewrap, which that image does not carry. Run
> `scan-batch` on a host or CI runner that has the sandbox, pointed at the same
> `MCPSIGHT_DSN`.

---

## Troubleshooting

**`no sandbox backend available`**

Install bubblewrap (`apt-get install bubblewrap`), or scan remote targets
instead. macOS and Windows have no bubblewrap, so use a Linux host or a `docker:`
target. The refusal is deliberate.

**`capability.not_observed` on a stdio scan**

Install `strace`. Without it the sandbox still isolates the server, but nothing
watches it, so the decoy-read and egress checks cannot fire. The report says so
with this info finding, so a grade from such a run covers declared capabilities
only. `docker:` targets and `--no-sandbox` runs get the same finding, because
neither is traced yet.

**`no baseline recorded. Run 'mcpsight scan' first`**

`verify` never creates a baseline. Run `scan` once, commit
`.mcpsight/baseline.json`, and then `verify` has something to compare against.

**The server times out**

The default budget is 30s for the whole probe. Servers that install a package on
first run routinely exceed it. Raise it with `--timeout 120s`.

**A server fails to initialize in the sandbox**

It probably needs the network during startup. Retry with `--allow-net`, and note
that egress findings are suppressed for that run.

**Drift fires on every scan**

Something in the manifest is nondeterministic, such as a timestamp or a generated
ID in a description. Check the diff in `report.json`. Genuine nondeterminism in a
tool definition is worth reporting to the maintainer, since it defeats change
detection for everyone.

**Supply-chain findings never appear**

You are running `--offline`, or the runner cannot reach OSV.dev.

**A finding is wrong**

Injection rules are heuristics, and false positives are expected. Point `--rules`
at your own pattern file, then please open an issue. A noisy tool gets
uninstalled in a week, so disputes are genuinely useful.

---

## Known limitations

Stated plainly, because overclaiming would be worse than the gaps:

- Token counts are heuristic estimates, labeled `(est.)`. Real BPE tokenizers are
  a planned drop-in.
- `strace` observation can be evaded by code that is actively trying to evade it.
  The hardened path is designed but not built.
- `npx:` and `uvx:` targets run network-allowed, so egress findings do not fire
  for them. See [Honest limits](#honest-limits).
- Stdio scanning is Linux-only in practice. macOS and Windows handle remote and
  `docker:` targets.
- `--sbom` (CycloneDX) is planned but not implemented.
- Local scan history is `baseline.json` only. The richer SQLite history store is
  deferred, and the drift and verify path does not need it.
- There are no published binaries and no npm wrapper yet. Build from source.

---

## See also

| Document | What it covers |
|---|---|
| [README.md](README.md) | The short version |
| [docs/rubric.md](docs/rubric.md) | The score, in full, versioned |
| [docs/threat-model.md](docs/threat-model.md) | What we defend against, and what we do not |
| [docs/ci.md](docs/ci.md) | Ready-to-use CI workflows |
| [docs/analyzers/README.md](docs/analyzers/README.md) | Writing your own analyzer |
| [docs/phase0-spike.md](docs/phase0-spike.md) | The proof-of-concept behind the sandbox design |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and pull requests |

---

<p align="center">
  © 2026 Greyquill Software Private Limited · Licensed under
  <a href="LICENSE">Apache-2.0</a> · <a href="NOTICE">NOTICE</a>
</p>
