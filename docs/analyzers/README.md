# Analyzers

An analyzer inspects a scanned server and returns findings. Each one is an
independent, self-contained package under `internal/analyze/<name>/`, so adding
an analyzer is a single reviewable PR. That is how outside contributors arrive.

## The current set

| Analyzer | Package | Network? | What it finds |
|---|---|---|---|
| Context cost | `contextcost` | no | Token cost per model, schema bloat |
| Capability | `capability` | no | Declared *and* observed (sandbox) capability, the gap between them |
| Injection | `injection` | no | Tool-poisoning / prompt-injection in descriptions (YAML rules + structural detectors) |
| Supply chain | `supplychain` | **yes** | Install scripts, source availability, OSV CVEs, typosquat |
| Auth posture | `authposture` | (via probe) | Unauthenticated listing, plaintext HTTP, weak TLS (remote only) |
| Drift | `drift` | no | Structural diff vs the committed baseline; severity by direction of change |

Every rule ID maps to a row in [`../rubric.md`](../rubric.md). The scorer derives
penalties from a finding's `Severity`, nothing else.

## The interface

```go
// internal/analyze/analyze.go
type Analyzer interface {
    Name() string
    Analyze(ctx context.Context, in *Input) []Finding
}
```

`Input` bundles everything an analyzer may read. Any field may be nil, so
tolerate that:

| Field | Present when |
|---|---|
| `Manifest` | always |
| `Baseline` | a prior baseline exists (not the first scan). Used by drift. |
| `Trace` | a sandbox run happened (stdio targets). Used for observed capability. |
| `Auth` | a remote target was probed. Used by auth posture. |
| `PackageSpec` / `Ecosystem` | the target is a published package. Used by supply chain. |
| `Offline` | the user passed `--offline`; network analyzers must no-op |

Analyzers must be **pure with respect to `Input`** (no mutation) so they can run
in parallel. Except for the explicitly networked ones, they must run **offline**
with no API key.

## Adding an analyzer, end to end

1. **Create the package** `internal/analyze/<name>/<name>.go` implementing the
   interface. Return findings with stable, namespaced rule IDs
   (`<name>.<rule>`), a clear `Title`, a `Detail`, and a `Remediation`. The
   remediation is what turns a report into a pull request.
2. **Register it** in `internal/scan/scan.go` (`analyzers()`), one line.
3. **Document the rules** in `docs/rubric.md`: add a row per rule with its
   default severity, traced to a threat in `docs/threat-model.md`. If you change
   any severity, penalty, or band, bump `RubricVersion` in
   `internal/buildinfo/buildinfo.go` and note it in the rubric. Never silently
   re-grade history.
4. **Add a fixture** in `testdata/servers/` that your analyzer catches (the
   fixtures are the spec) and a unit test constructing an `Input` directly.
   Include a false-positive guard against `benign-docs`.
5. `make test && go vet ./... && gofmt -w .`

### Severity, honestly

Conservative defaults. A noisy analyzer gets the tool uninstalled in a week.
Prefer `info`/`low` when unsure; reserve `critical`
for confirmed exploitation (a decoy-credential read, an active model-hijack
instruction).

## Extending the injection rules without code

The injection analyzer's text patterns live in
[`../../internal/analyze/injection/rules/patterns.yaml`](../../internal/analyze/injection/rules/patterns.yaml)
(embedded by default, overridable with `--rules`). Add or dispute a pattern by
editing that YAML. You don't need to write Go. Structural detectors (invisible characters,
encoded blobs, length) are in code because regex can't express them.
