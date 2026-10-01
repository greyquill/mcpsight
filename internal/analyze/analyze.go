// Package analyze defines the shared vocabulary of the scan: Severity,
// Finding, and the Analyzer interface. Each analyzer is independent,
// parallelizable, and individually toggleable — adding one is a self-contained
// package under internal/analyze/*.
package analyze

import (
	"context"

	"github.com/greyquill/mcpsight/internal/manifest"
)

// Severity ranks a finding. The string values are stable (they appear in JSON,
// SARIF, and the baseline) and their penalties live in the score package, which
// implements the published rubric (docs/rubric.md).
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// rank orders severities for sorting (higher is more severe).
func (s Severity) rank() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// MoreSevereThan reports whether s outranks other.
func (s Severity) MoreSevereThan(other Severity) bool { return s.rank() > other.rank() }

// Finding is one issue an analyzer reports. RuleID is the stable, namespaced
// identifier (e.g. "injection.override_instruction") that maps to a row in
// docs/rubric.md; the scorer derives penalties from Severity, and remediation
// turns a report into an actionable pull request.
type Finding struct {
	Analyzer    string         `json:"analyzer"`
	RuleID      string         `json:"rule_id"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Detail      string         `json:"detail,omitempty"`
	Tool        string         `json:"tool,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
}

// Input bundles everything an analyzer may consult. Fields are nil when not
// available: Baseline is nil on a first scan; Trace is nil for remote targets
// and for declared-only (Phase 1) capability analysis; Package is nil until the
// supply-chain analyzer populates it. Analyzers must tolerate nil inputs.
type Input struct {
	Target   string
	Manifest *manifest.Manifest
	Baseline *manifest.Manifest
	Trace    *SandboxTrace
	Package  *PackageMeta

	// PackageSpec and Ecosystem identify the published package for the
	// supply-chain analyzer (e.g. "@scope/name@1.2.3", "npm"). Empty for remote
	// and local targets, which have no registry package to inspect.
	PackageSpec string
	Ecosystem   string
	// Offline disables analyzers that need network access (supply-chain).
	Offline bool
	// Auth carries the remote auth/TLS posture the probe observed; nil for
	// stdio targets. Consumed by the auth-posture analyzer.
	Auth *AuthPosture
}

// AuthPosture records what the probe observed about a remote server's
// authentication and transport security.
type AuthPosture struct {
	Scheme                 string // "https" | "http"
	TLSVersion             uint16 // negotiated tls.Version, 0 if none
	UnauthenticatedListing bool   // tools/list succeeded with no credentials
	RequiresAuth           bool   // credentials were supplied and needed
}

// SandboxTrace holds observed behavior from a sandbox run: what the server
// actually did during the probe, as distinct from what it declared.
type SandboxTrace struct {
	DecoyReads  []string // decoy credential paths the server read (relative to home)
	EgressHosts []string // external addresses it attempted to connect to
	DNSResolve  []string // resolver/DNS connection attempts (distinct from raw egress)
	// NetDenied records whether the run had the network denied. When true, an
	// egress attempt is unambiguously the server's own (nothing else could have
	// made it), so it is finding-worthy; when false (e.g. an npx run that needs
	// the network to install), egress cannot be cleanly attributed to the server.
	NetDenied bool
}

// PackageMeta holds supply-chain metadata (Phase 2). Declared here for the same
// reason as SandboxTrace.
type PackageMeta struct {
	Source          string
	HasInstallHook  bool
	DependencyCount int
	SourceAvailable bool
}

// Analyzer inspects an Input and returns findings. Implementations must be pure
// with respect to Input (no mutation) so they can run in parallel.
type Analyzer interface {
	// Name is the analyzer's stable identifier, used in Finding.Analyzer and
	// for --only/--skip selection.
	Name() string
	Analyze(ctx context.Context, in *Input) []Finding
}
