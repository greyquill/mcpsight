// Package scan orchestrates a single server scan end to end: probe the target,
// run every analyzer over the resulting manifest (plus an optional baseline for
// drift), score the findings against the rubric, and assemble a Report. It does
// not persist anything — recording baselines and writing artifacts is the CLI's
// job, so `verify` can run the same analysis without side effects.
package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/analyze/authposture"
	"github.com/greyquill/mcpsight/internal/analyze/capability"
	"github.com/greyquill/mcpsight/internal/analyze/contextcost"
	"github.com/greyquill/mcpsight/internal/analyze/drift"
	"github.com/greyquill/mcpsight/internal/analyze/injection"
	"github.com/greyquill/mcpsight/internal/analyze/supplychain"
	"github.com/greyquill/mcpsight/internal/buildinfo"
	"github.com/greyquill/mcpsight/internal/manifest"
	"github.com/greyquill/mcpsight/internal/probe"
	"github.com/greyquill/mcpsight/internal/score"
	"github.com/greyquill/mcpsight/internal/target"
)

// BaselineState describes how the current manifest relates to the baseline.
type BaselineState string

const (
	BaselineFirstScan BaselineState = "first_scan" // no baseline recorded yet
	BaselineUnchanged BaselineState = "unchanged"  // hash matches the baseline
	BaselineDrifted   BaselineState = "drifted"    // hash differs from the baseline
)

// Report is the full result of scanning one server.
type Report struct {
	Target        target.Target       `json:"target"`
	Server        manifest.ServerInfo `json:"server"`
	ManifestHash  string              `json:"manifest_hash"`
	Runner        string              `json:"runner"`
	ContextCost   contextcost.Report  `json:"context_cost"`
	Capabilities  capability.Summary  `json:"capabilities"`
	Findings      []analyze.Finding   `json:"findings"`
	Score         score.Scorecard     `json:"score"`
	BaselineState BaselineState       `json:"baseline_state"`
	Manifest      *manifest.Manifest  `json:"-"` // available to the caller for recording
	ToolVersion   string              `json:"mcpsight_version"`
	RubricVersion int                 `json:"rubric_version"`
	ScannedAt     string              `json:"scanned_at"`
	DurationMs    int64               `json:"duration_ms"`
}

// analyzers is the registered set, run in order. Adding an analyzer is a
// one-line change here plus its package (see docs/analyzers/README.md). The
// injection analyzer compiles its embedded rule set at construction; a failure
// there is a build-time bug in the rules, so we surface it rather than hide it.
// rulesPath, when non-empty, replaces the embedded rules with a user-supplied
// set so maintainers can tighten, loosen, or dispute the defaults.
func analyzers(rulesPath string) ([]analyze.Analyzer, error) {
	inj, err := newInjection(rulesPath)
	if err != nil {
		return nil, err
	}
	return []analyze.Analyzer{
		contextcost.Analyzer{},
		capability.Analyzer{},
		inj,
		supplychain.New(),
		authposture.Analyzer{},
		drift.Analyzer{},
	}, nil
}

// newInjection builds the injection analyzer, preferring a custom rule file.
func newInjection(rulesPath string) (*injection.Analyzer, error) {
	if rulesPath == "" {
		return injection.New()
	}
	rs, err := injection.LoadRuleSet(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("loading rules from %s: %w", rulesPath, err)
	}
	return injection.NewWithRules(rs), nil
}

// Options configures a scan.
type Options struct {
	Probe    probe.Options
	Baseline *manifest.Manifest // prior manifest for drift; nil on first scan
	Offline  bool               // disable network analyzers (supply-chain)
	Rules    string             // custom injection rule file; embedded set if empty
	Now      time.Time          // scan timestamp; time.Now() if zero
}

// ecosystem maps a target kind to the package ecosystem the supply-chain
// analyzer queries.
func ecosystem(k target.Kind) string {
	switch k {
	case target.KindNPX:
		return "npm"
	case target.KindUVX:
		return "PyPI"
	default:
		return ""
	}
}

// Run probes the target and produces a Report. The optional baseline manifest
// enables drift findings.
func Run(ctx context.Context, t target.Target, opts Options) (*Report, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	start := now

	res, err := probe.Probe(ctx, t, opts.Probe)
	if err != nil {
		return nil, err
	}
	m := res.Manifest
	hash, err := m.Hash()
	if err != nil {
		return nil, err
	}

	in := &analyze.Input{
		Target:      t.Name,
		Manifest:    m,
		Baseline:    opts.Baseline,
		Trace:       res.Trace,
		Auth:        res.Auth,
		PackageSpec: t.Package,
		Ecosystem:   ecosystem(t.Kind),
		Offline:     opts.Offline,
	}
	registered, err := analyzers(opts.Rules)
	if err != nil {
		return nil, err
	}
	var findings []analyze.Finding
	for _, a := range registered {
		findings = append(findings, a.Analyze(ctx, in)...)
	}

	rep := &Report{
		Target:        t,
		Server:        m.Server,
		ManifestHash:  hash,
		Runner:        res.Runner,
		ContextCost:   contextcost.Compute(m),
		Capabilities:  capability.Classify(m),
		Findings:      findings,
		Score:         score.Compute(findings),
		BaselineState: baselineState(opts.Baseline, hash),
		Manifest:      m,
		ToolVersion:   buildinfo.Version,
		RubricVersion: buildinfo.RubricVersion,
		ScannedAt:     now.UTC().Format(time.RFC3339),
		DurationMs:    time.Since(start).Milliseconds(),
	}
	return rep, nil
}

func baselineState(baseline *manifest.Manifest, hash string) BaselineState {
	if baseline == nil {
		return BaselineFirstScan
	}
	if bh, err := baseline.Hash(); err == nil && bh == hash {
		return BaselineUnchanged
	}
	return BaselineDrifted
}

// MaxSeverity returns the most severe finding severity in the report, or Info
// if there are none. Used by --fail-on and exit-code logic.
func (r *Report) MaxSeverity() analyze.Severity {
	max := analyze.Info
	for _, f := range r.Findings {
		if f.Severity.MoreSevereThan(max) {
			max = f.Severity
		}
	}
	return max
}
