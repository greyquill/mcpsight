// Package supplychain assesses the risk of the published package behind a
// server: install scripts, source availability, dependency count, known CVEs
// (OSV.dev), and typosquatting. Unlike the injection analyzer this one uses the
// network (registry + OSV), and degrades gracefully when offline or when the
// target is not a package (remote/local).
package supplychain

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/greyquill/mcpsight/internal/analyze"
)

// youngDays is the age below which a package is flagged as immature.
const youngDays = 30

// Analyzer performs the supply-chain checks.
type Analyzer struct {
	client *http.Client
}

// New returns a supply-chain analyzer with a bounded HTTP client.
func New() *Analyzer {
	return &Analyzer{client: &http.Client{Timeout: 12 * time.Second}}
}

func (*Analyzer) Name() string { return "supplychain" }

func (a *Analyzer) Analyze(ctx context.Context, in *analyze.Input) []analyze.Finding {
	if in.PackageSpec == "" || in.Offline {
		return nil // nothing to inspect, or network disabled
	}
	name, version := splitSpec(in.PackageSpec)

	// Typosquat is offline-cheap and does not need registry metadata.
	var findings []analyze.Finding
	if sq, ok := nearestSquat(name); ok {
		detail := fmt.Sprintf("%q is one or two keystrokes from %q. Typosquatting is how malicious packages get installed by mistake.", name, sq.target)
		if sq.sameName {
			detail = fmt.Sprintf("%q has the same name as %q under a different scope. Publishing a popular name under another scope is a common way to get a malicious package installed.", name, sq.target)
		}
		findings = append(findings, analyze.Finding{
			Analyzer: "supplychain", RuleID: "supplychain.typosquat", Severity: analyze.High,
			Title:       "Package name resembles a popular package",
			Detail:      detail,
			Remediation: fmt.Sprintf("Confirm you meant %q and not %q.", name, sq.target),
			Meta:        map[string]any{"suspected_target": sq.target},
		})
	}

	info, err := fetch(ctx, a.client, in.Ecosystem, name, version)
	if err != nil {
		return append(findings, analyze.Finding{
			Analyzer: "supplychain", RuleID: "supplychain.metadata_unavailable", Severity: analyze.Info,
			Title:  "Supply-chain metadata could not be fetched",
			Detail: "Registry metadata for this package was unavailable (" + err.Error() + "); supply-chain checks were skipped.",
		})
	}

	if info.HasInstallScript {
		findings = append(findings, analyze.Finding{
			Analyzer: "supplychain", RuleID: "supplychain.install_script", Severity: analyze.High,
			Title:       "Package runs an install script",
			Detail:      "This package declares an install/postinstall script, which runs arbitrary code on your machine at install time, before you ever call a tool.",
			Remediation: "Install with scripts disabled and review what the script does, or avoid the package.",
		})
	}
	if info.RepoURL == "" {
		findings = append(findings, analyze.Finding{
			Analyzer: "supplychain", RuleID: "supplychain.no_source", Severity: analyze.Medium,
			Title:       "No source repository is published",
			Detail:      "The package publishes no resolvable source repository, so you cannot audit what you are running.",
			Remediation: "Prefer packages that publish a source repository you can read.",
		})
	}
	if info.Ecosystem == "npm" && info.MaintainerCount == 1 {
		findings = append(findings, analyze.Finding{
			Analyzer: "supplychain", RuleID: "supplychain.single_maintainer", Severity: analyze.Low,
			Title:       "Single-maintainer package",
			Detail:      "Only one maintainer publishes this package. If that account is lost or taken over, nobody else can respond.",
			Remediation: "Weigh the dependency risk; a single compromised account can push a malicious version.",
		})
	}
	if !info.Created.IsZero() && time.Since(info.Created) < youngDays*24*time.Hour {
		findings = append(findings, analyze.Finding{
			Analyzer: "supplychain", RuleID: "supplychain.young_package", Severity: analyze.Low,
			Title:       "Very new package",
			Detail:      fmt.Sprintf("This package was first published %d days ago; new packages are the typical vehicle for typosquats.", int(time.Since(info.Created).Hours()/24)),
			Remediation: "Be cautious installing brand-new packages.",
		})
	}

	// Known vulnerabilities (OSV). Absence of a result means "unknown", not "clean".
	if vulns, err := queryOSV(ctx, a.client, name, info.Version, info.Ecosystem); err == nil {
		for _, v := range vulns {
			findings = append(findings, analyze.Finding{
				Analyzer: "supplychain", RuleID: "supplychain.known_cve", Severity: cveSeverity(v.Severity),
				Title:       "Known vulnerability: " + v.ID,
				Detail:      strings.TrimSpace(v.Summary),
				Remediation: "Upgrade to a fixed version; see https://osv.dev/vulnerability/" + v.ID,
				Meta:        map[string]any{"id": v.ID, "osv_severity": v.Severity},
			})
		}
	}
	return findings
}

// fetch dispatches to the right registry client by ecosystem.
func fetch(ctx context.Context, client *http.Client, ecosystem, name, version string) (*PackageInfo, error) {
	switch ecosystem {
	case "npm":
		return fetchNPM(ctx, client, name, version)
	case "PyPI", "pypi":
		return fetchPyPI(ctx, client, name, version)
	default:
		return nil, fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
}

// splitSpec parses "name@version" (and scoped "@scope/name@version"), returning
// name and version (version may be empty).
func splitSpec(spec string) (string, string) {
	at := strings.LastIndex(spec, "@")
	if at <= 0 { // no version, or the only @ is the scope prefix
		return spec, ""
	}
	return spec[:at], spec[at+1:]
}

func cveSeverity(osv string) analyze.Severity {
	switch strings.ToUpper(osv) {
	case "CRITICAL", "HIGH":
		return analyze.High
	case "MODERATE", "MEDIUM", "LOW":
		return analyze.Medium
	default:
		return analyze.Medium
	}
}
