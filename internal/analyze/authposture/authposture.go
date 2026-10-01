// Package authposture evaluates a remote MCP server's authentication and
// transport security from what the probe observed: whether tools/list answers
// with no credentials (large numbers of internet-exposed servers do), and
// whether the transport is plaintext or negotiates weak TLS. Stdio targets have
// no auth posture and are skipped. See docs/rubric.md.
package authposture

import (
	"context"
	"crypto/tls"

	"github.com/greyquill/mcpsight/internal/analyze"
)

// Analyzer implements the auth-posture checks.
type Analyzer struct{}

func (Analyzer) Name() string { return "authposture" }

func (Analyzer) Analyze(_ context.Context, in *analyze.Input) []analyze.Finding {
	ap := in.Auth
	if ap == nil {
		return nil // stdio target — nothing to assess
	}
	var findings []analyze.Finding

	if ap.UnauthenticatedListing {
		findings = append(findings, analyze.Finding{
			Analyzer: "authposture", RuleID: "authposture.unauthenticated_listing", Severity: analyze.High,
			Title: "Server lists its tools without authentication",
			Detail: "tools/list returned successfully with no credentials. Anyone who can reach " +
				"this endpoint can list its tools, and probably call them.",
			Remediation: "Require authentication (OAuth 2.1 or at least a bearer token) before serving tool listings.",
		})
	}

	if ap.Scheme == "http" {
		findings = append(findings, analyze.Finding{
			Analyzer: "authposture", RuleID: "authposture.plaintext_http", Severity: analyze.High,
			Title:       "Server is served over plaintext HTTP",
			Detail:      "The endpoint uses http://, so tool traffic and any credentials travel unencrypted.",
			Remediation: "Serve the MCP endpoint over HTTPS.",
		})
	} else if ap.TLSVersion != 0 && ap.TLSVersion < tls.VersionTLS12 {
		findings = append(findings, analyze.Finding{
			Analyzer: "authposture", RuleID: "authposture.weak_tls", Severity: analyze.Medium,
			Title:       "Server negotiated an outdated TLS version",
			Detail:      "The connection negotiated " + tlsName(ap.TLSVersion) + ", which is deprecated and considered weak.",
			Remediation: "Require TLS 1.2 or higher.",
		})
	}
	return findings
}

func tlsName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	default:
		return "an old TLS/SSL version"
	}
}
