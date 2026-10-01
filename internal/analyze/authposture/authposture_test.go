package authposture

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/greyquill/mcpsight/internal/analyze"
)

func ruleSet(fs []analyze.Finding) map[string]analyze.Severity {
	m := map[string]analyze.Severity{}
	for _, f := range fs {
		m[f.RuleID] = f.Severity
	}
	return m
}

func TestStdioTargetSkipped(t *testing.T) {
	if fs := (Analyzer{}).Analyze(context.Background(), &analyze.Input{Auth: nil}); fs != nil {
		t.Errorf("stdio target (no Auth) must yield no findings, got %v", fs)
	}
}

func TestAuthenticatedHTTPSIsClean(t *testing.T) {
	in := &analyze.Input{Auth: &analyze.AuthPosture{
		Scheme: "https", TLSVersion: tls.VersionTLS13, RequiresAuth: true, UnauthenticatedListing: false,
	}}
	if fs := (Analyzer{}).Analyze(context.Background(), in); len(fs) != 0 {
		t.Errorf("a TLS-1.3, authenticated server should be clean, got %v", fs)
	}
}

func TestUnauthenticatedIsHigh(t *testing.T) {
	in := &analyze.Input{Auth: &analyze.AuthPosture{Scheme: "https", TLSVersion: tls.VersionTLS13, UnauthenticatedListing: true}}
	if got := ruleSet(Analyzer{}.Analyze(context.Background(), in)); got["authposture.unauthenticated_listing"] != analyze.High {
		t.Errorf("unauthenticated listing should be high, got %v", got)
	}
}

func TestWeakTLSIsMedium(t *testing.T) {
	in := &analyze.Input{Auth: &analyze.AuthPosture{Scheme: "https", TLSVersion: tls.VersionTLS11, RequiresAuth: true}}
	got := ruleSet(Analyzer{}.Analyze(context.Background(), in))
	if got["authposture.weak_tls"] != analyze.Medium {
		t.Errorf("TLS 1.1 should flag weak_tls medium, got %v", got)
	}
	if _, ok := got["authposture.plaintext_http"]; ok {
		t.Error("https must not flag plaintext_http")
	}
}
