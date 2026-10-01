package capability

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/manifest"
)

func has(classes []string, want string) bool {
	for _, c := range classes {
		if c == want {
			return true
		}
	}
	return false
}

func TestClassifyFromSchemaAndText(t *testing.T) {
	cases := []struct {
		tool manifest.Tool
		want string
	}{
		{manifest.Tool{Name: "run_command", Description: "Execute a shell command", InputSchema: json.RawMessage(`{"properties":{"command":{"type":"string"}}}`)}, ExecShell},
		{manifest.Tool{Name: "fetch_url", Description: "Download a URL", InputSchema: json.RawMessage(`{"properties":{"url":{"type":"string"}}}`)}, NetEgress},
		{manifest.Tool{Name: "read_file", Description: "Read a file from disk", InputSchema: json.RawMessage(`{"properties":{"path":{"type":"string"}}}`)}, FSRead},
		{manifest.Tool{Name: "get_secret", Description: "Return a stored credential"}, SecretRead},
		{manifest.Tool{Name: "eval", Description: "Evaluate a python expression", InputSchema: json.RawMessage(`{"properties":{"code":{"type":"string"}}}`)}, CodeEval},
	}
	for _, c := range cases {
		got := ClassifyTool(c.tool)
		if !has(got, c.want) {
			t.Errorf("tool %q: want class %s, got %v", c.tool.Name, c.want, got)
		}
	}
}

func TestBenignToolHasNoDangerousClass(t *testing.T) {
	// A pure math tool should not trip shell/eval/secret classifiers.
	got := ClassifyTool(manifest.Tool{Name: "add", Description: "Add two numbers", InputSchema: json.RawMessage(`{"properties":{"a":{"type":"number"},"b":{"type":"number"}}}`)})
	for _, bad := range []string{ExecShell, CodeEval, SecretRead} {
		if has(got, bad) {
			t.Errorf("benign add tool wrongly classified as %s: %v", bad, got)
		}
	}
}

func TestObservedDecoyReadIsCritical(t *testing.T) {
	in := &analyze.Input{
		Manifest: &manifest.Manifest{Tools: []manifest.Tool{{Name: "x", Description: "docs"}}},
		Trace:    &analyze.SandboxTrace{DecoyReads: []string{".ssh/id_rsa"}, NetDenied: true},
	}
	var crit bool
	for _, f := range (Analyzer{}).Analyze(context.Background(), in) {
		if f.RuleID == "capability.decoy_read" && f.Severity == analyze.Critical {
			crit = true
		}
	}
	if !crit {
		t.Error("a decoy read must produce a critical capability.decoy_read finding")
	}
}

func TestObservedEgressGapOnDeniedNet(t *testing.T) {
	in := &analyze.Input{
		Manifest: &manifest.Manifest{Tools: []manifest.Tool{{Name: "add", Description: "add two numbers"}}},
		Trace:    &analyze.SandboxTrace{EgressHosts: []string{"203.0.113.7:443"}, NetDenied: true},
	}
	got := map[string]analyze.Severity{}
	for _, f := range (Analyzer{}).Analyze(context.Background(), in) {
		got[f.RuleID] = f.Severity
	}
	if got["capability.egress_unexpected"] != analyze.High {
		t.Error("egress on a denied-net run should be high")
	}
	if got["capability.declared_observed_gap"] != analyze.High {
		t.Error("undeclared egress should flag a declared-vs-observed gap")
	}
}

func TestNoEgressFindingWhenNetAllowed(t *testing.T) {
	// With the network allowed (e.g. npx install), egress cannot be attributed.
	in := &analyze.Input{
		Manifest: &manifest.Manifest{Tools: []manifest.Tool{{Name: "x", Description: "d"}}},
		Trace:    &analyze.SandboxTrace{EgressHosts: []string{"1.2.3.4:443"}, NetDenied: false},
	}
	for _, f := range (Analyzer{}).Analyze(context.Background(), in) {
		if f.RuleID == "capability.egress_unexpected" {
			t.Error("must not flag egress when the network was allowed")
		}
	}
}

func TestCommonWordsDoNotOverclassify(t *testing.T) {
	// A search tool's "query" is not a database write, and "file system" in
	// prose is not shell execution.
	cases := []struct {
		tool manifest.Tool
		bad  string
	}{
		{manifest.Tool{Name: "search_docs", Description: "Search the documentation for a query string.", InputSchema: json.RawMessage(`{"properties":{"query":{"type":"string"}}}`)}, DBWrite},
		{manifest.Tool{Name: "stat", Description: "Report free space on the file system."}, ExecShell},
	}
	for _, c := range cases {
		if got := ClassifyTool(c.tool); has(got, c.bad) {
			t.Errorf("tool %q wrongly classified as %s: %v", c.tool.Name, c.bad, got)
		}
	}
}

func TestUnobservedRunSaysSo(t *testing.T) {
	in := &analyze.Input{
		Manifest:   &manifest.Manifest{Tools: []manifest.Tool{{Name: "x", Description: "docs"}}},
		Unobserved: "strace is not installed",
	}
	var got *analyze.Finding
	for _, f := range (Analyzer{}).Analyze(context.Background(), in) {
		if f.RuleID == "capability.not_observed" {
			got = &f
		}
	}
	if got == nil {
		t.Fatal("an unobserved stdio run must produce capability.not_observed")
	}
	if got.Severity != analyze.Info {
		t.Errorf("severity = %s, want info", got.Severity)
	}
	if !strings.Contains(got.Detail, "strace is not installed") {
		t.Errorf("detail should carry the reason, got %q", got.Detail)
	}
}

func TestObservedRunHasNoNotObservedFinding(t *testing.T) {
	in := &analyze.Input{
		Manifest: &manifest.Manifest{Tools: []manifest.Tool{{Name: "x", Description: "docs"}}},
		Trace:    &analyze.SandboxTrace{NetDenied: true},
	}
	for _, f := range (Analyzer{}).Analyze(context.Background(), in) {
		if f.RuleID == "capability.not_observed" {
			t.Error("a traced run must not report capability.not_observed")
		}
	}
}
