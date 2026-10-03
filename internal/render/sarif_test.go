package render

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/scan"
)

func runOf(t *testing.T, reports []*scan.Report) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := SARIF(&buf, reports); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []map[string]any `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Runs[0]
}

// A clean scan must produce "results": [], or code scanning rejects the upload.
func TestSARIFCleanScanHasEmptyResults(t *testing.T) {
	run := runOf(t, []*scan.Report{{}})
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("results = %#v, want an empty array", run["results"])
	}
	if len(results) != 0 {
		t.Fatalf("got %d results for a clean scan", len(results))
	}
}

func TestSARIFRulesAreSorted(t *testing.T) {
	r := &scan.Report{Findings: []analyze.Finding{
		{RuleID: "injection.unrelated_path", Severity: analyze.High},
		{RuleID: "authposture.plaintext_http", Severity: analyze.High},
		{RuleID: "drift.tool_added", Severity: analyze.Medium},
	}}
	for i := 0; i < 5; i++ {
		rules := runOf(t, []*scan.Report{r})["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
		var ids []string
		for _, x := range rules {
			ids = append(ids, x.(map[string]any)["id"].(string))
		}
		want := []string{"authposture.plaintext_http", "drift.tool_added", "injection.unrelated_path"}
		for k := range want {
			if ids[k] != want[k] {
				t.Fatalf("rules out of order: %v", ids)
			}
		}
	}
}
