package scan_test

import (
	"context"
	"testing"

	"github.com/greyquill/mcpsight/internal/scan"
	"github.com/greyquill/mcpsight/internal/target"
)

func rules(rep *scan.Report) map[string]bool {
	m := map[string]bool{}
	for _, f := range rep.Findings {
		m[f.RuleID] = true
	}
	return m
}

// End to end: an unauthenticated plaintext-HTTP server (httptest is plain http)
// should trip both auth-posture rules through the full probe + scan pipeline.
func TestAuthPostureUnauthenticatedHTTP(t *testing.T) {
	srv := mockServer(t, []map[string]any{{"name": "t", "description": "a tool"}})
	defer srv.Close()

	tgt, _ := target.Resolve(srv.URL)
	rep, err := scan.Run(context.Background(), tgt, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := rules(rep)
	if !r["authposture.unauthenticated_listing"] {
		t.Error("expected unauthenticated_listing finding")
	}
	if !r["authposture.plaintext_http"] {
		t.Error("expected plaintext_http finding for an http:// endpoint")
	}
}
