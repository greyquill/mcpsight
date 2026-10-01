package score

import (
	"testing"

	"github.com/greyquill/mcpsight/internal/analyze"
)

func TestComputeWorkedExample(t *testing.T) {
	// From docs/rubric.md: one high unauthenticated listing (-20) and one medium
	// encoded blob (-8) => 72 => grade C.
	findings := []analyze.Finding{
		{RuleID: "authposture.unauthenticated_listing", Severity: analyze.High},
		{RuleID: "injection.encoded_blob", Severity: analyze.Medium, Tool: "x"},
	}
	sc := Compute(findings)
	if sc.Score != 72 || sc.Grade != "C" || sc.Capped {
		t.Errorf("want 72/C uncapped, got %d/%s capped=%v", sc.Score, sc.Grade, sc.Capped)
	}

	// Add a critical decoy read (-40) => 32, already under the cap => F.
	findings = append(findings, analyze.Finding{RuleID: "capability.decoy_read", Severity: analyze.Critical, Tool: "x"})
	sc = Compute(findings)
	if sc.Score != 32 || sc.Grade != "F" {
		t.Errorf("want 32/F, got %d/%s", sc.Score, sc.Grade)
	}
}

func TestCriticalCapsAtF(t *testing.T) {
	// A lone critical would leave 60 (C). The cap holds it at 39 (F).
	sc := Compute([]analyze.Finding{{RuleID: "capability.decoy_read", Severity: analyze.Critical, Tool: "x"}})
	if sc.Score != 39 || sc.Grade != "F" || !sc.Capped {
		t.Errorf("want 39/F capped, got %d/%s capped=%v", sc.Score, sc.Grade, sc.Capped)
	}
}

func TestPerRulePerToolDedup(t *testing.T) {
	// The same rule firing many times on the SAME tool counts once...
	same := []analyze.Finding{
		{RuleID: "injection.imperative_instruction", Severity: analyze.High, Tool: "t"},
		{RuleID: "injection.imperative_instruction", Severity: analyze.High, Tool: "t"},
		{RuleID: "injection.imperative_instruction", Severity: analyze.High, Tool: "t"},
	}
	if sc := Compute(same); sc.Score != 80 {
		t.Errorf("same rule+tool should count once (-20 => 80), got %d", sc.Score)
	}
	// ...but the same rule on DIFFERENT tools counts each.
	diff := []analyze.Finding{
		{RuleID: "injection.imperative_instruction", Severity: analyze.High, Tool: "a"},
		{RuleID: "injection.imperative_instruction", Severity: analyze.High, Tool: "b"},
	}
	if sc := Compute(diff); sc.Score != 60 {
		t.Errorf("distinct tools should each count (-40 => 60), got %d", sc.Score)
	}
}

func TestCleanServerScoresA(t *testing.T) {
	sc := Compute(nil)
	if sc.Score != 100 || sc.Grade != "A" {
		t.Errorf("clean server should be 100/A, got %d/%s", sc.Score, sc.Grade)
	}
	// Info findings never subtract.
	sc = Compute([]analyze.Finding{{RuleID: "context.oversized_tool", Severity: analyze.Info}})
	if sc.Score != 100 {
		t.Errorf("info must not subtract, got %d", sc.Score)
	}
}
