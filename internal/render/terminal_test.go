package render

import (
	"testing"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/scan"
	"github.com/greyquill/mcpsight/internal/score"
)

func TestGradeNote(t *testing.T) {
	unobserved := analyze.Finding{RuleID: "capability.not_observed", Severity: analyze.Info}
	cases := []struct {
		name string
		r    scan.Report
		want string
	}{
		{"plain", scan.Report{}, ""},
		{"capped", scan.Report{Score: score.Scorecard{Capped: true}}, ", capped by a critical finding"},
		{"unobserved", scan.Report{Findings: []analyze.Finding{unobserved}}, ", behavior not observed"},
		{"both", scan.Report{Score: score.Scorecard{Capped: true}, Findings: []analyze.Finding{unobserved}},
			", capped by a critical finding, behavior not observed"},
	}
	for _, c := range cases {
		if got := gradeNote(&c.r); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
