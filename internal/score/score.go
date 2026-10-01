// Package score implements the published, versioned scoring rubric
// (docs/rubric.md). The mapping from findings to a grade is deliberately simple
// and transparent: anyone must be able to recompute a score by hand from the
// findings. If this logic and docs/rubric.md ever disagree, that is a bug.
package score

import (
	"sort"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/buildinfo"
)

// penalties are the per-severity point deductions defined in docs/rubric.md.
// Changing these REQUIRES bumping buildinfo.RubricVersion and docs/rubric.md.
var penalties = map[analyze.Severity]int{
	analyze.Critical: 40,
	analyze.High:     20,
	analyze.Medium:   8,
	analyze.Low:      3,
	analyze.Info:     0,
}

// criticalCap is the highest score a server with any critical finding can get:
// the top of the F band. The rubric says one critical is enough to fail.
const criticalCap = 39

// Scorecard is the computed grade plus the arithmetic behind it, so the report
// can show every subtraction and the reader can check it.
type Scorecard struct {
	Score         int            `json:"score"`
	Grade         string         `json:"grade"`
	RubricVersion int            `json:"rubric_version"`
	Deductions    []Deduction    `json:"deductions"`
	CountBySev    map[string]int `json:"count_by_severity"`
	// Capped is set when a critical finding held the score at criticalCap.
	Capped bool `json:"capped,omitempty"`
}

// Deduction records one applied penalty (after per-rule-per-tool deduplication).
type Deduction struct {
	RuleID   string           `json:"rule_id"`
	Tool     string           `json:"tool,omitempty"`
	Severity analyze.Severity `json:"severity"`
	Points   int              `json:"points"`
}

// Compute derives a Scorecard from findings per rubric v1: start at 100,
// subtract each severity's penalty, but count each (rule, tool) pair at most
// once so a single issue cannot nuke a score repeatedly. Floors at 0. Any
// critical finding caps the score at 39, so it always grades F.
func Compute(findings []analyze.Finding) Scorecard {
	seen := map[[2]string]bool{}
	sc := Scorecard{
		Score:         100,
		RubricVersion: buildinfo.RubricVersion,
		CountBySev:    map[string]int{},
	}
	for _, f := range findings {
		sc.CountBySev[string(f.Severity)]++
		key := [2]string{f.RuleID, f.Tool}
		if seen[key] {
			continue
		}
		seen[key] = true
		p := penalties[f.Severity]
		if p == 0 {
			continue
		}
		sc.Score -= p
		sc.Deductions = append(sc.Deductions, Deduction{
			RuleID: f.RuleID, Tool: f.Tool, Severity: f.Severity, Points: p,
		})
	}
	if sc.Score < 0 {
		sc.Score = 0
	}
	if sc.CountBySev[string(analyze.Critical)] > 0 && sc.Score > criticalCap {
		sc.Score = criticalCap
		sc.Capped = true
	}
	sort.SliceStable(sc.Deductions, func(i, j int) bool {
		return sc.Deductions[i].Points > sc.Deductions[j].Points
	})
	sc.Grade = grade(sc.Score)
	return sc
}

// grade maps a 0-100 score to a letter per the rubric's bands.
func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
