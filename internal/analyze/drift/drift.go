// Package drift detects rug-pulls: it diffs the current manifest against a
// committed baseline and derives finding severity from the DIRECTION of change.
// A shortened description is noise; a description that acquires a hijack
// instruction, or a capability that escalates, is critical. This is the feature
// that keeps mcpsight installed. See docs/rubric.md.
package drift

import (
	"context"
	"regexp"
	"strings"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/analyze/capability"
	"github.com/greyquill/mcpsight/internal/manifest"
)

// hijackPhrases are high-confidence signs a description is trying to steer the
// model. Drift treats one of these APPEARING as critical. The Phase 2 injection
// analyzer owns the fuller pattern set; drift only needs the unambiguous cases.
var hijackPhrases = regexp.MustCompile(`(?i)(ignore (all )?previous|disregard (the )?(above|previous)|do not (tell|inform|mention to) the user|before (calling|using) any other tool|without (telling|informing) the user)`)

// Analyzer implements the drift check.
type Analyzer struct{}

func (Analyzer) Name() string { return "drift" }

// Analyze returns drift findings, or nil on a first scan (no baseline yet — the
// scan command records the baseline separately).
func (Analyzer) Analyze(_ context.Context, in *analyze.Input) []analyze.Finding {
	if in.Baseline == nil || in.Manifest == nil {
		return nil
	}
	baseTools := indexTools(in.Baseline.Tools)
	curTools := indexTools(in.Manifest.Tools)

	var findings []analyze.Finding
	for _, ch := range manifest.Diff(in.Baseline, in.Manifest) {
		if f, ok := classify(ch, baseTools, curTools); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func classify(ch manifest.Change, base, cur map[string]manifest.Tool) (analyze.Finding, bool) {
	f := analyze.Finding{Analyzer: "drift", Tool: ch.Target}
	switch ch.Kind {
	case manifest.ToolDescriptionChanged:
		// Critical only if the NEW text introduces a hijack phrase the old lacked.
		if hijackPhrases.MatchString(ch.After) && !hijackPhrases.MatchString(ch.Before) {
			f.RuleID, f.Severity = "drift.instruction_added", analyze.Critical
			f.Title = "Tool description gained a model-directed instruction"
			f.Detail = "The description of \"" + ch.Target + "\" now contains an instruction " +
				"aimed at the model that was not there in the baseline. This is the classic rug-pull."
			f.Remediation = "Do not upgrade. Inspect the new description and pin the previous version."
			return f, true
		}
		if len(ch.After) < len(ch.Before) {
			f.RuleID, f.Severity = "drift.description_shortened", analyze.Info
			f.Title = "Tool description shortened"
			f.Detail = "The description of \"" + ch.Target + "\" was shortened; usually benign."
			return f, true
		}
		f.RuleID, f.Severity = "drift.description_changed", analyze.Low
		f.Title = "Tool description changed"
		f.Detail = "The description of \"" + ch.Target + "\" changed. Review the new wording."
		return f, true

	case manifest.ToolSchemaChanged:
		if esc := escalated(base[ch.Target], cur[ch.Target]); len(esc) > 0 {
			f.RuleID, f.Severity = "drift.capability_escalated", analyze.High
			f.Title = "Tool capability escalated"
			f.Detail = "The input schema of \"" + ch.Target + "\" changed in a way that adds capability: " +
				strings.Join(esc, ", ") + "."
			f.Remediation = "Confirm the server legitimately needs the new capability before upgrading."
			f.Meta = map[string]any{"added_capabilities": esc}
			return f, true
		}
		f.RuleID, f.Severity = "drift.schema_changed", analyze.Low
		f.Title = "Tool input schema changed"
		f.Detail = "The input schema of \"" + ch.Target + "\" changed."
		return f, true

	case manifest.ToolAdded:
		f.RuleID, f.Severity = "drift.tool_added", analyze.Medium
		f.Title = "New tool appeared"
		f.Detail = "Tool \"" + ch.Target + "\" was not in the baseline. New tools expand the attack surface."
		f.Remediation = "Review the new tool's description and schema as you would a new install."
		return f, true

	case manifest.ToolRemoved:
		f.RuleID, f.Severity = "drift.tool_removed", analyze.Info
		f.Title = "Tool removed"
		f.Detail = "Tool \"" + ch.Target + "\" is no longer present. Reduced surface, but may break callers."
		return f, true

	case manifest.ServerVersionChanged:
		f.RuleID, f.Severity = "drift.server_version_changed", analyze.Info
		f.Title = "Server version changed"
		f.Detail = "Server version changed from " + ch.Before + " to " + ch.After + "."
		return f, true

	case manifest.ResourceAdded, manifest.PromptAdded:
		f.RuleID, f.Severity = "drift."+string(ch.Kind), analyze.Low
		f.Title = "New " + kindNoun(ch.Kind) + " appeared"
		f.Detail = "\"" + ch.Target + "\" was not in the baseline."
		return f, true

	case manifest.ResourceRemoved, manifest.PromptRemoved:
		f.RuleID, f.Severity = "drift."+string(ch.Kind), analyze.Info
		f.Title = kindNoun(ch.Kind) + " removed"
		f.Detail = "\"" + ch.Target + "\" is no longer present."
		return f, true
	}
	return analyze.Finding{}, false
}

// escalated returns capability classes present in cur but not in base.
func escalated(base, cur manifest.Tool) []string {
	had := map[string]bool{}
	for _, c := range capability.ClassifyTool(base) {
		had[c] = true
	}
	var added []string
	for _, c := range capability.ClassifyTool(cur) {
		if !had[c] {
			added = append(added, c)
		}
	}
	return added
}

func indexTools(ts []manifest.Tool) map[string]manifest.Tool {
	m := make(map[string]manifest.Tool, len(ts))
	for _, t := range ts {
		m[t.Name] = t
	}
	return m
}

func kindNoun(k manifest.ChangeKind) string {
	if strings.HasPrefix(string(k), "resource") {
		return "resource"
	}
	return "prompt"
}
