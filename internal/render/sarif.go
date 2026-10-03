package render

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/buildinfo"
	"github.com/greyquill/mcpsight/internal/scan"
)

// SARIF writes findings as SARIF 2.1.0, which GitHub code scanning ingests
// natively — free distribution for the tool and CI-native results. One run
// aggregates all scanned servers; each result's logical location names the
// server and tool it came from.
func SARIF(w io.Writer, reports []*scan.Report) error {
	rulesByID := map[string]sarifRule{}
	// SARIF requires an array here: a clean scan must write [], never null.
	results := []sarifResult{}

	for _, r := range reports {
		for _, f := range r.Findings {
			if _, ok := rulesByID[f.RuleID]; !ok {
				rulesByID[f.RuleID] = sarifRule{
					ID:               f.RuleID,
					Name:             f.RuleID,
					ShortDescription: sarifText{Text: f.Title},
					HelpURI:          "https://github.com/greyquill/mcpsight/blob/main/docs/rubric.md",
					DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
				}
			}
			results = append(results, sarifResult{
				RuleID:  f.RuleID,
				Level:   sarifLevel(f.Severity),
				Message: sarifText{Text: messageText(f)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: locationURI(r, f)}},
					LogicalLocations: []sarifLogical{{Name: logicalName(r, f), Kind: "member"}},
				}},
			})
		}
	}

	rules := make([]sarifRule, 0, len(rulesByID))
	for _, r := range rulesByID {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "mcpsight",
				InformationURI: "https://github.com/greyquill/mcpsight",
				Version:        buildinfo.Version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func sarifLevel(s analyze.Severity) string {
	switch s {
	case analyze.Critical, analyze.High:
		return "error"
	case analyze.Medium:
		return "warning"
	default:
		return "note"
	}
}

func messageText(f analyze.Finding) string {
	msg := f.Title
	if f.Detail != "" {
		msg += ". " + f.Detail
	}
	if f.Remediation != "" {
		msg += " Fix: " + f.Remediation
	}
	return msg
}

func locationURI(r *scan.Report, _ analyze.Finding) string {
	if r.Target.Name != "" {
		return "mcp-server/" + r.Target.Name
	}
	return "mcp-server"
}

func logicalName(r *scan.Report, f analyze.Finding) string {
	name := r.Target.Name
	if f.Tool != "" {
		name += "/" + f.Tool
	}
	return name
}

// --- SARIF 2.1.0 document types (minimal subset we emit) ---

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	ShortDescription sarifText   `json:"shortDescription"`
	HelpURI          string      `json:"helpUri"`
	DefaultConfig    sarifConfig `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifLogical struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type sarifText struct {
	Text string `json:"text"`
}
