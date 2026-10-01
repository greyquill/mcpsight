// Package contextcost estimates the token cost a server's tool definitions
// impose on every request, reported per model family, and flags schema bloat
// that a maintainer can actually fix. See docs/rubric.md (context.*).
package contextcost

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/manifest"
	"github.com/greyquill/mcpsight/internal/tokenize"
)

// Report is the headline token accounting the renderer prints. Token counts are
// ESTIMATES (see the tokenize package) and are labeled as such in output.
type Report struct {
	ToolCount int         `json:"tool_count"`
	Models    []ModelCost `json:"models"`
	PerTool   []ToolCost  `json:"per_tool"` // sorted, worst offender first
}

// ModelCost is the estimated total tokens and per-request price for one model.
type ModelCost struct {
	Model  string  `json:"model"`
	Family string  `json:"family"`
	Tokens int     `json:"tokens"`
	USD    float64 `json:"usd_per_request"`
}

// ToolCost is one tool's estimated token weight (using the first model family
// as the representative estimate for ranking offenders).
type ToolCost struct {
	Name   string `json:"name"`
	Tokens int    `json:"tokens"`
}

// Compute produces the token table for a manifest across all default models.
func Compute(m *manifest.Manifest) Report {
	r := Report{ToolCount: len(m.Tools)}
	for _, model := range tokenize.Models {
		tk := tokenize.EstimatorFor(model)
		total := 0
		for _, t := range m.Tools {
			total += tk.Count(serializeTool(t))
		}
		r.Models = append(r.Models, ModelCost{
			Model:  model.Name,
			Family: model.Family,
			Tokens: total,
			USD:    float64(total) / 1_000_000 * model.InputUSDPerMTok,
		})
	}
	if len(tokenize.Models) > 0 {
		rep := tokenize.EstimatorFor(tokenize.Models[0])
		for _, t := range m.Tools {
			r.PerTool = append(r.PerTool, ToolCost{Name: t.Name, Tokens: rep.Count(serializeTool(t))})
		}
		sort.SliceStable(r.PerTool, func(i, j int) bool { return r.PerTool[i].Tokens > r.PerTool[j].Tokens })
	}
	return r
}

// serializeTool renders a tool roughly as a client injects it into the request,
// so the token estimate reflects real cost.
func serializeTool(t manifest.Tool) string {
	obj := map[string]any{"name": t.Name, "description": t.Description}
	if len(t.InputSchema) > 0 {
		obj["inputSchema"] = json.RawMessage(t.InputSchema)
	}
	b, _ := json.Marshal(obj)
	return string(b)
}

// Thresholds for actionable findings. Kept as named constants so the rubric and
// the code stay legible together.
const (
	schemaDepthBloat  = 5    // nesting depth beyond which a schema is "flattenable"
	oversizedToolFrac = 0.40 // a single tool taking >40% of the budget is worth noting
)

// Analyzer emits the actionable context-cost findings (schema bloat, an
// oversized tool). The headline table comes from Compute, not from findings.
type Analyzer struct{}

func (Analyzer) Name() string { return "context" }

func (Analyzer) Analyze(_ context.Context, in *analyze.Input) []analyze.Finding {
	m := in.Manifest
	if m == nil || len(m.Tools) == 0 {
		return nil
	}
	rep := Compute(m)
	var findings []analyze.Finding

	// Schema bloat: deeply nested input schemas can usually be flattened.
	for _, t := range m.Tools {
		if d := schemaDepth(t.InputSchema); d > schemaDepthBloat {
			findings = append(findings, analyze.Finding{
				Analyzer: "context", RuleID: "context.schema_bloat", Severity: analyze.Low,
				Tool:  t.Name,
				Title: "Deeply nested input schema inflates token cost",
				Detail: "The input schema nests " + strconv.Itoa(d) + " levels deep; flattening it " +
					"reduces the tokens this tool costs on every request.",
				Remediation: "Flatten nested objects or replace them with references; " +
					"prefer flat parameter lists where possible.",
				Meta: map[string]any{"depth": d},
			})
		}
	}

	// Oversized tool: one tool dominating the budget is worth surfacing (info).
	if total := sumTokens(rep.PerTool); total > 0 && len(rep.PerTool) > 0 {
		top := rep.PerTool[0]
		share := float64(top.Tokens) / float64(total)
		// It must also take twice its even share, or a server with two or three
		// tools would always trip the 40% line.
		if share > oversizedToolFrac && share > 2/float64(len(rep.PerTool)) {
			findings = append(findings, analyze.Finding{
				Analyzer: "context", RuleID: "context.oversized_tool", Severity: analyze.Info,
				Tool:  top.Name,
				Title: "One tool dominates the context budget",
				Detail: fmt.Sprintf("Tool %q accounts for %.0f%% of the server's estimated token cost.",
					top.Name, share*100),
				Remediation: "Consider trimming its description or schema, or splitting it.",
				Meta:        map[string]any{"tokens": top.Tokens, "total": total},
			})
		}
	}
	return findings
}

func sumTokens(ts []ToolCost) int {
	n := 0
	for _, t := range ts {
		n += t.Tokens
	}
	return n
}

// schemaDepth returns the maximum object/array nesting depth of a JSON schema.
func schemaDepth(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0
	}
	return depth(v)
}

func depth(v any) int {
	switch t := v.(type) {
	case map[string]any:
		max := 0
		for _, val := range t {
			if d := depth(val); d > max {
				max = d
			}
		}
		return max + 1
	case []any:
		max := 0
		for _, val := range t {
			if d := depth(val); d > max {
				max = d
			}
		}
		return max + 1
	default:
		return 0
	}
}
