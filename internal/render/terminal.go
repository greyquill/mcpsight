// Package render turns a scan Report into output: a pretty terminal summary
// (default), JSON, SARIF, and markdown.
package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/scan"
)

// ANSI colors, used only when color is enabled (a TTY without NO_COLOR).
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
)

type painter struct{ on bool }

func (p painter) c(color, s string) string {
	if !p.on {
		return s
	}
	return color + s + cReset
}

// Terminal writes the human-readable summary.
func Terminal(w io.Writer, r *scan.Report, color bool) {
	p := painter{on: color}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", p.c(cBold, orDash(r.Server.Name, r.Target.Name)))
	line(w, "Server", serverLine(r))
	line(w, "Grade", gradeLine(p, r))
	fmt.Fprintln(w)
	line(w, "Context cost", contextLine(r))
	line(w, "Capabilities", capabilityLine(p, r))
	line(w, "Drift", driftLine(p, r))
	fmt.Fprintln(w)

	writeFindings(w, p, r)
}

func line(w io.Writer, label, value string) {
	fmt.Fprintf(w, "  %-14s%s\n", label, value)
}

func reset(color bool) string {
	if color {
		return cReset
	}
	return ""
}

func serverLine(r *scan.Report) string {
	v := r.Server.Version
	if v == "" {
		v = "unknown version"
	}
	return fmt.Sprintf("%s  (%s, via %s)", orDash(r.Server.Name, "?"), v, r.Runner)
}

func gradeLine(p painter, r *scan.Report) string {
	color := cGreen
	switch r.Score.Grade {
	case "C":
		color = cYellow
	case "D", "F":
		color = cRed
	}
	return fmt.Sprintf("%s  (%d/100%s)  %s",
		p.c(cBold+color, r.Score.Grade), r.Score.Score, gradeNote(r),
		p.c(cDim, fmt.Sprintf("rubric v%d", r.RubricVersion)))
}

// gradeNote qualifies the score: a critical cap held it down, or the server ran
// unobserved, so a high grade covers declared capabilities only.
func gradeNote(r *scan.Report) string {
	var note string
	if r.Score.Capped {
		note += ", capped by a critical finding"
	}
	for _, f := range r.Findings {
		if f.RuleID == "capability.not_observed" {
			note += ", behavior not observed"
			break
		}
	}
	return note
}

func contextLine(r *scan.Report) string {
	cc := r.ContextCost
	if len(cc.Models) == 0 {
		return toolCount(cc.ToolCount)
	}
	m := cc.Models[0] // representative model for the headline
	return fmt.Sprintf("~%s tokens  (%s)   %s per request @ %s  %s",
		commas(m.Tokens), toolCount(cc.ToolCount), usd(m.USD), m.Model, "(est.)")
}

func toolCount(n int) string {
	if n == 1 {
		return "1 tool"
	}
	return fmt.Sprintf("%d tools", n)
}

// usd formats a per-request cost, saying "under $0.001" rather than "$0.000".
func usd(v float64) string {
	if v < 0.0005 {
		return "under $0.001"
	}
	return fmt.Sprintf("~$%.3f", v)
}

func capabilityLine(p painter, r *scan.Report) string {
	if len(r.Capabilities.Classes) == 0 {
		return p.c(cDim, "none declared")
	}
	return strings.Join(r.Capabilities.Classes, "  ")
}

func driftLine(p painter, r *scan.Report) string {
	switch r.BaselineState {
	case scan.BaselineFirstScan:
		return p.c(cDim, "baseline recorded (first scan)")
	case scan.BaselineUnchanged:
		return p.c(cGreen, "unchanged since baseline")
	case scan.BaselineDrifted:
		n := countDrift(r)
		return p.c(cRed+cBold, fmt.Sprintf("DRIFTED: %d change(s) since baseline", n))
	}
	return "-"
}

func writeFindings(w io.Writer, p painter, r *scan.Report) {
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "  %s\n\n", p.c(cGreen, "No findings."))
		return
	}
	sorted := append([]analyze.Finding(nil), r.Findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Severity.MoreSevereThan(sorted[j].Severity)
	})
	fmt.Fprintf(w, "  %s\n", p.c(cBold, "Findings"))
	for _, f := range sorted {
		fmt.Fprintf(w, "  %s  %s %s\n",
			sevBadge(p, f.Severity), p.c(cBold, f.Title), p.c(cDim, "["+f.RuleID+"]"))
		if f.Tool != "" {
			fmt.Fprintf(w, "      %s\n", p.c(cCyan, "tool: "+f.Tool))
		}
		if f.Detail != "" {
			fmt.Fprintf(w, "      %s\n", wrapIndent(f.Detail, 6, 78))
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "      %s %s\n", p.c(cDim, "fix:"), wrapIndent(f.Remediation, 6, 78))
		}
	}
	fmt.Fprintln(w)
}

func sevBadge(p painter, s analyze.Severity) string {
	color := cDim
	switch s {
	case analyze.Critical:
		color = cRed + cBold
	case analyze.High:
		color = cRed
	case analyze.Medium:
		color = cYellow
	case analyze.Low:
		color = cCyan
	}
	return p.c(color, fmt.Sprintf("%-8s", strings.ToUpper(string(s))))
}

func countDrift(r *scan.Report) int {
	n := 0
	for _, f := range r.Findings {
		if f.Analyzer == "drift" {
			n++
		}
	}
	return n
}

func orDash(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// commas inserts thousands separators into a non-negative integer.
func commas(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, d := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, d)
	}
	return string(out)
}

// wrapIndent wraps text to width, indenting continuation lines by indent spaces.
func wrapIndent(text string, indent, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	pad := strings.Repeat(" ", indent)
	var b strings.Builder
	lineLen := 0
	for i, word := range words {
		if i > 0 && lineLen+1+len(word) > width {
			b.WriteString("\n" + pad)
			lineLen = 0
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(word)
		lineLen += len(word)
	}
	return b.String()
}
