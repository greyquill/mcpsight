// Package capability classifies the DECLARED capability surface of a server —
// what its tool names, descriptions, and schemas say it can reach. Phase 1 is
// declared-only; Phase 2 adds observed capabilities from the sandbox and flags
// the gap between the two. See docs/rubric.md.
package capability

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/manifest"
)

// Capability classes, matching the taxonomy in docs/rubric.md.
const (
	FSRead     = "fs:read"
	FSWrite    = "fs:write"
	ExecShell  = "exec:shell"
	NetEgress  = "net:egress"
	DBWrite    = "db:write"
	SecretRead = "secrets:read"
	CodeEval   = "code:eval"
)

// dangerous lists the classes worth surfacing even before observation. Reading
// files or the network is common and benign; shelling out, evaluating code, or
// touching secrets is worth a user's eye. These emit Info findings (no score
// impact in Phase 1 — the score comes from observed behavior in Phase 2).
var dangerous = map[string]bool{
	ExecShell: true, CodeEval: true, SecretRead: true, DBWrite: true, FSWrite: true,
}

// classifier pairs a capability class with the signals that imply it.
type classifier struct {
	class    string
	words    *regexp.Regexp // matched against name + description
	schemaKV *regexp.Regexp // matched against schema property names
}

func word(alts ...string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)\b(` + strings.Join(alts, "|") + `)\b`)
}

var classifiers = []classifier{
	{FSRead, word("read", "cat", "load", "open", "list files?", "get file", "fetch file"), word("path", "file", "filename", "filepath", "dir", "directory")},
	{FSWrite, word("write", "save", "create file", "delete", "remove", "unlink", "mkdir", "edit file", "put file", "append"), word("content", "data", "destination", "dest")},
	{ExecShell, word("exec", "execute", "shell", "run command", "spawn", "bash", "subprocess"), word("command", "cmd", "argv", "args")},
	{NetEgress, word("fetch", "http", "https", "request", "download", "curl", "webhook", "api call", "url"), word("url", "endpoint", "host", "uri")},
	{DBWrite, word("insert", "update", "upsert", "drop table", "delete from", "sql"), word("sql", "statement")},
	{SecretRead, word("secret", "credential", "password", "token", "api key", "vault", "env var", "environment variable"), word("secret", "token", "credential", "password")},
	{CodeEval, word("eval", "evaluate", "interpret", "run code", "execute code", "python", "javascript", "compile"), word("code", "script", "expression", "source")},
}

// Summary is the declared capability surface for a manifest.
type Summary struct {
	Classes []string            `json:"classes"` // union across all tools, sorted
	ByTool  map[string][]string `json:"by_tool"` // per-tool classes
}

// Classify returns the declared capability surface of a manifest.
func Classify(m *manifest.Manifest) Summary {
	s := Summary{ByTool: map[string][]string{}}
	union := map[string]bool{}
	for _, t := range m.Tools {
		classes := classifyTool(t)
		if len(classes) > 0 {
			s.ByTool[t.Name] = classes
			for _, c := range classes {
				union[c] = true
			}
		}
	}
	for c := range union {
		s.Classes = append(s.Classes, c)
	}
	sort.Strings(s.Classes)
	return s
}

// ClassifyTool returns the declared capability classes of a single tool. Used
// by the drift analyzer to detect capability escalation across versions.
func ClassifyTool(t manifest.Tool) []string { return classifyTool(t) }

func classifyTool(t manifest.Tool) []string {
	haystack := strings.ToLower(t.Name + "\n" + t.Description)
	props := schemaPropertyNames(t.InputSchema)
	found := map[string]bool{}
	for _, c := range classifiers {
		if c.words.MatchString(haystack) || (c.schemaKV != nil && c.schemaKV.MatchString(props)) {
			found[c.class] = true
		}
	}
	out := make([]string, 0, len(found))
	for c := range found {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// schemaPropertyNames extracts JSON Schema property names (space-joined) so
// classifiers can match on them (a "command" property strongly implies shell).
func schemaPropertyNames(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	var names []string
	var walk func(any)
	walk = func(n any) {
		m, ok := n.(map[string]any)
		if !ok {
			if arr, ok := n.([]any); ok {
				for _, e := range arr {
					walk(e)
				}
			}
			return
		}
		if props, ok := m["properties"].(map[string]any); ok {
			for name, sub := range props {
				names = append(names, name)
				walk(sub)
			}
		}
		for k, sub := range m {
			if k != "properties" {
				walk(sub)
			}
		}
	}
	walk(v)
	return strings.ToLower(strings.Join(names, " "))
}

// Analyzer emits Info findings for notably powerful declared capabilities. The
// full surface goes to the report via Classify; here we only draw the eye to
// the dangerous classes.
type Analyzer struct{}

func (Analyzer) Name() string { return "capability" }

func (Analyzer) Analyze(_ context.Context, in *analyze.Input) []analyze.Finding {
	if in.Manifest == nil {
		return nil
	}
	var findings []analyze.Finding
	// Declared surface (from names/descriptions/schemas).
	for _, t := range in.Manifest.Tools {
		for _, c := range classifyTool(t) {
			if !dangerous[c] {
				continue
			}
			findings = append(findings, analyze.Finding{
				Analyzer: "capability", RuleID: "capability.declared_" + slug(c), Severity: analyze.Info,
				Tool:  t.Name,
				Title: "Declares " + c + " capability",
				Detail: "Tool \"" + t.Name + "\" appears to declare the " + c +
					" capability from its name, description, or schema.",
				Meta: map[string]any{"class": c},
			})
		}
	}
	// Observed behavior from the sandbox (what it actually did on startup).
	findings = append(findings, observed(in)...)
	return findings
}

// observed turns the sandbox trace into findings: any decoy-credential read is
// critical; an egress attempt on a network-denied run is high (unambiguously the
// server's own); and egress with no declared net:egress capability is a
// declared-vs-observed gap.
func observed(in *analyze.Input) []analyze.Finding {
	tr := in.Trace
	if tr == nil {
		return nil
	}
	var findings []analyze.Finding
	// One finding lists every decoy read, so the single -40 penalty (per the
	// rubric's per-rule dedup) matches one visible finding.
	if len(tr.DecoyReads) > 0 {
		findings = append(findings, analyze.Finding{
			Analyzer: "capability", RuleID: "capability.decoy_read", Severity: analyze.Critical,
			Title: "Server read decoy credential files on startup",
			Detail: "During the probe the server read the decoy credential file(s): " +
				strings.Join(tr.DecoyReads, ", ") + ". A server that reads credential files on " +
				"startup is exfiltrating, not initializing.",
			Remediation: "Do not install this server. Report it to the registry it came from.",
			Meta:        map[string]any{"paths": tr.DecoyReads},
		})
	}
	if tr.NetDenied && len(tr.EgressHosts) > 0 {
		declaresNet := in.Manifest != nil && hasClass(Classify(in.Manifest).Classes, NetEgress)
		f := analyze.Finding{
			Analyzer: "capability", RuleID: "capability.egress_unexpected", Severity: analyze.High,
			Title:       "Server attempted network egress on startup",
			Detail:      "The server tried to reach " + strings.Join(tr.EgressHosts, ", ") + " during startup, with the network denied. It should not need the network to list its tools.",
			Remediation: "Investigate why the server connects out on startup before trusting it.",
			Meta:        map[string]any{"hosts": tr.EgressHosts},
		}
		findings = append(findings, f)
		if !declaresNet {
			findings = append(findings, analyze.Finding{
				Analyzer: "capability", RuleID: "capability.declared_observed_gap", Severity: analyze.High,
				Title:       "Observed network egress exceeds declared capability",
				Detail:      "The server contacted the network but none of its tools declare a net:egress capability. Observed behavior exceeding the declared surface is a red flag.",
				Remediation: "Treat the undeclared capability as the true capability of the server.",
				Meta:        map[string]any{"hosts": tr.EgressHosts},
			})
		}
	}
	return findings
}

func hasClass(classes []string, want string) bool {
	for _, c := range classes {
		if c == want {
			return true
		}
	}
	return false
}

func slug(class string) string { return strings.ReplaceAll(class, ":", "_") }
