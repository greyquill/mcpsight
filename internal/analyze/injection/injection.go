// Package injection detects tool-poisoning / prompt-injection patterns in MCP
// tool descriptions — the attack that matters most, because the description is
// fed to the model and can instruct it directly. It is rule-based and runs
// entirely offline with no API key (a deliberate differentiator): regex rules
// live in rules/patterns.yaml, and structural detectors (invisible characters,
// encoded payloads, excessive length) are built in.
package injection

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/manifest"
)

// excessiveLen is the description length (runes) above which we flag bloat that
// is also an obfuscation surface.
const excessiveLen = 1500

// Analyzer runs the injection rule set plus structural detectors.
type Analyzer struct {
	rules *RuleSet
}

// New returns an analyzer using the embedded default rules. A custom rule set
// (from --rules) can be supplied with NewWithRules.
func New() (*Analyzer, error) {
	rs, err := DefaultRuleSet()
	if err != nil {
		return nil, err
	}
	return &Analyzer{rules: rs}, nil
}

// NewWithRules returns an analyzer backed by a specific rule set.
func NewWithRules(rs *RuleSet) *Analyzer { return &Analyzer{rules: rs} }

func (*Analyzer) Name() string { return "injection" }

func (a *Analyzer) Analyze(_ context.Context, in *analyze.Input) []analyze.Finding {
	if in.Manifest == nil {
		return nil
	}
	var findings []analyze.Finding
	for _, t := range in.Manifest.Tools {
		findings = append(findings, a.analyzeTool(t)...)
	}
	return findings
}

func (a *Analyzer) analyzeTool(t manifest.Tool) []analyze.Finding {
	hay := t.Name + "\n" + t.Description
	var findings []analyze.Finding

	// Regex rules from YAML.
	for i := range a.rules.Rules {
		r := &a.rules.Rules[i]
		if r.match(hay) {
			findings = append(findings, analyze.Finding{
				Analyzer: "injection", RuleID: r.ID, Severity: severity(r.Severity),
				Tool: t.Name, Title: r.Title, Detail: r.Detail, Remediation: r.Remediation,
			})
		}
	}

	// Structural: invisible / cross-script characters.
	if reason, ok := invisibleChars(t.Description); ok {
		findings = append(findings, analyze.Finding{
			Analyzer: "injection", RuleID: "injection.invisible_chars", Severity: analyze.High,
			Tool:  t.Name,
			Title: "Description contains hidden or deceptive characters",
			Detail: "The description contains " + reason + ", which can hide instructions from " +
				"human review while still reaching the model.",
			Remediation: "Strip zero-width and bidirectional control characters; use a single script per word.",
		})
	}

	// Structural: embedded encoded payload.
	if dec, ok := encodedBlob(t.Description); ok {
		findings = append(findings, analyze.Finding{
			Analyzer: "injection", RuleID: "injection.encoded_blob", Severity: analyze.Medium,
			Tool:  t.Name,
			Title: "Description embeds an encoded payload",
			Detail: fmt.Sprintf("A base64 blob in the description decodes to text (%q…); encoded "+
				"content in a description is a way to smuggle instructions past review.", truncate(dec, 40)),
			Remediation: "Remove encoded blobs from tool descriptions.",
		})
	}

	// Structural: excessive length.
	if n := len([]rune(t.Description)); n > excessiveLen {
		findings = append(findings, analyze.Finding{
			Analyzer: "injection", RuleID: "injection.excessive_length", Severity: analyze.Low,
			Tool:  t.Name,
			Title: "Unusually long tool description",
			Detail: fmt.Sprintf("The description is %d characters. That is far more than a tool needs, "+
				"and gives instructions plenty of room to hide.", n),
			Remediation: "Trim the description to what the tool actually does.",
		})
	}
	return findings
}

// Invisible/deceptive character code points, written as integer code points so
// no actual invisible character ever lives in this source file.
const (
	zwsp = 0x200b // zero-width space
	zwnj = 0x200c // zero-width non-joiner
	zwj  = 0x200d // zero-width joiner
	bom  = 0xfeff // zero-width no-break space / BOM

	bidiLo1, bidiHi1 = 0x202a, 0x202e // LRE..RLO embedding/override
	bidiLo2, bidiHi2 = 0x2066, 0x2069 // LRI..PDI isolates
)

// invisibleChars reports zero-width characters, bidirectional control
// characters, or mixed-script "homoglyph" words, with a human-readable reason.
func invisibleChars(s string) (string, bool) {
	var reasons []string
	for _, r := range s {
		switch {
		case r == zwsp || r == zwnj || r == zwj || r == bom:
			reasons = appendUnique(reasons, "zero-width characters")
		case (r >= bidiLo1 && r <= bidiHi1) || (r >= bidiLo2 && r <= bidiHi2):
			reasons = appendUnique(reasons, "bidirectional control characters")
		}
	}
	if mixedScriptWord(s) {
		reasons = appendUnique(reasons, "mixed-script (homoglyph) text")
	}
	if len(reasons) == 0 {
		return "", false
	}
	return strings.Join(reasons, " and "), true
}

// mixedScriptWord reports whether any single alphabetic token mixes Latin with
// Cyrillic or Greek letters — the signature of a homoglyph substitution.
func mixedScriptWord(s string) bool {
	var latin, confusable bool
	flush := func() bool {
		hit := latin && confusable
		latin, confusable = false, false
		return hit
	}
	for _, r := range s {
		if unicode.IsLetter(r) {
			switch {
			case unicode.Is(unicode.Latin, r):
				latin = true
			case unicode.Is(unicode.Cyrillic, r) || unicode.Is(unicode.Greek, r):
				confusable = true
			}
			continue
		}
		if flush() {
			return true
		}
	}
	return flush()
}

// encodedBlob finds a base64 run that decodes to mostly-printable text and
// returns the decoded string. Short or non-decoding runs are ignored to keep
// false positives down.
func encodedBlob(s string) (string, bool) {
	isB64 := func(r rune) bool {
		return r == '+' || r == '/' || r == '=' ||
			(r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
	}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return !isB64(r) }) {
		if len(tok) < 24 || len(tok)%4 != 0 {
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(tok)
		if err != nil || len(dec) < 8 {
			continue
		}
		if printableRatio(dec) > 0.85 {
			return string(dec), true
		}
	}
	return "", false
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			printable++
		}
	}
	return float64(printable) / float64(len(b))
}

func appendUnique(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
