package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/manifest"
	"github.com/greyquill/mcpsight/internal/scan"
)

func TestSafe(t *testing.T) {
	cases := map[string]string{
		"plain name":                  "plain name",
		"café ✓":                      "café ✓",
		"\x1b[2J\x1b[Hclear":          `\x1b[2J\x1b[Hclear`,
		"\x1b]8;;http://evil\x07link": `\x1b]8;;http://evil\x07link`,
		"line\nCRITICAL  forged":      `line\x0aCRITICAL  forged`,
		"tab\there":                   `tab\x09here`,
		"\u202egnp.exe":               `\u202egnp.exe`,
		"c1 \u009b31m":                `c1 \u009b31m`,
		"bad utf8 \xff":               `bad utf8 \xff`,
	}
	for in, want := range cases {
		if got := Safe(in); got != want {
			t.Errorf("Safe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeBlockKeepsLines(t *testing.T) {
	got := SafeBlock("err: boom\n\tat x\x1b[31m")
	if got != "err: boom\n\tat x\\x1b[31m" {
		t.Errorf("got %q", got)
	}
}

func TestMarkdownEscapes(t *testing.T) {
	for _, in := range []string{"[click](https://evil)", "<img src=x onerror=1>", "a | b", "**bold**"} {
		got := mdText(in)
		for _, bad := range []string{"](", "<img", " | ", "**b"} {
			if strings.Contains(got, bad) {
				t.Errorf("mdText(%q) = %q still contains %q", in, got, bad)
			}
		}
	}
	if got := mdCode("a`b"); got != "`` a`b ``" {
		t.Errorf("mdCode backtick: %q", got)
	}
	if got := mdCode("x|y"); got != "`x\\|y`" {
		t.Errorf("mdCode pipe: %q", got)
	}
}

// A hostile server controls its name, tool names, and the text findings quote.
func hostileReport() *scan.Report {
	return &scan.Report{
		Server: manifest.ServerInfo{Name: "evil\x1b]0;pwned\x07", Version: "1\x1b[2J"},
		Findings: []analyze.Finding{{
			Severity: analyze.High, RuleID: "injection.override_instruction",
			Title:  "t\x1b[8m",
			Tool:   "tool\n  No findings.",
			Detail: "quoted <img src=x> \x1b]8;;http://evil\x07here",
		}},
	}
}

func TestTerminalNeverEmitsServerEscapes(t *testing.T) {
	var buf bytes.Buffer
	Terminal(&buf, hostileReport(), false)
	out := buf.String()
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Errorf("terminal output carries raw control bytes:\n%q", out)
	}
	if strings.Contains(out, "\n  No findings.") {
		t.Errorf("a tool name forged a report line:\n%s", out)
	}
}

func TestMarkdownNeverEmitsServerHTML(t *testing.T) {
	r := hostileReport()
	r.Findings[0].Title = "<img src=https://evil/pixel> [click](https://evil)"
	r.Findings[0].Tool = "x` <b>y</b> |z"
	var buf bytes.Buffer
	Markdown(&buf, []*scan.Report{r})
	out := buf.String()
	for _, bad := range []string{"<img", "](https://evil", "\x1b"} {
		if strings.Contains(out, bad) {
			t.Errorf("markdown output contains %q:\n%s", bad, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| **high**") && strings.Count(strings.ReplaceAll(line, `\|`, ""), "|") != 4 {
			t.Errorf("a server string added a table cell: %s", line)
		}
	}
}
