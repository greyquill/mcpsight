package render

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Server-controlled text (names, descriptions quoted in findings, stderr) must
// never reach a terminal or a Markdown comment as-is. Escape sequences can
// rewrite the screen, set the window title, or plant hyperlinks; a newline can
// forge a report line; bidi controls can make text read differently than it
// is. These helpers make all of that visible instead of active.

// Safe returns s on one line with every control character shown as an escape.
func Safe(s string) string { return escapeControls(s, false) }

// SafeBlock is Safe for multi-line text such as server stderr: it keeps
// newlines and tabs and escapes everything else.
func SafeBlock(s string) string { return escapeControls(s, true) }

func escapeControls(s string, keepLines bool) string {
	if isPlain(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case keepLines && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case (r >= 0x80 && r <= 0x9f) || isBidi(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// isPlain is the fast path: printable ASCII needs no work.
func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// isBidi reports Unicode bidirectional formatting characters.
func isBidi(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// mdText escapes s for Markdown prose and table cells: it cannot open a link,
// emphasis, HTML tag, or new table cell.
func mdText(s string) string {
	var b strings.Builder
	for _, r := range Safe(s) {
		switch {
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '&':
			b.WriteString("&amp;")
		case strings.ContainsRune("\\`*_{}[]()#+-.!|~", r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mdCode renders s as an inline code span inside a table cell. The fence is one
// backtick longer than any run inside s, so s cannot close it, and pipes are
// escaped because GFM splits table cells before it parses code spans.
func mdCode(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(Safe(s), "|", `\|`)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if longest > 0 {
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}
