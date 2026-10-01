// Package cli wires the cobra command tree. It is deliberately thin: commands
// resolve targets, call internal/scan, render, and manage baselines/exit codes.
// All real work lives in the analyzer, probe, and store packages.
package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/buildinfo"
	"github.com/greyquill/mcpsight/internal/render"
	"github.com/spf13/cobra"
)

// Exit codes are CI-friendly by construction.
const (
	ExitClean    = 0
	ExitFindings = 1
	ExitError    = 2
)

// Execute runs the root command and returns a process exit code.
func Execute(args []string) int {
	root := newRoot()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		// A CommandError carries an explicit exit code; anything else is ExitError.
		if ce, ok := err.(*commandError); ok {
			if ce.msg != "" {
				fmt.Fprintln(os.Stderr, "mcpsight:", ce.msg)
			}
			return ce.code
		}
		fmt.Fprintln(os.Stderr, "mcpsight:", render.SafeBlock(err.Error()))
		return ExitError
	}
	return ExitClean
}

// commandError lets commands choose the process exit code without cobra
// printing usage for a runtime (non-usage) failure.
type commandError struct {
	code int
	msg  string
}

func (e *commandError) Error() string { return e.msg }

func failf(code int, format string, a ...any) *commandError {
	return &commandError{code: code, msg: fmt.Sprintf(format, a...)}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "mcpsight",
		Short:         "An X-ray machine for MCP servers",
		Long:          "mcpsight inspects an MCP server's token cost, capability surface, and change history before you trust it.\nA Greyquill Software open-source project.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCmd(), newVerifyCmd(), newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "mcpsight %s (commit %s, rubric v%d)\n",
				buildinfo.Version, buildinfo.Commit, buildinfo.RubricVersion)
			return nil
		},
	}
}

// parseSeverity maps a --fail-on flag value to a Severity threshold.
func parseSeverity(s string) (analyze.Severity, error) {
	switch s {
	case "critical":
		return analyze.Critical, nil
	case "high":
		return analyze.High, nil
	case "medium":
		return analyze.Medium, nil
	case "low":
		return analyze.Low, nil
	case "info":
		return analyze.Info, nil
	default:
		return "", fmt.Errorf("invalid severity %q (want critical|high|medium|low|info)", s)
	}
}

// atLeast reports whether sev is at or above threshold.
func atLeast(sev, threshold analyze.Severity) bool {
	return sev == threshold || sev.MoreSevereThan(threshold)
}

// targetError reports a per-target failure on stderr.
func targetError(noColor bool, name string, err error) {
	stderrLine(noColor, render.SafeBlock(fmt.Sprintf("✗ %s: %v", name, err)))
}

// stderrLine writes a warning or error to stderr, in red when stderr is a color
// terminal.
func stderrLine(noColor bool, msg string) {
	if colorEnabled(os.Stderr, noColor) {
		msg = "\033[31m" + msg + "\033[0m"
	}
	fmt.Fprintln(os.Stderr, msg)
}

// colorEnabled decides whether to emit ANSI color: only to a terminal, and not
// when NO_COLOR is set (https://no-color.org) or --no-color was passed.
func colorEnabled(w io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
