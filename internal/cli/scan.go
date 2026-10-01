package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/greyquill/mcpsight/internal/analyze/injection"
	"github.com/greyquill/mcpsight/internal/probe"
	"github.com/greyquill/mcpsight/internal/render"
	"github.com/greyquill/mcpsight/internal/scan"
	"github.com/greyquill/mcpsight/internal/store"
	"github.com/greyquill/mcpsight/internal/target"
	"github.com/spf13/cobra"
)

type scanFlags struct {
	from           string
	jsonOut        bool
	sarifOut       bool
	markdownOut    bool
	allowNet       bool
	noSandbox      bool
	updateBaseline bool
	failOn         string
	timeout        time.Duration
	noColor        bool
	offline        bool
	rules          string
	root           string
}

func newScanCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan [target...]",
		Short: "Inspect one or more MCP servers",
		Long: "Scan MCP servers: context cost, declared capabilities, and drift against a\n" +
			"committed baseline. Targets can be npx:/uvx:/docker:/https:// forms, or use\n" +
			"--from to scan every server in an existing MCP config file.",
		Example: "  mcpsight scan --from claude_desktop_config.json\n" +
			"  mcpsight scan npx:@modelcontextprotocol/server-postgres\n" +
			"  mcpsight scan https://mcp.example.com/sse",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.from, "from", "", "scan every server in an MCP config file (e.g. claude_desktop_config.json)")
	fl.BoolVar(&f.jsonOut, "json", false, "write the report as JSON to stdout instead of the terminal summary")
	fl.BoolVar(&f.sarifOut, "sarif", false, "write SARIF to stdout instead of the terminal summary")
	fl.BoolVar(&f.markdownOut, "markdown", false, "write Markdown (for PR comments) to stdout instead of the terminal summary")
	fl.BoolVar(&f.allowNet, "allow-net", false, "allow network egress for local stdio servers that need it to initialize")
	fl.BoolVar(&f.noSandbox, "no-sandbox", false, "DANGEROUS: run stdio servers without a sandbox")
	fl.BoolVar(&f.updateBaseline, "update-baseline", false, "record the current manifest as the new baseline")
	fl.StringVar(&f.failOn, "fail-on", "high", "exit non-zero if any finding is at or above this severity (critical|high|medium|low|info)")
	fl.DurationVar(&f.timeout, "timeout", 0, "per-server wall-clock budget (default 30s)")
	fl.BoolVar(&f.noColor, "no-color", false, "disable ANSI color")
	fl.BoolVar(&f.offline, "offline", false, "skip analyzers that need network access (supply-chain)")
	fl.StringVar(&f.rules, "rules", "", "use a custom injection rule file instead of the embedded rules")
	fl.StringVar(&f.root, "dir", ".", "project directory holding .mcpsight/")
	return cmd
}

func runScan(cmd *cobra.Command, args []string, f scanFlags) error {
	threshold, err := parseSeverity(f.failOn)
	if err != nil {
		return failf(ExitError, "%v", err)
	}
	targets, err := collectTargets(args, f.from)
	if err != nil {
		return failf(ExitError, "%v", err)
	}
	// Validate a custom rule set up front: a typo'd path should fail now, not
	// after a 30s probe.
	if f.rules != "" {
		if _, err := injection.LoadRuleSet(f.rules); err != nil {
			return failf(ExitError, "loading rules from %s: %v", f.rules, err)
		}
	}
	if f.noSandbox {
		stderrLine(f.noColor, "⚠  --no-sandbox: untrusted server code will run WITHOUT isolation.")
	}

	baselines, err := store.LoadBaselines(f.root)
	if err != nil {
		return failf(ExitError, "loading baselines: %v", err)
	}

	out := cmd.OutOrStdout()
	color := colorEnabled(out, f.noColor)
	ctx := context.Background()

	var reports []*scan.Report
	dirty := false
	hadError := false
	failing := false

	for _, t := range targets {
		var baselineManifest = manifestOf(baselines.Get(t.Name))
		rep, err := scan.Run(ctx, t, scan.Options{
			Probe:    probe.Options{AllowNet: f.allowNet, NoSandbox: f.noSandbox, Timeout: f.timeout},
			Baseline: baselineManifest,
			Offline:  f.offline,
			Rules:    f.rules,
		})
		if err != nil {
			targetError(f.noColor, t.Name, err)
			hadError = true
			continue
		}
		reports = append(reports, rep)
		if !f.jsonOut && !f.sarifOut && !f.markdownOut {
			render.Terminal(out, rep, color)
		}

		if rep.BaselineState == scan.BaselineFirstScan || f.updateBaseline {
			baselines.Put(t.Name, baselineFrom(rep))
			dirty = true
		}
		if atLeast(rep.MaxSeverity(), threshold) {
			failing = true
		}
	}

	if dirty {
		if err := baselines.Save(f.root); err != nil {
			return failf(ExitError, "saving baseline: %v", err)
		}
	}
	if err := writeArtifacts(f.root, reports); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write report artifact: %v\n", err)
	}
	switch {
	case f.jsonOut:
		if err := writeJSONStdout(out, reports); err != nil {
			return failf(ExitError, "%v", err)
		}
	case f.sarifOut:
		if err := render.SARIF(out, reports); err != nil {
			return failf(ExitError, "%v", err)
		}
	case f.markdownOut:
		if err := render.Markdown(out, reports); err != nil {
			return failf(ExitError, "%v", err)
		}
	case len(reports) > 0:
		fmt.Fprintf(out, "  Report: %s  |  SARIF: %s\n\n",
			filepath.Join(f.root, store.Dir, "report.json"),
			filepath.Join(f.root, store.Dir, "report.sarif"))
	}

	switch {
	case hadError:
		return failf(ExitError, "")
	case failing:
		return failf(ExitFindings, "")
	}
	return nil
}

// writeArtifacts persists report.json under .mcpsight/ (a single object for one
// target, an array for several).
func writeArtifacts(root string, reports []*scan.Report) error {
	if len(reports) == 0 {
		return nil
	}
	dir := filepath.Join(root, store.Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var payload any = reports
	if len(reports) == 1 {
		payload = reports[0]
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), append(data, '\n'), 0o644); err != nil {
		return err
	}
	// Always emit SARIF too, so GitHub code scanning can pick it up without a flag.
	var buf bytes.Buffer
	if err := render.SARIF(&buf, reports); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.sarif"), buf.Bytes(), 0o644)
}

func writeJSONStdout(out interface{ Write([]byte) (int, error) }, reports []*scan.Report) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if len(reports) == 1 {
		return enc.Encode(reports[0])
	}
	return enc.Encode(reports)
}

func collectTargets(args []string, from string) ([]target.Target, error) {
	var targets []target.Target
	for _, a := range args {
		t, err := target.Resolve(a)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	if from != "" {
		ts, err := target.FromConfig(from)
		if err != nil {
			return nil, err
		}
		targets = append(targets, ts...)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets: pass a target (e.g. npx:@scope/name) or --from <config>")
	}
	return targets, nil
}
