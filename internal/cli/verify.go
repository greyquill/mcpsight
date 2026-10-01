package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/greyquill/mcpsight/internal/probe"
	"github.com/greyquill/mcpsight/internal/render"
	"github.com/greyquill/mcpsight/internal/scan"
	"github.com/greyquill/mcpsight/internal/store"
	"github.com/spf13/cobra"
)

type verifyFlags struct {
	from    string
	timeout time.Duration
	noColor bool
	offline bool
	root    string
}

func newVerifyCmd() *cobra.Command {
	var f verifyFlags
	cmd := &cobra.Command{
		Use:   "verify [target...]",
		Short: "Fail if a server drifted from its committed baseline (for CI)",
		Long: "verify re-scans servers and compares them to the baseline recorded in\n" +
			".mcpsight/baseline.json. It never updates the baseline and exits non-zero\n" +
			"if any server drifted. Use it to gate CI.",
		Example: "  mcpsight verify --from claude_desktop_config.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd, args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.from, "from", "", "verify every server in an MCP config file")
	fl.DurationVar(&f.timeout, "timeout", 0, "per-server wall-clock budget (default 30s)")
	fl.BoolVar(&f.noColor, "no-color", false, "disable ANSI color")
	fl.BoolVar(&f.offline, "offline", false, "skip analyzers that need network access (supply-chain)")
	fl.StringVar(&f.root, "dir", ".", "project directory holding .mcpsight/")
	return cmd
}

func runVerify(cmd *cobra.Command, args []string, f verifyFlags) error {
	targets, err := collectTargets(args, f.from)
	if err != nil {
		return failf(ExitError, "%v", err)
	}
	baselines, err := store.LoadBaselines(f.root)
	if err != nil {
		return failf(ExitError, "loading baselines: %v", err)
	}

	out := cmd.OutOrStdout()
	color := colorEnabled(out, f.noColor)
	ctx := context.Background()

	drifted := false
	hadError := false

	for _, t := range targets {
		bl := baselines.Get(t.Name)
		if bl == nil {
			targetError(f.noColor, t.Name, errors.New("no baseline recorded. Run 'mcpsight scan' first"))
			hadError = true
			continue
		}
		rep, err := scan.Run(ctx, t, scan.Options{
			Probe:    probe.Options{Timeout: f.timeout},
			Baseline: bl.Manifest,
			Offline:  f.offline,
		})
		if err != nil {
			targetError(f.noColor, t.Name, err)
			hadError = true
			continue
		}
		render.Terminal(out, rep, color)
		if rep.BaselineState == scan.BaselineDrifted {
			drifted = true
		}
	}

	switch {
	case hadError:
		return failf(ExitError, "")
	case drifted:
		return failf(ExitFindings, "drift detected: a server changed since its baseline")
	}
	fmt.Fprintln(out, "  All servers match their baselines.")
	return nil
}
