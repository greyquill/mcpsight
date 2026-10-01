// Package index turns discovery + scanning + storage into the Registry Security
// Index: it runs the same scan the CLI runs, at scale, and persists results to
// Postgres, from which it publishes a static snapshot.
package index

import (
	"context"

	"github.com/greyquill/mcpsight/internal/crawl"
	"github.com/greyquill/mcpsight/internal/scan"
	"github.com/greyquill/mcpsight/internal/store/postgres"
	"github.com/greyquill/mcpsight/internal/target"
)

// WorkItem is one server to scan and how to record it.
type WorkItem struct {
	Ref    postgres.ServerRef
	Target target.Target
}

// FromDiscovered turns crawler output into work items, skipping servers with no
// resolvable target (and returning those as errors for logging).
func FromDiscovered(ds []crawl.DiscoveredServer) ([]WorkItem, []error) {
	var items []WorkItem
	var errs []error
	for _, d := range ds {
		t, err := d.PrimaryTarget()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		items = append(items, WorkItem{Ref: refFor(t, d.RepoURL, d.Registry), Target: t})
	}
	return items, errs
}

// FromConfig builds work items from an MCP config file, for scanning a curated
// or local set (including the fixture servers) without the live registry.
func FromConfig(path string) ([]WorkItem, error) {
	targets, err := target.FromConfig(path)
	if err != nil {
		return nil, err
	}
	items := make([]WorkItem, 0, len(targets))
	for _, t := range targets {
		items = append(items, WorkItem{Ref: refFor(t, "", "local"), Target: t})
	}
	return items, nil
}

// refFor derives the persisted server identity from a resolved target.
func refFor(t target.Target, repoURL, registry string) postgres.ServerRef {
	ref := postgres.ServerRef{CanonicalURL: repoURL, Registry: registry}
	switch t.Kind {
	case target.KindNPX:
		ref.Source, ref.Identifier = "npm", orRaw(t.Package, t.Raw)
	case target.KindUVX:
		ref.Source, ref.Identifier = "pypi", orRaw(t.Package, t.Raw)
	case target.KindDocker:
		ref.Source, ref.Identifier = "oci", orRaw(t.Package, t.Raw)
	case target.KindRemote:
		ref.Source, ref.Identifier = "http", t.URL
	default:
		ref.Source, ref.Identifier = "local", orRaw(t.Name, t.Raw)
	}
	return ref
}

func orRaw(s, raw string) string {
	if s != "" {
		return s
	}
	return raw
}

// Summary reports the outcome of a batch run.
type Summary struct {
	Scanned int
	Failed  int
}

// Recorder is the subset of the store the batch runner needs (eases testing).
type Recorder interface {
	RecordScan(ctx context.Context, ref postgres.ServerRef, rep *scan.Report) (int64, error)
}

// Logf is a progress callback (nil is allowed).
type Logf func(format string, args ...any)

// RunBatch scans each work item with the shared core and records the result.
// Scans run sequentially: each spins up a sandbox, so serial keeps resource use
// predictable on the runner. A single server's failure never aborts the batch.
func RunBatch(ctx context.Context, items []WorkItem, store Recorder, opts scan.Options, log Logf) Summary {
	if log == nil {
		log = func(string, ...any) {}
	}
	var sum Summary
	for i, item := range items {
		log("[%d/%d] scanning %s", i+1, len(items), item.Ref.Identifier)
		rep, err := scan.Run(ctx, item.Target, opts)
		if err != nil {
			sum.Failed++
			log("    failed: %v", err)
			continue
		}
		if _, err := store.RecordScan(ctx, item.Ref, rep); err != nil {
			sum.Failed++
			log("    record failed: %v", err)
			continue
		}
		sum.Scanned++
		log("    %s (%d/100), %d finding(s)", rep.Score.Grade, rep.Score.Score, len(rep.Findings))
	}
	return sum
}
