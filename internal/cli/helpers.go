package cli

import (
	"time"

	"github.com/greyquill/mcpsight/internal/manifest"
	"github.com/greyquill/mcpsight/internal/scan"
	"github.com/greyquill/mcpsight/internal/store"
)

// manifestOf returns the baseline's recorded manifest, or nil if there is none.
func manifestOf(bl *store.Baseline) *manifest.Manifest {
	if bl == nil {
		return nil
	}
	return bl.Manifest
}

// baselineFrom builds a persisted baseline record from a scan report.
func baselineFrom(rep *scan.Report) *store.Baseline {
	return &store.Baseline{
		Target:        rep.Target.Name,
		ServerName:    rep.Server.Name,
		ManifestHash:  rep.ManifestHash,
		Manifest:      rep.Manifest,
		ToolVersion:   rep.ToolVersion,
		RubricVersion: rep.RubricVersion,
		RecordedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}
