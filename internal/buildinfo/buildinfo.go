// Package buildinfo carries version metadata stamped at build time and the
// rubric version the scorer implements. Every scan records both so historical
// grades remain interpretable (see docs/rubric.md, docs/threat-model.md §8).
package buildinfo

import "runtime/debug"

// Version is the mcpsight release, overridable via -ldflags at build time.
var Version = "0.0.0-dev"

// Commit is the source revision, overridable via -ldflags at build time.
var Commit = "unknown"

// RubricVersion is the scoring rubric this binary implements. Bump in lockstep
// with docs/rubric.md whenever penalties, bands, or rule severities change.
const RubricVersion = 1

// `go install ...@v1.2.3` sets no ldflags, but the module version and VCS
// revision are embedded in the binary. Use them so reports never say 0.0.0-dev
// for a tagged install.
func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	fillFrom(info)
}

func fillFrom(info *debug.BuildInfo) {
	if Version == "0.0.0-dev" {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			Version = v
		}
	}
	if Commit == "unknown" {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				Commit = s.Value[:7]
			}
		}
	}
}
