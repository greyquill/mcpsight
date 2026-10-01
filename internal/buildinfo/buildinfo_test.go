package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestFillFrom(t *testing.T) {
	cases := []struct {
		name                    string
		version, commit         string
		info                    debug.BuildInfo
		wantVersion, wantCommit string
	}{
		{
			name:    "go install of a tag",
			version: "0.0.0-dev", commit: "unknown",
			info: debug.BuildInfo{
				Main:     debug.Module{Version: "v0.1.0"},
				Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "88175d4351a3411687a137cb7c6d507b72af0b94"}},
			},
			wantVersion: "v0.1.0", wantCommit: "88175d4",
		},
		{
			name:    "local go build",
			version: "0.0.0-dev", commit: "unknown",
			info:        debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			wantVersion: "0.0.0-dev", wantCommit: "unknown",
		},
		{
			name:    "ldflags win",
			version: "v0.2.0", commit: "abc1234",
			info: debug.BuildInfo{
				Main:     debug.Module{Version: "v9.9.9"},
				Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "ffffffffffffffff"}},
			},
			wantVersion: "v0.2.0", wantCommit: "abc1234",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldV, oldC := Version, Commit
			defer func() { Version, Commit = oldV, oldC }()
			Version, Commit = c.version, c.commit
			fillFrom(&c.info)
			if Version != c.wantVersion || Commit != c.wantCommit {
				t.Errorf("got %s/%s, want %s/%s", Version, Commit, c.wantVersion, c.wantCommit)
			}
		})
	}
}
