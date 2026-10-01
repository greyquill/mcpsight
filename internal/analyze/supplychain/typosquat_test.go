package supplychain

import "testing"

func TestTyposquatSeed(t *testing.T) {
	cases := []struct {
		name     string
		want     string // suspected target, "" when not a squat
		sameName bool
	}{
		{"@modelcontextprotocol/server-postgress", "@modelcontextprotocol/server-postgres", false},
		{"@modelcontextprotocol/server-postgres", "", false},
		{"mcp-server-ftch", "mcp-server-fetch", false},
		{"totally-unrelated-package", "", false},
		// Popular packages close to each other are not squats of each other.
		{"@modelcontextprotocol/server-gitlab", "", false},
		{"@modelcontextprotocol/server-github", "", false},
		{"mcp-server-git", "", false},
		// The same name under another scope is.
		{"@evil/server-postgres", "@modelcontextprotocol/server-postgres", true},
		{"@evil/mcp-server-fetch", "mcp-server-fetch", true},
		// A near spelling picks the closest popular name, not the first in the list.
		{"@modelcontextprotocol/server-gitlad", "@modelcontextprotocol/server-gitlab", false},
	}
	for _, c := range cases {
		sq, ok := nearestSquat(c.name)
		if !ok {
			sq = squat{}
		}
		if sq.target != c.want || sq.sameName != c.sameName {
			t.Errorf("%s: got target=%q sameName=%v, want %q sameName=%v", c.name, sq.target, sq.sameName, c.want, c.sameName)
		}
	}
}
