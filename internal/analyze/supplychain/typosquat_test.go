package supplychain

import "testing"

func TestTyposquatSeed(t *testing.T) {
	cases := map[string]bool{
		"@modelcontextprotocol/server-postgress": true,  // squat (extra s)
		"@modelcontextprotocol/server-postgres":  false, // the real one
		"mcp-server-ftch":                        true,  // squat of fetch? distance 2 from fetch
		"totally-unrelated-package":              false,
	}
	for name, wantSquat := range cases {
		got := nearestSquat(name) != ""
		if got != wantSquat {
			t.Errorf("%s: squat=%v want %v (nearest=%q)", name, got, wantSquat, nearestSquat(name))
		}
	}
}
