package manifest

import (
	"encoding/json"
	"testing"
)

// The hash must be invariant to things that are not real changes: tool
// ordering, object-key ordering inside schemas, and canonically-equivalent
// Unicode. It must change when the server's actual surface changes.
func TestHashInvariance(t *testing.T) {
	a := &Manifest{
		Server: ServerInfo{Name: "s", Version: "1.0.0"},
		Tools: []Tool{
			{Name: "beta", Description: "second", InputSchema: json.RawMessage(`{"b":1,"a":2}`)},
			{Name: "alpha", Description: "first", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	}
	// Same server, tools listed in a different order and schema keys reordered.
	b := &Manifest{
		Server: ServerInfo{Name: "s", Version: "1.0.0"},
		Tools: []Tool{
			{Name: "alpha", Description: "first", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "beta", Description: "second", InputSchema: json.RawMessage(`{"a":2,"b":1}`)},
		},
	}
	ha, err := a.Hash()
	if err != nil {
		t.Fatal(err)
	}
	hb, err := b.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Errorf("hash should be order/keyorder invariant:\n a=%s\n b=%s", ha, hb)
	}

	// A real change to a description must change the hash.
	b.Tools[0].Description = "first CHANGED"
	hc, _ := b.Hash()
	if hc == ha {
		t.Error("hash should change when a description changes")
	}
}

func TestUnicodeNFCInvariance(t *testing.T) {
	// "é" as single codepoint (NFC) vs "e" + combining acute (NFD).
	nfcForm := &Manifest{Tools: []Tool{{Name: "t", Description: "café"}}}
	nfdForm := &Manifest{Tools: []Tool{{Name: "t", Description: "café"}}}
	h1, _ := nfcForm.Hash()
	h2, _ := nfdForm.Hash()
	if h1 != h2 {
		t.Error("NFC and NFD forms of the same text must hash identically")
	}
}

func TestDeterministicAcrossRuns(t *testing.T) {
	m := &Manifest{
		Server: ServerInfo{Name: "s", Version: "2"},
		Tools:  []Tool{{Name: "x", Description: "<script> & stuff", InputSchema: json.RawMessage(`{"z":[3,1,2]}`)}},
	}
	first, _ := m.Canonical()
	for i := 0; i < 20; i++ {
		next, _ := m.Canonical()
		if string(first) != string(next) {
			t.Fatalf("canonical output not stable across runs at iter %d", i)
		}
	}
	// Array order inside schemas is preserved (can be semantic).
	if got := string(first); !contains(got, `[3,1,2]`) {
		t.Errorf("array order should be preserved, got: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
