package manifest

import (
	"encoding/json"
	"testing"
)

func TestDiff(t *testing.T) {
	base := &Manifest{
		Server: ServerInfo{Name: "s", Version: "1.0.0"},
		Tools: []Tool{
			{Name: "keep", Description: "unchanged"},
			{Name: "edit", Description: "old text", InputSchema: json.RawMessage(`{"a":1}`)},
			{Name: "gone", Description: "will be removed"},
		},
	}
	cur := &Manifest{
		Server: ServerInfo{Name: "s", Version: "1.1.0"},
		Tools: []Tool{
			{Name: "keep", Description: "unchanged"},
			{Name: "edit", Description: "new text", InputSchema: json.RawMessage(`{"a":1,"b":2}`)},
			{Name: "fresh", Description: "brand new"},
		},
	}

	got := map[ChangeKind][]string{}
	for _, c := range Diff(base, cur) {
		got[c.Kind] = append(got[c.Kind], c.Target)
	}

	want := map[ChangeKind]string{
		ServerVersionChanged:   "s",
		ToolAdded:              "fresh",
		ToolRemoved:            "gone",
		ToolDescriptionChanged: "edit",
		ToolSchemaChanged:      "edit",
	}
	for kind, target := range want {
		if len(got[kind]) != 1 || got[kind][0] != target {
			t.Errorf("%s: want [%s], got %v", kind, target, got[kind])
		}
	}
	if _, ok := got[ToolDescriptionChanged]; !ok {
		t.Error("expected a description change for 'edit'")
	}
	// 'keep' must produce no change of any kind.
	for kind, targets := range got {
		for _, tg := range targets {
			if tg == "keep" {
				t.Errorf("unchanged tool 'keep' produced a %s change", kind)
			}
		}
	}
}

func TestDiffNoChange(t *testing.T) {
	m := &Manifest{Tools: []Tool{{Name: "a", Description: "x", InputSchema: json.RawMessage(`{"k":1}`)}}}
	// Same content, schema keys reordered — must be seen as no change.
	m2 := &Manifest{Tools: []Tool{{Name: "a", Description: "x", InputSchema: json.RawMessage(`{ "k" : 1 }`)}}}
	if d := Diff(m, m2); len(d) != 0 {
		t.Errorf("expected no changes, got %v", d)
	}
}
