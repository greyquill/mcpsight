package manifest

import "sort"

// ChangeKind enumerates the structural differences between two manifests. The
// diff is purely structural; deciding the SEVERITY of a change (a description
// gaining an imperative instruction is critical, a shortening is noise) is the
// drift analyzer's job, not this package's. See docs/rubric.md (drift.*).
type ChangeKind string

const (
	ToolAdded              ChangeKind = "tool_added"
	ToolRemoved            ChangeKind = "tool_removed"
	ToolDescriptionChanged ChangeKind = "tool_description_changed"
	ToolSchemaChanged      ChangeKind = "tool_schema_changed"
	ResourceAdded          ChangeKind = "resource_added"
	ResourceRemoved        ChangeKind = "resource_removed"
	PromptAdded            ChangeKind = "prompt_added"
	PromptRemoved          ChangeKind = "prompt_removed"
	ServerVersionChanged   ChangeKind = "server_version_changed"
)

// Change is one structural difference between a baseline and a current
// manifest. Target names the affected element (tool/resource/prompt name);
// Before and After hold the relevant values where applicable.
type Change struct {
	Kind   ChangeKind `json:"kind"`
	Target string     `json:"target,omitempty"`
	Before string     `json:"before,omitempty"`
	After  string     `json:"after,omitempty"`
}

// Diff compares a baseline (from) manifest against the current (to) manifest
// and returns the structural changes, deterministically ordered. Comparison is
// on normalized values so canonically-equivalent text does not register as a
// change; callers should pass manifests as captured (Diff normalizes internally).
func Diff(from, to *Manifest) []Change {
	from = from.canonicalCopy()
	to = to.canonicalCopy()
	var changes []Change

	if from.Server.Version != to.Server.Version {
		changes = append(changes, Change{
			Kind:   ServerVersionChanged,
			Target: to.Server.Name,
			Before: from.Server.Version,
			After:  to.Server.Version,
		})
	}

	fromTools := indexTools(from.Tools)
	toTools := indexTools(to.Tools)
	for name, tt := range toTools {
		ft, ok := fromTools[name]
		if !ok {
			changes = append(changes, Change{Kind: ToolAdded, Target: name, After: tt.Description})
			continue
		}
		if ft.Description != tt.Description {
			changes = append(changes, Change{
				Kind: ToolDescriptionChanged, Target: name,
				Before: ft.Description, After: tt.Description,
			})
		}
		if string(ft.InputSchema) != string(tt.InputSchema) {
			changes = append(changes, Change{
				Kind: ToolSchemaChanged, Target: name,
				Before: string(ft.InputSchema), After: string(tt.InputSchema),
			})
		}
	}
	for name := range fromTools {
		if _, ok := toTools[name]; !ok {
			changes = append(changes, Change{Kind: ToolRemoved, Target: name})
		}
	}

	changes = append(changes, presenceDiff(resourceKeys(from.Resources), resourceKeys(to.Resources), ResourceAdded, ResourceRemoved)...)
	changes = append(changes, presenceDiff(promptKeys(from.Prompts), promptKeys(to.Prompts), PromptAdded, PromptRemoved)...)

	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Kind != changes[j].Kind {
			return changes[i].Kind < changes[j].Kind
		}
		return changes[i].Target < changes[j].Target
	})
	return changes
}

func indexTools(ts []Tool) map[string]Tool {
	m := make(map[string]Tool, len(ts))
	for _, t := range ts {
		m[t.Name] = t
	}
	return m
}

func resourceKeys(rs []Resource) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.URI
	}
	return out
}

func promptKeys(ps []Prompt) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

func presenceDiff(from, to []string, added, removed ChangeKind) []Change {
	fromSet := make(map[string]bool, len(from))
	for _, k := range from {
		fromSet[k] = true
	}
	toSet := make(map[string]bool, len(to))
	for _, k := range to {
		toSet[k] = true
	}
	var changes []Change
	for k := range toSet {
		if !fromSet[k] {
			changes = append(changes, Change{Kind: added, Target: k})
		}
	}
	for k := range fromSet {
		if !toSet[k] {
			changes = append(changes, Change{Kind: removed, Target: k})
		}
	}
	return changes
}
