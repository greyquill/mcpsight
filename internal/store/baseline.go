// Package store persists scan state. The baseline is a single JSON file
// (.mcpsight/baseline.json) that is meant to be committed to git and diffed in
// pull requests: it is the reference `mcpsight verify` checks against to catch
// rug-pulls. Richer scan history lives in SQLite alongside it (history.go).
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/greyquill/mcpsight/internal/manifest"
)

// Dir is the per-project directory holding baselines and scan artifacts.
const Dir = ".mcpsight"

// baselineFile is the committable baseline document within Dir.
const baselineFile = "baseline.json"

// Baseline is the recorded reference for one server.
type Baseline struct {
	Target        string             `json:"target"`
	ServerName    string             `json:"server_name"`
	ManifestHash  string             `json:"manifest_hash"`
	Manifest      *manifest.Manifest `json:"manifest"`
	ToolVersion   string             `json:"mcpsight_version"`
	RubricVersion int                `json:"rubric_version"`
	RecordedAt    string             `json:"recorded_at"` // RFC3339, supplied by caller (kept out of the hash)
}

// Baselines is the on-disk document: baselines keyed by target name.
type Baselines struct {
	Version   string               `json:"version"`
	Baselines map[string]*Baseline `json:"baselines"`
}

// LoadBaselines reads .mcpsight/baseline.json under root. A missing file yields
// an empty set, not an error (the first scan has no baseline).
func LoadBaselines(root string) (*Baselines, error) {
	path := filepath.Join(root, Dir, baselineFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Baselines{Version: manifest.SchemaVersion, Baselines: map[string]*Baseline{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var b Baselines
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if b.Baselines == nil {
		b.Baselines = map[string]*Baseline{}
	}
	return &b, nil
}

// Get returns the baseline for a target key, or nil if none is recorded.
func (b *Baselines) Get(key string) *Baseline { return b.Baselines[key] }

// Put records or replaces a baseline.
func (b *Baselines) Put(key string, bl *Baseline) {
	if b.Baselines == nil {
		b.Baselines = map[string]*Baseline{}
	}
	b.Baselines[key] = bl
}

// Save writes the baseline document back to disk deterministically (sorted keys,
// indented) so it produces clean, reviewable git diffs.
func (b *Baselines) Save(root string) error {
	if b.Version == "" {
		b.Version = manifest.SchemaVersion
	}
	dir := filepath.Join(root, Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Marshal with sorted keys for a stable diff. json.Marshal already sorts map
	// keys; MarshalIndent keeps it readable.
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Join(dir, baselineFile), data, 0o644)
}

// Keys returns the recorded target keys, sorted.
func (b *Baselines) Keys() []string {
	keys := make([]string, 0, len(b.Baselines))
	for k := range b.Baselines {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
