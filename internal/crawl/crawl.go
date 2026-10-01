// Package crawl discovers MCP servers to scan. It is pluggable: the official
// registry over HTTP, or a local seed file (for testing, offline runs, or
// scanning a curated list). Discovery only enumerates servers; scanning them is
// the batch runner's job.
package crawl

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/greyquill/mcpsight/internal/target"
)

// DiscoveredServer is one server found by a crawler, with its scannable targets
// resolved (a server may publish an npm package, a PyPI package, and/or a remote
// endpoint; we prefer the first that resolves).
type DiscoveredServer struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	RepoURL     string   `json:"repo_url,omitempty"`
	Registry    string   `json:"registry"` // official | file | ...
	Targets     []string `json:"targets"`  // e.g. ["npx:@scope/pkg@1.2.3", "https://..."]
}

// PrimaryTarget resolves the first usable target for this server.
func (d DiscoveredServer) PrimaryTarget() (target.Target, error) {
	for _, raw := range d.Targets {
		if t, err := target.Resolve(raw); err == nil {
			return t, nil
		}
	}
	return target.Target{}, fmt.Errorf("server %q has no resolvable target", d.Name)
}

// Crawler enumerates servers from a source.
type Crawler interface {
	Name() string
	Crawl(ctx context.Context) ([]DiscoveredServer, error)
}

// FileCrawler reads a seed list of servers from a JSON file: either a bare array
// of DiscoveredServer, or {"servers":[...]}. Used for tests, offline runs, and
// scanning a curated set without the live registry.
type FileCrawler struct{ Path string }

func (f FileCrawler) Name() string { return "file:" + f.Path }

func (f FileCrawler) Crawl(_ context.Context) ([]DiscoveredServer, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	var arr []DiscoveredServer
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return withRegistry(arr, "file"), nil
	}
	var wrapped struct {
		Servers []DiscoveredServer `json:"servers"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", f.Path, err)
	}
	return withRegistry(wrapped.Servers, "file"), nil
}

func withRegistry(ds []DiscoveredServer, reg string) []DiscoveredServer {
	for i := range ds {
		if ds[i].Registry == "" {
			ds[i].Registry = reg
		}
	}
	return ds
}
