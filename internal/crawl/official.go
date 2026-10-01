package crawl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DefaultRegistryBase is the official MCP registry API base.
const DefaultRegistryBase = "https://registry.modelcontextprotocol.io"

// OfficialCrawler enumerates servers from the official MCP registry's
// /v0/servers endpoint, following cursor pagination. It is modeled on the
// registry's documented response shape; if the registry is unreachable the
// caller falls back to a FileCrawler.
type OfficialCrawler struct {
	BaseURL  string
	Client   *http.Client
	MaxPages int // 0 = unlimited
}

// NewOfficialCrawler returns a crawler with sane defaults.
func NewOfficialCrawler() *OfficialCrawler {
	return &OfficialCrawler{
		BaseURL:  DefaultRegistryBase,
		Client:   &http.Client{Timeout: 20 * time.Second},
		MaxPages: 0,
	}
}

func (c *OfficialCrawler) Name() string { return "official-registry" }

// registryPage matches the /v0/servers response (server.schema.json
// 2025-12-11). Each entry wraps the server document in "server"; registry
// bookkeeping sits under "_meta".
type registryPage struct {
	Servers []struct {
		Server registryServer `json:"server"`
	} `json:"servers"`
	Metadata struct {
		NextCursor string `json:"nextCursor"`
	} `json:"metadata"`
}

type registryServer struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Repository  struct {
		URL string `json:"url"`
	} `json:"repository"`
	Packages []struct {
		RegistryType string `json:"registryType"` // npm | pypi | oci | ...
		Identifier   string `json:"identifier"`
		Version      string `json:"version"`
	} `json:"packages"`
	Remotes []struct {
		Type string `json:"type"` // streamable-http | sse
		URL  string `json:"url"`
	} `json:"remotes"`
}

func (c *OfficialCrawler) Crawl(ctx context.Context) ([]DiscoveredServer, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultRegistryBase
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}

	var out []DiscoveredServer
	cursor := ""
	for page := 0; c.MaxPages == 0 || page < c.MaxPages; page++ {
		// version=latest lists each server once, at its newest published version.
		q := url.Values{"version": {"latest"}, "limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		u := base + "/v0/servers?" + q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return out, fmt.Errorf("crawling registry: %w", err)
		}
		if resp.StatusCode >= 400 {
			resp.Body.Close()
			return out, fmt.Errorf("registry returned %d", resp.StatusCode)
		}
		var pg registryPage
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&pg)
		resp.Body.Close()
		if err != nil {
			return out, fmt.Errorf("decoding registry page: %w", err)
		}
		for _, e := range pg.Servers {
			out = append(out, toDiscovered(e.Server))
		}
		if pg.Metadata.NextCursor == "" {
			break
		}
		cursor = pg.Metadata.NextCursor
	}
	return out, nil
}

// toDiscovered maps a registry server to scannable targets, preferring npm, then
// PyPI, then a remote endpoint.
func toDiscovered(s registryServer) DiscoveredServer {
	d := DiscoveredServer{Name: s.Name, Description: s.Description, RepoURL: s.Repository.URL, Registry: "official"}
	for _, p := range s.Packages {
		if p.Identifier == "" {
			continue
		}
		switch p.RegistryType {
		case "npm":
			spec := p.Identifier
			if p.Version != "" {
				spec += "@" + p.Version
			}
			d.Targets = append(d.Targets, "npx:"+spec)
		case "pypi":
			d.Targets = append(d.Targets, "uvx:"+p.Identifier)
		case "oci":
			// OCI identifiers usually carry their own tag already.
			d.Targets = append(d.Targets, "docker:"+p.Identifier)
		}
	}
	for _, r := range s.Remotes {
		if r.URL != "" {
			d.Targets = append(d.Targets, r.URL)
		}
	}
	return d
}
