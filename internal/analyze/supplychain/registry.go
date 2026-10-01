package supplychain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PackageInfo is the registry metadata the supply-chain analyzer reasons about.
type PackageInfo struct {
	Name             string
	Version          string
	Ecosystem        string // "npm" or "PyPI"
	HasInstallScript bool
	DependencyCount  int
	MaintainerCount  int
	RepoURL          string
	Created          time.Time
	Modified         time.Time
	Found            bool
}

// fetchNPM reads a package's metadata from the npm registry. version may be
// empty, in which case dist-tags.latest is used.
func fetchNPM(ctx context.Context, client *http.Client, name, version string) (*PackageInfo, error) {
	// Scoped names (@scope/name) must have the slash encoded for the registry.
	endpoint := "https://registry.npmjs.org/" + strings.Replace(url.PathEscape(name), "%40", "@", 1)
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Dependencies     map[string]string `json:"dependencies"`
			HasInstallScript bool              `json:"hasInstallScript"`
			Scripts          map[string]string `json:"scripts"`
			Repository       json.RawMessage   `json:"repository"`
		} `json:"versions"`
		Maintainers []json.RawMessage `json:"maintainers"`
		Time        map[string]string `json:"time"`
		Repository  json.RawMessage   `json:"repository"`
	}
	if err := getJSON(ctx, client, endpoint, &doc); err != nil {
		return nil, err
	}
	if version == "" {
		version = doc.DistTags["latest"]
	}
	info := &PackageInfo{Name: name, Version: version, Ecosystem: "npm", Found: true,
		MaintainerCount: len(doc.Maintainers)}
	if v, ok := doc.Versions[version]; ok {
		info.DependencyCount = len(v.Dependencies)
		info.HasInstallScript = v.HasInstallScript || hasLifecycleScript(v.Scripts)
		info.RepoURL = repoURL(v.Repository)
	}
	if info.RepoURL == "" {
		info.RepoURL = repoURL(doc.Repository)
	}
	info.Created = parseTime(doc.Time["created"])
	info.Modified = parseTime(doc.Time["modified"])
	return info, nil
}

// fetchPyPI reads a package's metadata from PyPI's JSON API.
func fetchPyPI(ctx context.Context, client *http.Client, name, version string) (*PackageInfo, error) {
	endpoint := "https://pypi.org/pypi/" + url.PathEscape(name) + "/json"
	var doc struct {
		Info struct {
			HomePage    string            `json:"home_page"`
			ProjectURLs map[string]string `json:"project_urls"`
			RequiresD   []string          `json:"requires_dist"`
			Version     string            `json:"version"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := getJSON(ctx, client, endpoint, &doc); err != nil {
		return nil, err
	}
	if version == "" {
		version = doc.Info.Version
	}
	info := &PackageInfo{Name: name, Version: version, Ecosystem: "PyPI", Found: true,
		DependencyCount: len(doc.Info.RequiresD), RepoURL: pypiRepo(doc.Info.HomePage, doc.Info.ProjectURLs)}
	// Age: earliest upload across releases → created; the target version → modified.
	for _, files := range doc.Releases {
		for _, f := range files {
			t := parseTime(f.UploadTime)
			if !t.IsZero() && (info.Created.IsZero() || t.Before(info.Created)) {
				info.Created = t
			}
		}
	}
	return info, nil
}

func getJSON(ctx context.Context, client *http.Client, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("package not found")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("registry returned %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func hasLifecycleScript(scripts map[string]string) bool {
	for _, k := range []string{"install", "preinstall", "postinstall"} {
		if _, ok := scripts[k]; ok {
			return true
		}
	}
	return false
}

// repoURL extracts a repository URL from npm's repository field, which may be a
// string or an object {"type","url"}.
func repoURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.URL
	}
	return ""
}

func pypiRepo(homepage string, projectURLs map[string]string) string {
	for _, k := range []string{"Source", "Repository", "Source Code", "Homepage"} {
		if v, ok := projectURLs[k]; ok && v != "" {
			return v
		}
	}
	return homepage
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
