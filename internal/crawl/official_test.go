package crawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// Two pages in the registry's live shape (server.schema.json 2025-12-11).
var registryPages = map[string]string{
	"": `{"servers":[
		{"server":{"name":"io.example/npm-one","description":"An npm server.","version":"1.0.1",
			"repository":{"url":"https://github.com/example/one"},
			"packages":[{"registryType":"npm","identifier":"npm-one","version":"1.0.1","transport":{"type":"stdio"}}]},
		 "_meta":{"io.modelcontextprotocol.registry/official":{"isLatest":true}}},
		{"server":{"name":"io.example/remote","version":"2.0.0",
			"remotes":[{"type":"streamable-http","url":"https://mcp.example.com/mcp"}]}}
	],"metadata":{"nextCursor":"io.example/remote:2.0.0","count":2}}`,
	"io.example/remote:2.0.0": `{"servers":[
		{"server":{"name":"io.example/py","version":"0.3.0",
			"packages":[{"registryType":"pypi","identifier":"py-mcp","version":"0.3.0"},
			            {"registryType":"oci","identifier":"ghcr.io/example/py-mcp:0.3.0"}]}}
	],"metadata":{"count":1}}`,
}

func TestOfficialCrawlerLiveShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/servers" || r.URL.Query().Get("version") != "latest" {
			t.Errorf("unexpected request %s", r.URL)
		}
		body, ok := registryPages[r.URL.Query().Get("cursor")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := (&OfficialCrawler{BaseURL: srv.URL, Client: srv.Client()}).Crawl(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []DiscoveredServer{
		{Name: "io.example/npm-one", Description: "An npm server.", RepoURL: "https://github.com/example/one", Registry: "official", Targets: []string{"npx:npm-one@1.0.1"}},
		{Name: "io.example/remote", Registry: "official", Targets: []string{"https://mcp.example.com/mcp"}},
		{Name: "io.example/py", Registry: "official", Targets: []string{"uvx:py-mcp", "docker:ghcr.io/example/py-mcp:0.3.0"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("crawl mismatch\n got: %+v\nwant: %+v", got, want)
	}
}
