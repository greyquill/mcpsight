package supplychain

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

// Vuln is a known vulnerability from OSV.dev.
type Vuln struct {
	ID       string
	Summary  string
	Severity string // best-effort: CRITICAL/HIGH/MODERATE/LOW/"" if unknown
}

// queryOSV asks OSV.dev whether a package version has known advisories. OSV is
// free and needs no key. Failures are returned as errors and treated as
// "unknown", never as "clean".
func queryOSV(ctx context.Context, client *http.Client, name, version, ecosystem string) ([]Vuln, error) {
	body, _ := json.Marshal(map[string]any{
		"version": version,
		"package": map[string]string{"name": name, "ecosystem": ecosystem},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		Vulns []struct {
			ID               string         `json:"id"`
			Summary          string         `json:"summary"`
			DatabaseSpecific map[string]any `json:"database_specific"`
			Severity         []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	vulns := make([]Vuln, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		sev := ""
		if ds, ok := v.DatabaseSpecific["severity"].(string); ok {
			sev = ds
		}
		vulns = append(vulns, Vuln{ID: v.ID, Summary: v.Summary, Severity: sev})
	}
	return vulns, nil
}
