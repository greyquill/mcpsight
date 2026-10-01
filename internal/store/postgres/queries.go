package postgres

import (
	"context"
	"regexp"
	"time"

	"github.com/greyquill/mcpsight/internal/manifest"
)

// hijackPhrase mirrors the drift analyzer's high-confidence signal, so a
// description that gains an instruction is recorded as a critical drift event.
var hijackPhrase = regexp.MustCompile(`(?i)(ignore (all )?previous|do not (tell|inform) the user|before (calling|using) any other tool)`)

// driftSeverityFor assigns a severity to a structural change, content-aware for
// the cases that matter (a description gaining a hijack instruction is critical).
func driftSeverityFor(ch manifest.Change) string {
	switch ch.Kind {
	case manifest.ToolDescriptionChanged:
		if hijackPhrase.MatchString(ch.After) && !hijackPhrase.MatchString(ch.Before) {
			return "critical"
		}
		if len(ch.After) < len(ch.Before) {
			return "info"
		}
		return "low"
	case manifest.ToolAdded:
		return "medium"
	case manifest.ToolSchemaChanged, manifest.ResourceAdded, manifest.PromptAdded:
		return "low"
	default:
		return "info"
	}
}

// ServerSummary is one row of the index: a server plus its latest grade and
// headline numbers. This is what the leaderboard and per-server pages render.
type ServerSummary struct {
	ID            int64     `json:"id"`
	Source        string    `json:"source"`
	Identifier    string    `json:"identifier"`
	CanonicalURL  string    `json:"canonical_url,omitempty"`
	Registry      string    `json:"registry,omitempty"`
	Version       string    `json:"version,omitempty"`
	Grade         string    `json:"grade"`
	Score         int       `json:"score"`
	ManifestHash  string    `json:"manifest_hash"`
	ToolCount     int       `json:"tool_count"`
	TokenEstimate int       `json:"token_estimate"`
	Critical      int       `json:"critical"`
	High          int       `json:"high"`
	ScannedAt     time.Time `json:"scanned_at"`
}

// ListLatest returns the latest scan summary for every server, worst grade
// first. Aggregates (finding counts, token totals) are merged in Go to keep the
// SQL legible.
func (s *Store) ListLatest(ctx context.Context) ([]ServerSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (s.id)
		       s.id, s.source, s.identifier, COALESCE(s.canonical_url,''), COALESCE(s.registry,''),
		       sc.id, COALESCE(sc.version,''), sc.grade, sc.score, sc.manifest_hash, sc.scanned_at
		FROM servers s JOIN scans sc ON sc.server_id = s.id
		ORDER BY s.id, sc.scanned_at DESC, sc.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ServerSummary
	scanIDs := map[int64]int{} // scan_id -> index in out
	for rows.Next() {
		var sm ServerSummary
		var scanID int64
		if err := rows.Scan(&sm.ID, &sm.Source, &sm.Identifier, &sm.CanonicalURL, &sm.Registry,
			&scanID, &sm.Version, &sm.Grade, &sm.Score, &sm.ManifestHash, &sm.ScannedAt); err != nil {
			return nil, err
		}
		scanIDs[scanID] = len(out)
		out = append(out, sm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}

	ids := make([]int64, 0, len(scanIDs))
	for id := range scanIDs {
		ids = append(ids, id)
	}
	// Finding counts by severity per scan.
	fr, err := s.pool.Query(ctx, `
		SELECT scan_id, severity, count(*) FROM findings WHERE scan_id = ANY($1) GROUP BY scan_id, severity`, ids)
	if err != nil {
		return nil, err
	}
	for fr.Next() {
		var scanID int64
		var sev string
		var n int
		if err := fr.Scan(&scanID, &sev, &n); err != nil {
			fr.Close()
			return nil, err
		}
		idx := scanIDs[scanID]
		switch sev {
		case "critical":
			out[idx].Critical = n
		case "high":
			out[idx].High = n
		}
	}
	fr.Close()

	// Tool count and representative token total per scan.
	tr, err := s.pool.Query(ctx, `
		SELECT scan_id, count(*), COALESCE(SUM((token_count_by_model_json->>'representative')::int),0)
		FROM tool_defs WHERE scan_id = ANY($1) GROUP BY scan_id`, ids)
	if err != nil {
		return nil, err
	}
	defer tr.Close()
	for tr.Next() {
		var scanID int64
		var count, tokens int
		if err := tr.Scan(&scanID, &count, &tokens); err != nil {
			return nil, err
		}
		idx := scanIDs[scanID]
		out[idx].ToolCount = count
		out[idx].TokenEstimate = tokens
	}
	return out, tr.Err()
}

// Stats is the ecosystem-wide summary the index headline shows.
type Stats struct {
	TotalServers      int            `json:"total_servers"`
	GradeDistribution map[string]int `json:"grade_distribution"`
	CriticalServers   int            `json:"servers_with_critical"`
	DriftEvents30d    int            `json:"drift_events_30d"`
}

// Stats computes the ecosystem summary from the latest scan of each server.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	st := Stats{GradeDistribution: map[string]int{}}
	latest, err := s.ListLatest(ctx)
	if err != nil {
		return st, err
	}
	st.TotalServers = len(latest)
	for _, sm := range latest {
		st.GradeDistribution[sm.Grade]++
		if sm.Critical > 0 {
			st.CriticalServers++
		}
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM drift_events WHERE detected_at > now() - interval '30 days'`).Scan(&st.DriftEvents30d); err != nil {
		return st, err
	}
	return st, nil
}

// DriftRow is a recorded change between two scans of a server.
type DriftRow struct {
	ServerIdentifier string    `json:"server_identifier"`
	Kind             string    `json:"kind"`
	Severity         string    `json:"severity"`
	Target           string    `json:"target"`
	DetectedAt       time.Time `json:"detected_at"`
}

// RecentDrift returns the most recent drift events across all servers.
func (s *Store) RecentDrift(ctx context.Context, limit int) ([]DriftRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT sv.identifier, d.kind, d.severity, COALESCE(d.diff_json->>'target',''), d.detected_at
		FROM drift_events d JOIN servers sv ON sv.id = d.server_id
		ORDER BY d.detected_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DriftRow
	for rows.Next() {
		var d DriftRow
		if err := rows.Scan(&d.ServerIdentifier, &d.Kind, &d.Severity, &d.Target, &d.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
