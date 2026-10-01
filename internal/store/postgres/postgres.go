// Package postgres is the index's data store: the same scan.Report the CLI
// produces, persisted at scale for the public Registry Security Index. Plain SQL
// over pgx, no ORM. The index is the CLI run at scale with this behind it, which
// is what makes the public numbers reproducible.
package postgres

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/greyquill/mcpsight/internal/manifest"
	"github.com/greyquill/mcpsight/internal/scan"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// Store is a connection pool to the index database.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres using a standard DSN (or a libpq URL). Config is an
// environment variable per twelve-factor; the caller reads it.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Migrate applies the idempotent schema. Safe to call on every startup.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schemaSQL)
	return err
}

// ServerRef identifies a server independent of any single scan.
type ServerRef struct {
	Source       string // npm | pypi | oci | http
	Identifier   string // package spec or URL
	CanonicalURL string
	Registry     string
}

// RecordScan upserts the server, inserts the scan and its findings + tool
// definitions, and derives drift events by diffing against the server's previous
// scan. It runs in one transaction so a partial scan never lands. Returns the
// new scan id.
func (s *Store) RecordScan(ctx context.Context, ref ServerRef, rep *scan.Report) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful commit

	var serverID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO servers (source, identifier, canonical_url, registry, last_seen)
		VALUES ($1,$2,$3,$4, now())
		ON CONFLICT (source, identifier) DO UPDATE SET last_seen = now(),
		    canonical_url = COALESCE(EXCLUDED.canonical_url, servers.canonical_url)
		RETURNING id`,
		ref.Source, ref.Identifier, nullStr(ref.CanonicalURL), nullStr(ref.Registry),
	).Scan(&serverID)
	if err != nil {
		return 0, fmt.Errorf("upsert server: %w", err)
	}

	// The previous scan (before this one) drives drift detection.
	prevID, prevManifest, _ := latestScan(ctx, tx, serverID)

	manifestJSON, _ := json.Marshal(rep.Manifest)
	var scanID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO scans (server_id, version, scanned_at, mcpsight_version, rubric_version,
		                   score, grade, manifest_hash, duration_ms, manifest_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		serverID, nullStr(rep.Server.Version), parseScannedAt(rep.ScannedAt),
		rep.ToolVersion, rep.RubricVersion, rep.Score.Score, rep.Score.Grade,
		rep.ManifestHash, rep.DurationMs, manifestJSON,
	).Scan(&scanID)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}

	if err := insertFindings(ctx, tx, scanID, rep); err != nil {
		return 0, err
	}
	if err := insertToolDefs(ctx, tx, scanID, rep); err != nil {
		return 0, err
	}
	if prevManifest != nil && prevID != scanID {
		if err := insertDriftEvents(ctx, tx, serverID, prevID, scanID, prevManifest, rep.Manifest); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return scanID, nil
}

func insertFindings(ctx context.Context, tx pgx.Tx, scanID int64, rep *scan.Report) error {
	for _, f := range rep.Findings {
		detail, _ := json.Marshal(map[string]any{"detail": f.Detail, "remediation": f.Remediation, "meta": f.Meta})
		if _, err := tx.Exec(ctx, `
			INSERT INTO findings (scan_id, analyzer, rule_id, severity, title, detail_json, tool_name)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			scanID, f.Analyzer, f.RuleID, string(f.Severity), f.Title, detail, nullStr(f.Tool),
		); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	return nil
}

func insertToolDefs(ctx context.Context, tx pgx.Tx, scanID int64, rep *scan.Report) error {
	// Per-tool token counts (representative model) from the context-cost report.
	tokensByTool := map[string]int{}
	for _, tc := range rep.ContextCost.PerTool {
		tokensByTool[tc.Name] = tc.Tokens
	}
	for _, t := range rep.Manifest.Tools {
		tokens, _ := json.Marshal(map[string]int{"representative": tokensByTool[t.Name]})
		if _, err := tx.Exec(ctx, `
			INSERT INTO tool_defs (scan_id, name, description, schema_json, token_count_by_model_json)
			VALUES ($1,$2,$3,$4,$5)`,
			scanID, t.Name, t.Description, rawOrNull(t.InputSchema), tokens,
		); err != nil {
			return fmt.Errorf("insert tool_def: %w", err)
		}
	}
	return nil
}

func insertDriftEvents(ctx context.Context, tx pgx.Tx, serverID, fromScan, toScan int64, from, to *manifest.Manifest) error {
	for _, ch := range manifest.Diff(from, to) {
		diff, _ := json.Marshal(ch)
		if _, err := tx.Exec(ctx, `
			INSERT INTO drift_events (server_id, from_scan_id, to_scan_id, kind, severity, diff_json)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			serverID, fromScan, toScan, string(ch.Kind), driftSeverityFor(ch), diff,
		); err != nil {
			return fmt.Errorf("insert drift_event: %w", err)
		}
	}
	return nil
}

func latestScan(ctx context.Context, tx pgx.Tx, serverID int64) (int64, *manifest.Manifest, error) {
	var id int64
	var raw []byte
	err := tx.QueryRow(ctx, `
		SELECT id, manifest_json FROM scans WHERE server_id=$1 ORDER BY scanned_at DESC, id DESC LIMIT 1`,
		serverID,
	).Scan(&id, &raw)
	if err != nil {
		return 0, nil, err
	}
	var m manifest.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return id, nil, err
	}
	return id, &m, nil
}

func parseScannedAt(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Now().UTC()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func rawOrNull(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}
