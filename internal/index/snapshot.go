package index

import (
	"context"
	"sort"
	"time"

	"github.com/greyquill/mcpsight/internal/buildinfo"
	"github.com/greyquill/mcpsight/internal/store/postgres"
)

// Snapshot is the static JSON document the web reads. It is a point-in-time view
// of the index, published alongside the site so the page needs no live backend.
// Every number carries the code version that produced it, so it is reproducible.
type Snapshot struct {
	GeneratedAt   string                   `json:"generated_at"`
	ToolVersion   string                   `json:"mcpsight_version"`
	RubricVersion int                      `json:"rubric_version"`
	Stats         postgres.Stats           `json:"stats"`
	Servers       []postgres.ServerSummary `json:"servers"`
	Leaderboard   []postgres.ServerSummary `json:"context_cost_leaderboard"`
	RecentDrift   []postgres.DriftRow      `json:"recent_drift"`
}

// SnapshotSource is the read side of the store the snapshot needs.
type SnapshotSource interface {
	ListLatest(ctx context.Context) ([]postgres.ServerSummary, error)
	Stats(ctx context.Context) (postgres.Stats, error)
	RecentDrift(ctx context.Context, limit int) ([]postgres.DriftRow, error)
}

// BuildSnapshot assembles the published document. now is passed in so callers
// control the timestamp (and tests stay deterministic).
func BuildSnapshot(ctx context.Context, src SnapshotSource, now time.Time) (*Snapshot, error) {
	servers, err := src.ListLatest(ctx)
	if err != nil {
		return nil, err
	}
	stats, err := src.Stats(ctx)
	if err != nil {
		return nil, err
	}
	drift, err := src.RecentDrift(ctx, 50)
	if err != nil {
		return nil, err
	}

	// Worst grade first for the main table.
	sort.SliceStable(servers, func(i, j int) bool { return servers[i].Score < servers[j].Score })

	// Context-cost leaderboard: the priciest servers, top 20.
	board := append([]postgres.ServerSummary(nil), servers...)
	sort.SliceStable(board, func(i, j int) bool { return board[i].TokenEstimate > board[j].TokenEstimate })
	if len(board) > 20 {
		board = board[:20]
	}

	return &Snapshot{
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		ToolVersion:   buildinfo.Version,
		RubricVersion: buildinfo.RubricVersion,
		Stats:         stats,
		Servers:       servers,
		Leaderboard:   board,
		RecentDrift:   drift,
	}, nil
}
