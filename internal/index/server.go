package index

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/greyquill/mcpsight/internal/store/postgres"
)

// Server exposes the index over HTTP: a JSON API for the data and static file
// serving for the web UI. This is the self-hostable index — "docker compose up"
// and a stranger has a working copy. The public GitHub Pages site
// instead reads a pre-generated snapshot.json and needs no backend.
type Server struct {
	store  *postgres.Store
	webDir string
}

// NewServer builds a server over the store; webDir (may be "") is served as
// static files at /.
func NewServer(store *postgres.Store, webDir string) *Server {
	return &Server{store: store, webDir: webDir}
}

// Router returns the HTTP handler.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	r.Route("/api", func(r chi.Router) {
		r.Get("/stats", s.handleStats)
		r.Get("/servers", s.handleServers)
		r.Get("/drift", s.handleDrift)
		r.Get("/snapshot", s.handleSnapshot)
	})

	if s.webDir != "" {
		r.Handle("/*", http.FileServer(http.Dir(s.webDir)))
	}
	return r
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.store.Stats(r.Context())
	writeJSON(w, st, err)
}

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListLatest(r.Context())
	writeJSON(w, list, err)
}

func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.RecentDrift(r.Context(), 50)
	writeJSON(w, list, err)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := BuildSnapshot(r.Context(), s.store, time.Now())
	writeJSON(w, snap, err)
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

// WriteSnapshotFile builds a snapshot and writes it to path (creating parent
// dirs). Used by the `snapshot` subcommand to publish the static site's data.
func WriteSnapshotFile(ctx context.Context, src SnapshotSource, path string, now time.Time) error {
	snap, err := BuildSnapshot(ctx, src, now)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
