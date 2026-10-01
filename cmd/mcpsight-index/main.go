// Command mcpsight-index is the Registry Security Index: it crawls MCP
// registries, scans every server with the same core the CLI uses, stores results
// in Postgres, and publishes a static snapshot / serves a JSON API.
// Config is environment variables (twelve-factor). A Greyquill Software project.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/greyquill/mcpsight/internal/crawl"
	"github.com/greyquill/mcpsight/internal/index"
	"github.com/greyquill/mcpsight/internal/probe"
	"github.com/greyquill/mcpsight/internal/scan"
	"github.com/greyquill/mcpsight/internal/store/postgres"
	"github.com/spf13/cobra"
)

func main() {
	if err := root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "mcpsight-index:", err)
		os.Exit(1)
	}
}

// dsn reads the database DSN from the environment (twelve-factor).
func dsn() (string, error) {
	for _, k := range []string{"MCPSIGHT_DSN", "DATABASE_URL"} {
		if v := os.Getenv(k); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("set MCPSIGHT_DSN (or DATABASE_URL) to the Postgres connection string")
}

func openStore(ctx context.Context) (*postgres.Store, error) {
	d, err := dsn()
	if err != nil {
		return nil, err
	}
	// Retry the connection so `docker compose up` works regardless of whether
	// Postgres finishes starting before the index does.
	var st *postgres.Store
	for attempt := 0; attempt < 30; attempt++ {
		st, err = postgres.Open(ctx, d)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return st, nil
}

func root() *cobra.Command {
	c := &cobra.Command{Use: "mcpsight-index", Short: "The MCP Registry Security Index", SilenceUsage: true}
	c.AddCommand(migrateCmd(), crawlCmd(), scanBatchCmd(), snapshotCmd(), serveCmd(), previewCmd())
	return c
}

// previewCmd serves the static index site (reading web/data/snapshot.json) and
// opens it in the browser — no database required. This is the run-and-open path
// for reviewing the published UI locally.
func previewCmd() *cobra.Command {
	var webDir, addr string
	var noOpen bool
	c := &cobra.Command{
		Use:   "preview",
		Short: "Serve the static index site and open it in the browser (no database)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(filepath.Join(webDir, "index.html")); err != nil {
				return fmt.Errorf("no index.html in %q (run from the repo root, or pass --web)", webDir)
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			url := "http://" + ln.Addr().String() + "/"
			fmt.Printf("mcpsight index preview: %s  (serving %s)\n", url, webDir)
			if !noOpen {
				if err := index.OpenBrowser(url); err != nil {
					fmt.Println("open your browser to the URL above")
				}
			}
			return http.Serve(ln, http.FileServer(http.Dir(webDir)))
		},
	}
	c.Flags().StringVar(&webDir, "web", "web", "directory containing the static site")
	c.Flags().StringVar(&addr, "addr", "127.0.0.1:8099", "listen address")
	c.Flags().BoolVar(&noOpen, "no-open", false, "do not open a browser")
	return c
}

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use: "migrate", Short: "Apply the database schema",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer st.Close()
			fmt.Println("schema applied")
			return nil
		},
	}
}

// discover builds the crawler from flags: --seed <file> or the official registry.
func discover(ctx context.Context, seed, registryBase string) ([]crawl.DiscoveredServer, error) {
	if seed != "" {
		return crawl.FileCrawler{Path: seed}.Crawl(ctx)
	}
	c := crawl.NewOfficialCrawler()
	if registryBase != "" {
		c.BaseURL = registryBase
	}
	return c.Crawl(ctx)
}

func crawlCmd() *cobra.Command {
	var seed, registryBase string
	c := &cobra.Command{
		Use: "crawl", Short: "List servers a crawler would discover (dry run)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ds, err := discover(cmd.Context(), seed, registryBase)
			if err != nil {
				return err
			}
			for _, d := range ds {
				fmt.Printf("%-40s %v\n", d.Name, d.Targets)
			}
			fmt.Printf("\n%d servers discovered\n", len(ds))
			return nil
		},
	}
	c.Flags().StringVar(&seed, "seed", "", "discover from a local seed JSON file instead of the registry")
	c.Flags().StringVar(&registryBase, "registry", "", "override the registry base URL")
	return c
}

func scanBatchCmd() *cobra.Command {
	var seed, registryBase, from string
	var offline, noSandbox bool
	var timeout time.Duration
	c := &cobra.Command{
		Use: "scan-batch", Short: "Crawl (or read a config), scan every server, store results",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer st.Close()

			var items []index.WorkItem
			if from != "" {
				items, err = index.FromConfig(from)
			} else {
				var ds []crawl.DiscoveredServer
				ds, err = discover(ctx, seed, registryBase)
				if err == nil {
					var errs []error
					items, errs = index.FromDiscovered(ds)
					for _, e := range errs {
						fmt.Fprintln(os.Stderr, "skip:", e)
					}
				}
			}
			if err != nil {
				return err
			}
			opts := scan.Options{Offline: offline, Probe: probe.Options{NoSandbox: noSandbox, Timeout: timeout}}
			sum := index.RunBatch(ctx, items, st, opts, func(f string, a ...any) { fmt.Printf(f+"\n", a...) })
			fmt.Printf("\ndone: %d scanned, %d failed\n", sum.Scanned, sum.Failed)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&from, "from", "", "scan servers from an MCP config file instead of crawling")
	f.StringVar(&seed, "seed", "", "discover from a local seed JSON file")
	f.StringVar(&registryBase, "registry", "", "override the registry base URL")
	f.BoolVar(&offline, "offline", false, "skip network analyzers (supply-chain)")
	f.BoolVar(&noSandbox, "no-sandbox", false, "DANGEROUS: scan stdio servers without a sandbox")
	f.DurationVar(&timeout, "timeout", 0, "per-server wall-clock budget")
	return c
}

func snapshotCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use: "snapshot", Short: "Write the static snapshot JSON the web reads",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer st.Close()
			if err := index.WriteSnapshotFile(ctx, st, out, time.Now()); err != nil {
				return err
			}
			fmt.Println("snapshot written to", out)
			return nil
		},
	}
	c.Flags().StringVarP(&out, "out", "o", "web/data/snapshot.json", "output path")
	return c
}

func serveCmd() *cobra.Command {
	c := &cobra.Command{
		Use: "serve", Short: "Serve the JSON API and web UI",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer st.Close()
			addr := envOr("MCPSIGHT_ADDR", ":8080")
			webDir := os.Getenv("MCPSIGHT_WEB")
			srv := index.NewServer(st, webDir)
			fmt.Printf("mcpsight-index serving on %s (web=%q)\n", addr, webDir)
			return http.ListenAndServe(addr, srv.Router())
		},
	}
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
