// Package probe runs a resolved target and returns its canonical manifest. For
// remote targets it connects over HTTP; for stdio targets it launches the server
// inside the sandbox and speaks MCP over its stdio. This is the single place
// where untrusted code gets executed, always via the sandbox package.
package probe

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/greyquill/mcpsight/internal/analyze"
	"github.com/greyquill/mcpsight/internal/manifest"
	"github.com/greyquill/mcpsight/internal/mcp"
	"github.com/greyquill/mcpsight/internal/sandbox"
	"github.com/greyquill/mcpsight/internal/target"
)

// Options controls how a probe runs.
type Options struct {
	AllowNet  bool          // force network on even for local stdio targets
	NoSandbox bool          // run stdio targets unsandboxed (dangerous)
	Timeout   time.Duration // wall-clock budget; sandbox.DefaultTimeout if zero
}

// Result bundles what a probe produced.
type Result struct {
	Target   target.Target
	Manifest *manifest.Manifest
	Trace    *analyze.SandboxTrace // nil for remote and for Phase 1 declared-only
	Auth     *analyze.AuthPosture  // remote auth/TLS posture; nil for stdio
	Runner   string                // sandbox backend used, or "remote"
	AllowNet bool
}

// Probe executes a target and returns its manifest.
func Probe(ctx context.Context, t target.Target, opts Options) (*Result, error) {
	if t.Kind == target.KindRemote {
		return probeRemote(ctx, t, opts)
	}
	return probeStdio(ctx, t, opts)
}

func probeRemote(ctx context.Context, t target.Target, opts Options) (*Result, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = sandbox.DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpClient := &http.Client{Timeout: timeout}
	tr := mcp.NewHTTPTransport(t.URL, httpClient, t.Headers)
	client := mcp.NewClient(tr)
	defer client.Close()

	m, err := client.Introspect(cctx)
	if err != nil {
		return nil, fmt.Errorf("probing %s: %w", t.URL, err)
	}

	auth := &analyze.AuthPosture{Scheme: scheme(t.URL), TLSVersion: tr.LastTLSVersion}
	if len(t.Headers) == 0 {
		// The successful probe itself used no credentials.
		auth.UnauthenticatedListing = true
	} else {
		// Credentials were supplied; check whether they were actually needed by
		// re-probing without them.
		auth.RequiresAuth = true
		un := mcp.NewClient(mcp.NewHTTPTransport(t.URL, httpClient, nil))
		if _, uerr := un.Introspect(cctx); uerr == nil {
			auth.UnauthenticatedListing = true
			auth.RequiresAuth = false
		}
		un.Close()
	}
	return &Result{Target: t, Manifest: m, Auth: auth, Runner: "remote"}, nil
}

// selectRunner picks the sandbox backend for a target: docker: images run under
// their own container isolation; everything else uses bubblewrap (or refuses).
func selectRunner(t target.Target, allowUnsandboxed bool) (sandbox.Runner, error) {
	if t.Kind == target.KindDocker {
		d := &sandbox.Docker{}
		if ok, reason := d.Available(); !ok {
			return nil, fmt.Errorf("cannot scan docker target: %s", reason)
		}
		return d, nil
	}
	return sandbox.Select(allowUnsandboxed)
}

// resolveLauncher rewrites a bare launcher name (npx, uvx, node, …) to its
// absolute path so the sandbox can bind-mount its directory and put it on PATH.
// Common user/tool bin dirs are searched in addition to the process PATH, since
// uv/uvx typically live in ~/.local/bin. Unresolvable names are left as-is.
func resolveLauncher(command []string) []string {
	if len(command) == 0 || strings.Contains(command[0], "/") {
		return command
	}
	extra := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		extra = append(extra, filepath.Join(home, ".local", "bin"))
	}
	extra = append(extra, "/usr/local/bin")
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", strings.Join(append(extra, origPath), string(os.PathListSeparator)))
	abs, err := exec.LookPath(command[0])
	os.Setenv("PATH", origPath)
	if err != nil {
		return command
	}
	out := append([]string(nil), command...)
	out[0] = abs
	return out
}

func scheme(rawURL string) string {
	if strings.HasPrefix(rawURL, "https://") {
		return "https"
	}
	return "http"
}

func probeStdio(ctx context.Context, t target.Target, opts Options) (*Result, error) {
	runner, err := selectRunner(t, opts.NoSandbox)
	if err != nil {
		return nil, err
	}
	// Package launchers (npx/uvx) and OCI images need the network to fetch and
	// start, so we allow it for them (declared-only for those; egress findings
	// only apply to network-denied runs). Local commands default to
	// network-denied; --allow-net forces it on.
	allowNet := opts.AllowNet || t.Kind == target.KindNPX || t.Kind == target.KindUVX || t.Kind == target.KindDocker

	spec := sandbox.Spec{
		Command:   resolveLauncher(t.Command),
		Image:     t.Package, // OCI image ref for docker targets
		Env:       t.Env,
		AllowNet:  allowNet,
		DecoyHome: true,
		Trace:     true, // observe decoy reads + egress (no-op if strace absent / docker)
		Timeout:   opts.Timeout,
	}
	sess, err := runner.Start(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("starting sandbox for %s: %w", t.Name, err)
	}
	defer sess.Close() // safety net for early returns; Close is idempotent

	tr := mcp.NewStdioTransport(sess.Stdin, sess.Stdout)
	client := mcp.NewClient(tr)
	m, err := client.Introspect(ctx)
	if err != nil {
		if se := strings.TrimSpace(sess.Stderr()); se != "" {
			return nil, fmt.Errorf("probing %s: %w\nserver stderr:\n%s", t.Name, err, tailLines(se, 15))
		}
		return nil, fmt.Errorf("probing %s: %w", t.Name, err)
	}
	// Close now (not via defer) so the sandbox trace is finalized before we read
	// it: Trace() is only populated once the process is reaped and the strace log
	// parsed. Reading it before Close would always see nil.
	sess.Close()
	return &Result{
		Target: t, Manifest: m, Trace: sess.Trace(),
		Runner: runner.Name(), AllowNet: allowNet,
	}, nil
}

func tailLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
