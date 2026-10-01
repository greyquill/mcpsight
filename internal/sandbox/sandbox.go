// Package sandbox runs untrusted stdio MCP servers under isolation. The default
// backend is bubblewrap (rootless, no Docker); network is denied by default and
// a decoy home is seeded so credential-exfil attempts are catchable. If no
// backend is usable, stdio scans are REFUSED rather than run unprotected — the
// one thing this package must never do is silently execute untrusted code.
// See docs/threat-model.md §6.
package sandbox

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/greyquill/mcpsight/internal/analyze"
)

// DefaultTimeout bounds a probe's wall-clock time.
const DefaultTimeout = 30 * time.Second

// Spec describes a sandboxed process to launch.
type Spec struct {
	Command   []string      // argv; Command[0] is the executable (stdio runners)
	Image     string        // OCI image ref (Docker runner only)
	Env       []string      // extra environment as KEY=VALUE
	AllowNet  bool          // if false (default), egress is denied
	DecoyHome bool          // seed a fake home with decoy credentials
	Trace     bool          // observe decoy reads + egress (requires strace)
	Timeout   time.Duration // wall-clock budget; DefaultTimeout if zero
}

// Session is a running sandboxed process. The caller writes MCP requests to
// Stdin and reads responses from Stdout; Close terminates and cleans up.
type Session struct {
	Stdin  io.WriteCloser
	Stdout io.Reader

	stderr       *capBuffer
	trace        *analyze.SandboxTrace
	traceSkipped string
	closeFn      func() error
}

// Trace returns observed behavior from the run. Nil in Phase 1 (declared-only);
// Phase 2 populates decoy reads and egress attempts.
func (s *Session) Trace() *analyze.SandboxTrace { return s.trace }

// TraceSkipped says why behavior was not observed although Spec.Trace asked for
// it. Empty when the run was traced or tracing was not requested. A scan must
// report this, or an unobserved run would look clean.
func (s *Session) TraceSkipped() string { return s.traceSkipped }

// Stderr returns whatever the process wrote to stderr (for diagnostics).
func (s *Session) Stderr() string {
	if s.stderr == nil {
		return ""
	}
	return s.stderr.String()
}

// Close terminates the process and removes temporary state.
func (s *Session) Close() error {
	if s.closeFn == nil {
		return nil
	}
	return s.closeFn()
}

// Runner launches sandboxed processes.
type Runner interface {
	Name() string
	// Available reports whether this backend can be used here, with a
	// human-readable reason when it cannot.
	Available() (bool, string)
	Start(ctx context.Context, spec Spec) (*Session, error)
}

// Select returns the best available runner. It prefers bubblewrap. If no real
// sandbox is available it returns an error unless allowUnsandboxed is set, in
// which case it returns the direct (unsafe) runner. The caller is responsible
// for printing the loud warning that accompanies --no-sandbox.
func Select(allowUnsandboxed bool) (Runner, error) {
	bw := &Bwrap{}
	if ok, _ := bw.Available(); ok {
		return bw, nil
	}
	_, reason := bw.Available()
	if allowUnsandboxed {
		return &Direct{}, nil
	}
	return nil, fmt.Errorf("no sandbox backend available (%s); refusing to run untrusted stdio code. "+
		"Use --no-sandbox to override (dangerous), or scan remote targets only", reason)
}
