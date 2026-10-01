package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Bwrap runs a process under bubblewrap: new user/pid/ipc/uts/cgroup/net
// namespaces, read-only /usr, tmpfs /tmp, and a read-only decoy home. Network is
// denied unless Spec.AllowNet. This is the design validated by the Phase 0 spike
// (docs/phase0-spike.md).
type Bwrap struct{}

func (*Bwrap) Name() string { return "bubblewrap" }

// Available reports usability: bubblewrap is Linux-only and must be on PATH.
func (*Bwrap) Available() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "bubblewrap requires Linux; this host is " + runtime.GOOS
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		return false, "bwrap not found on PATH (install bubblewrap)"
	}
	return true, ""
}

func (*Bwrap) Start(ctx context.Context, spec Spec) (*Session, error) {
	if len(spec.Command) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	work, err := os.MkdirTemp("", "mcpsight-sbx-")
	if err != nil {
		return nil, err
	}
	home := filepath.Join(work, "home")
	if err := seedDecoys(home); err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	// Observed-capability tracing writes an strace log to an out-of-band dir
	// bound rw into the sandbox. Enabled only if requested and strace exists.
	tracing := spec.Trace && traceAvailable()
	outDir := filepath.Join(work, "out")
	tracePath := filepath.Join(outDir, "trace.log")
	if tracing {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			os.RemoveAll(work)
			return nil, err
		}
		if err := os.WriteFile(tracePath, nil, 0o644); err != nil {
			os.RemoveAll(work)
			return nil, err
		}
	}

	args := []string{
		// Start from an empty environment. Without this, bwrap passes the host's
		// environment through, including any tokens or DSNs the scanner holds.
		"--clearenv",
		"--unshare-user", "--unshare-pid", "--unshare-ipc",
		"--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--symlink", "usr/sbin", "/sbin",
		"--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/ssl", "/etc/ssl",
		"--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
		"--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
		"--proc", "/proc", "--dev", "/dev",
		"--size", "1073741824", "--tmpfs", "/tmp", // 1 GiB cap: room for package caches, but /tmp can't fill the host
		"--ro-bind", home, "/home/mcp",
		"--chdir", "/home/mcp",
		"--setenv", "HOME", "/home/mcp",
		"--setenv", "LANG", "C.UTF-8",
		"--setenv", "PATH", sandboxPath(spec.Command),
		// Package launchers (npx/uvx) need a writable cache; the decoy home is
		// read-only, so redirect all caches/state to the tmpfs /tmp.
		"--setenv", "XDG_CACHE_HOME", "/tmp/cache",
		"--setenv", "XDG_DATA_HOME", "/tmp/data",
		"--setenv", "XDG_CONFIG_HOME", "/tmp/config",
		"--setenv", "npm_config_cache", "/tmp/npm",
		"--setenv", "UV_CACHE_DIR", "/tmp/uv",
		"--setenv", "UV_PYTHON_INSTALL_DIR", "/tmp/uv-python",
	}
	if !spec.AllowNet {
		args = append(args, "--unshare-net")
	}
	// Make the server's own code readable inside the sandbox: bind read-only the
	// directories of any command arguments that are real host paths (the script,
	// its project dir for node_modules resolution). $HOME still points at the
	// decoy home, so reads of ~/.ssh etc. hit decoys, not these binds.
	for _, p := range codePaths(spec.Command) {
		args = append(args, "--ro-bind", p, p)
	}
	for _, e := range spec.Env {
		if k, v, ok := splitEnv(e); ok {
			args = append(args, "--setenv", k, v)
		}
	}
	if tracing {
		args = append(args, "--bind", outDir, "/out")
	}
	args = append(args, "--")
	// Under tracing, strace becomes the sandbox entrypoint and the server runs as
	// its child; the server's stdio still flows through to us, the trace goes to
	// the out-of-band file. openat/connect are enough to see decoy reads + egress.
	if tracing {
		args = append(args, straceBin, "-f", "-qq",
			"-e", "trace=network,openat,open,connect", "-o", "/out/trace.log")
	}
	args = append(args, spec.Command...)

	var finalize func(*Session)
	if tracing {
		decoys := DecoyRelPaths()
		netDenied := !spec.AllowNet
		finalize = func(s *Session) { s.trace = parseTrace(tracePath, decoys, netDenied) }
	}
	// Resource limits: cap per-process memory, CPU seconds, open
	// files, and file size so hostile code can't exhaust the host. Applied via
	// prlimit wrapping bwrap (limits are inherited by the whole tree). If prlimit
	// is unavailable we fall back to the wall-clock timeout alone.
	name, args := wrapWithLimits("bwrap", args, spec.Timeout)
	sess, err := startProcess(ctx, spec, name, args, func() { os.RemoveAll(work) }, finalize)
	if err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	return sess, nil
}

// wrapWithLimits prepends a prlimit invocation (when available) that bounds the
// sandboxed tree's memory, CPU time, open files, and max file size.
func wrapWithLimits(cmd string, args []string, timeout time.Duration) (string, []string) {
	prlimit, err := exec.LookPath("prlimit")
	if err != nil {
		return cmd, args
	}
	cpuSecs := int((timeout + timeout).Seconds()) // ~2x wall clock, a backstop
	if cpuSecs < 60 {
		cpuSecs = 60
	}
	limits := []string{
		"--as=2147483648",                // 2 GiB address space per process
		fmt.Sprintf("--cpu=%d", cpuSecs), // CPU seconds
		"--nofile=1024",                  // open files
		"--fsize=268435456",              // 256 MiB max file size
		"--",
		cmd,
	}
	return prlimit, append(limits, args...)
}

// straceBin is resolved lazily so a missing strace disables tracing rather than
// breaking the sandbox.
var straceBin = "strace"

func lookStrace() (string, error) { return exec.LookPath("strace") }

// startProcess launches argv, wiring stdio, a bounded stderr buffer, timeout,
// and cleanup. Shared by the bwrap and direct runners. finalize, if non-nil,
// runs after the process is reaped (e.g. to parse a trace) before cleanup.
func startProcess(ctx context.Context, spec Spec, name string, args []string, cleanup func(), finalize func(*Session)) (*Session, error) {
	timeout := spec.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	cmd := exec.CommandContext(cctx, name, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stderr := &capBuffer{limit: 64 * 1024}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("starting %s: %w", name, err)
	}

	sess := &Session{Stdin: stdin, Stdout: stdout, stderr: stderr}
	var once sync.Once
	sess.closeFn = func() error {
		once.Do(func() {
			cancel()       // signals the process to die
			_ = cmd.Wait() // reap
			if finalize != nil {
				finalize(sess) // e.g. parse the trace before cleanup removes it
			}
			cleanup()
		})
		return nil
	}
	return sess, nil
}

// codePaths returns the deduplicated set of host paths that must be
// bind-mounted for the command to run: the parent dir of each argument that is
// an existing file, and each argument that is an existing directory. Paths
// already provided by the base sandbox mounts are skipped. When a file sits
// directly in a home directory, only the file is bound, because binding its
// parent would expose ~/.ssh and everything else in that home.
func codePaths(command []string) []string {
	home, _ := os.UserHomeDir()
	seen := map[string]bool{}
	var paths []string
	add := func(p string) {
		if p == "" || coveredByBase(p) || seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}
	for _, arg := range command {
		abs, err := filepath.Abs(arg)
		if err != nil {
			continue
		}
		fi, err := os.Stat(abs)
		if err != nil {
			continue // not a path (a flag, a package name, etc.)
		}
		switch {
		case fi.IsDir() && exposesHome(abs, home):
			continue // never bind a home directory or anything above one
		case fi.IsDir():
			add(abs)
		case exposesHome(filepath.Dir(abs), home):
			add(abs)
		default:
			add(filepath.Dir(abs))
		}
	}
	return paths
}

// exposesHome reports whether binding dir would expose a whole home
// directory: dir is the scanning user's home, contains it, or is any
// /home/<user> or /root.
func exposesHome(dir, home string) bool {
	dir = filepath.Clean(dir)
	if home != "" {
		home = filepath.Clean(home)
		if dir == home || strings.HasPrefix(home, dir+"/") || dir == "/" {
			return true
		}
	}
	return dir == "/root" || filepath.Dir(dir) == "/home" || dir == "/home"
}

// coveredByBase reports whether a path is already available via the base mounts,
// so we don't redundantly (or dangerously) re-bind system or sandbox paths.
func coveredByBase(dir string) bool {
	for _, base := range []string{"/usr", "/bin", "/lib", "/lib64", "/sbin", "/proc", "/dev", "/tmp", "/etc", "/home/mcp"} {
		if dir == base || strings.HasPrefix(dir, base+"/") {
			return true
		}
	}
	// Refuse to bind overly-broad roots that would expose the whole host.
	return dir == "/" || dir == "/home" || dir == "/root"
}

// sandboxPath builds the in-sandbox PATH, prepending the resolved launcher's
// directory (e.g. ~/.local/bin for uvx) when it lives outside the base bins.
func sandboxPath(command []string) string {
	base := "/usr/bin:/bin"
	if len(command) == 0 || !strings.Contains(command[0], "/") {
		return base
	}
	dir := filepath.Dir(command[0])
	if dir == "/usr/bin" || dir == "/bin" || dir == "" {
		return base
	}
	return dir + ":" + base
}

func splitEnv(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return "", "", false
}
