package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Docker runs an OCI image as its own sandbox: `docker run` with the network
// denied, a read-only rootfs, a decoy home mounted read-only, and CPU/memory/PID
// limits. Container isolation replaces bubblewrap here — you cannot nest bwrap
// inside a container without a socket, and the container IS the boundary. Phase 1
// declared analysis + injection + supply chain all work; observed-capability
// tracing (strace) inside the container is a later enhancement.
type Docker struct{}

func (*Docker) Name() string { return "docker" }

func (*Docker) Available() (bool, string) {
	if _, err := exec.LookPath("docker"); err != nil {
		return false, "docker not found on PATH"
	}
	return true, ""
}

func (*Docker) Start(ctx context.Context, spec Spec) (*Session, error) {
	if spec.Image == "" {
		return nil, fmt.Errorf("docker runner requires an image")
	}
	work, err := os.MkdirTemp("", "mcpsight-oci-")
	if err != nil {
		return nil, err
	}
	home := filepath.Join(work, "home")
	if err := seedDecoys(home); err != nil {
		os.RemoveAll(work)
		return nil, err
	}

	args := []string{
		"run", "--rm", "-i",
		"--read-only",
		"--tmpfs", "/tmp:size=64m",
		"--pids-limit", "512",
		"--memory", "512m",
		"--cpus", "1",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"-v", home + ":/home/mcp:ro",
		"-e", "HOME=/home/mcp",
		"-e", "XDG_CACHE_HOME=/tmp/cache",
	}
	if !spec.AllowNet {
		args = append(args, "--network", "none")
	}
	for _, e := range spec.Env {
		args = append(args, "-e", e)
	}
	args = append(args, spec.Image)

	sess, err := startProcess(ctx, spec, "docker", args, func() { os.RemoveAll(work) }, nil)
	if err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	if spec.Trace {
		sess.traceSkipped = "the Docker runner does not observe behavior yet"
	}
	return sess, nil
}
