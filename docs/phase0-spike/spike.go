// Phase 0 spike: prove we can, from Go, run an untrusted stdio MCP server inside
// a bubblewrap sandbox (no Docker), complete the MCP handshake, and DETECT both
// a credential-exfil read of a decoy file and an outbound network attempt.
//
// Detection mechanism for the spike: strace the sandboxed process (network +
// openat syscalls) to an out-of-band log, parsed on the host. Production will
// replace strace with a netns recording proxy (egress) + fanotify (fs reads);
// this only needs to prove the signals are observable.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type rpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "SPIKE FAILED:", err)
		os.Exit(1)
	}
}

func run() error {
	here, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	work, err := os.MkdirTemp("", "mcpsight-spike-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	// Seed a decoy home with realistic-looking secrets.
	home := filepath.Join(work, "home")
	seedDecoys(home)
	outDir := filepath.Join(work, "out")
	os.MkdirAll(outDir, 0o755)
	tracePath := filepath.Join(outDir, "trace.log")
	os.WriteFile(tracePath, nil, 0o644)

	src := filepath.Join(here, "evil-server.js")
	body, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("evil-server.js not next to spike binary: %w", err)
	}
	// Place the server inside the decoy home so a single ro-bind covers it
	// (can't create a mountpoint file under a read-only bind).
	if err := os.WriteFile(filepath.Join(home, "evil-server.js"), body, 0o644); err != nil {
		return err
	}

	args := []string{
		"--unshare-user", "--unshare-pid", "--unshare-ipc",
		"--unshare-uts", "--unshare-cgroup", "--unshare-net",
		"--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--symlink", "usr/sbin", "/sbin",
		"--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/ssl", "/etc/ssl",
		"--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--ro-bind", home, "/home/mcp",
		"--bind", outDir, "/out",
		"--chdir", "/home/mcp",
		"--setenv", "HOME", "/home/mcp",
		"--setenv", "PATH", "/usr/bin:/bin",
		"--",
		"strace", "-f", "-qq", "-e", "trace=network,openat,open,connect",
		"-o", "/out/trace.log",
		"/usr/bin/node", "/home/mcp/evil-server.js",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bwrap", args...)
	cmd.Stderr = os.Stderr // strace/node diagnostics visible
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("bwrap start: %w", err)
	}

	rd := bufio.NewReader(stdout)
	enc := json.NewEncoder(stdin)
	send := func(v any) error { return enc.Encode(v) }
	readResp := func() (*rpc, error) {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		var r rpc
		return &r, json.Unmarshal(line, &r)
	}

	fmt.Println("→ initialize")
	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcpsight-spike", "version": "0"},
	}})
	init, err := readResp()
	if err != nil {
		return fmt.Errorf("no initialize response: %w", err)
	}
	fmt.Printf("← initialize result: %s\n", string(init.Result))

	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	fmt.Println("→ tools/list")
	send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	tl, err := readResp()
	if err != nil {
		return fmt.Errorf("no tools/list response: %w", err)
	}
	fmt.Printf("← tools/list result: %s\n", truncate(string(tl.Result), 400))

	stdin.Close()
	cmd.Wait()

	// --- Analyze the trace for the two detections ---
	trace, _ := os.ReadFile(tracePath)
	ts := string(trace)
	report(ts)
	return nil
}

func seedDecoys(home string) {
	files := map[string]string{
		".ssh/id_rsa":      "-----BEGIN OPENSSH PRIVATE KEY-----\nDECOY_DO_NOT_USE\n-----END OPENSSH PRIVATE KEY-----\n",
		".aws/credentials": "[default]\naws_access_key_id = AKIADECOYDECOYDECOY\naws_secret_access_key = decoydecoydecoydecoydecoydecoydecoydecoy\n",
		".env":             "OPENAI_API_KEY=sk-decoy0000000000000000000000000000000000\n",
	}
	for rel, body := range files {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o600)
	}
}

func report(trace string) {
	decoys := []string{".ssh/id_rsa", ".aws/credentials", ".env"}
	var reads []string
	for _, d := range decoys {
		if strings.Contains(trace, d) {
			reads = append(reads, d)
		}
	}
	var net []string
	for _, line := range strings.Split(trace, "\n") {
		if strings.Contains(line, "connect(") && (strings.Contains(line, "sin_addr") || strings.Contains(line, "sin6_addr")) && !strings.Contains(line, "127.0.0.1") && !strings.Contains(line, "::1") {
			net = append(net, strings.TrimSpace(line))
		}
	}

	fmt.Println("\n================ DETECTIONS ================")
	fmt.Printf("CRITICAL decoy-credential read : %v\n", nonEmpty(reads))
	for _, r := range reads {
		fmt.Printf("   • read %s\n", r)
	}
	fmt.Printf("HIGH     network egress attempt: %v\n", len(net) > 0)
	for _, n := range net {
		fmt.Printf("   • %s\n", truncate(n, 160))
	}
	fmt.Println("============================================")
	if len(reads) == 0 || len(net) == 0 {
		fmt.Println("NOTE: a signal is missing — inspect /out/trace.log")
	} else {
		fmt.Println("SPIKE PASSED: sandbox ran untrusted code and both signals were observed.")
	}
}

func nonEmpty(s []string) bool { return len(s) > 0 }
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
