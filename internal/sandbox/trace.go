package sandbox

import (
	"os"
	"regexp"
	"strings"

	"github.com/greyquill/mcpsight/internal/analyze"
)

// Observed-capability tracing turns the Phase 0 spike into a product feature:
// the sandboxed process is run under strace, and its network + file syscalls are
// parsed out of band to see what it actually did. strace is a pragmatic Phase 2
// mechanism; a hardened build would use a netns recording proxy + fanotify
// instead (see docs/threat-model.md §6). If strace is unavailable, tracing is
// simply skipped and no observed capabilities are reported.

// connectRe extracts the IPv4 address and port from an strace connect() line.
var connectRe = regexp.MustCompile(`connect\([0-9]+, \{sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([0-9.]+)"\)`)

// traceAvailable reports whether strace can be used for tracing.
func traceAvailable() bool {
	_, err := lookStrace()
	return err == nil
}

// parseTrace reads an strace log and derives observed behavior: which decoy
// files were read, and which network destinations were contacted (separating
// DNS/resolver attempts from raw external egress).
func parseTrace(logPath string, decoyRel []string, netDenied bool) *analyze.SandboxTrace {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return &analyze.SandboxTrace{NetDenied: netDenied}
	}
	tr := &analyze.SandboxTrace{NetDenied: netDenied}
	text := string(data)

	// Decoy reads: a decoy path appearing in an openat/open line.
	for _, rel := range decoyRel {
		if strings.Contains(text, "/"+rel) || strings.Contains(text, rel) {
			if openedPath(text, rel) {
				tr.DecoyReads = appendUniqueStr(tr.DecoyReads, rel)
			}
		}
	}

	// Network: classify each connect() by destination.
	egress := map[string]bool{}
	dns := map[string]bool{}
	for _, m := range connectRe.FindAllStringSubmatch(text, -1) {
		port, addr := m[1], m[2]
		switch {
		case isLoopbackResolver(addr) || port == "53":
			dns[addr+":"+port] = true
		case isLoopback(addr):
			// ordinary loopback (e.g. IPC); not egress
		default:
			egress[addr+":"+port] = true
		}
	}
	tr.EgressHosts = keysOf(egress)
	tr.DNSResolve = keysOf(dns)
	return tr
}

// openedPath reports whether the trace shows an openat/open call referencing rel.
func openedPath(text, rel string) bool {
	for _, line := range strings.Split(text, "\n") {
		if (strings.Contains(line, "openat(") || strings.Contains(line, "open(")) && strings.Contains(line, rel) {
			return true
		}
	}
	return false
}

func isLoopback(addr string) bool { return strings.HasPrefix(addr, "127.") || addr == "::1" }

// isLoopbackResolver matches the systemd-resolved stub (127.0.0.53), which is a
// resolution attempt, not raw egress.
func isLoopbackResolver(addr string) bool { return addr == "127.0.0.53" }

func appendUniqueStr(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

func keysOf(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
