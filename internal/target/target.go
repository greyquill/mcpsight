// Package target resolves a user-supplied target string into something the
// probe can run: an stdio command (npx/uvx/docker) or a remote HTTP endpoint.
// It also parses MCP config files so `mcpsight scan --from config.json` can
// enumerate every server a user already has.
package target

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Kind is the transport class of a target.
type Kind string

const (
	KindNPX    Kind = "npx"    // npm package run via npx (stdio)
	KindUVX    Kind = "uvx"    // PyPI package run via uvx (stdio)
	KindDocker Kind = "docker" // OCI image (stdio, nested container)
	KindRemote Kind = "remote" // Streamable HTTP endpoint
	KindLocal  Kind = "local"  // an explicit local command (from a config file)
)

// Target is a resolved scan target.
type Target struct {
	Raw     string            `json:"raw"`
	Name    string            `json:"name"` // display name (server name or package)
	Kind    Kind              `json:"kind"`
	Command []string          `json:"command,omitempty"` // stdio: argv to launch
	Env     []string          `json:"env,omitempty"`     // stdio: extra environment (KEY=VALUE)
	URL     string            `json:"url,omitempty"`     // remote: endpoint
	Headers map[string]string `json:"headers,omitempty"` // remote: extra headers
	Package string            `json:"package,omitempty"` // npx/uvx: package spec for prepare/supply-chain
}

// MarshalJSON writes a Target with its environment values and header values
// replaced by "[redacted]". Config files often carry API tokens there, and
// reports are written to disk and pasted into pull requests. Names are kept so
// a reader can still see which variables and headers were set.
func (t Target) MarshalJSON() ([]byte, error) {
	type plain Target // no MarshalJSON, so no recursion
	out := plain(t)
	if len(t.Env) > 0 {
		out.Env = make([]string, len(t.Env))
		for i, e := range t.Env {
			k, _, _ := strings.Cut(e, "=")
			out.Env[i] = k + "=[redacted]"
		}
	}
	if len(t.Headers) > 0 {
		out.Headers = make(map[string]string, len(t.Headers))
		for k := range t.Headers {
			out.Headers[k] = "[redacted]"
		}
	}
	return json.Marshal(out)
}

// Stdio reports whether the target runs as a local process (and thus needs the
// sandbox).
func (t Target) Stdio() bool { return t.Kind != KindRemote }

// Resolve parses a single target string of the forms documented in MANUAL.md:
//
//	npx:@scope/name@1.2.3
//	uvx:some-mcp-server
//	docker:ghcr.io/org/server:tag
//	https://mcp.example.com/sse
func Resolve(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return Target{}, fmt.Errorf("empty target")
	case strings.HasPrefix(raw, "https://"), strings.HasPrefix(raw, "http://"):
		return Target{Raw: raw, Kind: KindRemote, URL: raw, Name: raw}, nil
	case strings.HasPrefix(raw, "npx:"):
		pkg := strings.TrimPrefix(raw, "npx:")
		return Target{Raw: raw, Kind: KindNPX, Name: pkg, Package: pkg,
			Command: []string{"npx", "-y", pkg}}, nil
	case strings.HasPrefix(raw, "uvx:"):
		pkg := strings.TrimPrefix(raw, "uvx:")
		return Target{Raw: raw, Kind: KindUVX, Name: pkg, Package: pkg,
			Command: []string{"uvx", pkg}}, nil
	case strings.HasPrefix(raw, "docker:"):
		img := strings.TrimPrefix(raw, "docker:")
		return Target{Raw: raw, Kind: KindDocker, Name: img, Package: img,
			Command: []string{"docker", "run", "--rm", "-i", img}}, nil
	default:
		return Target{}, fmt.Errorf("unrecognized target %q: expected npx:, uvx:, docker:, or an https:// URL", raw)
	}
}

// serverEntry is one server in an MCP config file. It covers both the stdio
// shape ({command, args, env}) and the remote shape ({url, headers}), matching
// claude_desktop_config.json and .mcp.json.
type serverEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Type    string            `json:"type"`
	Headers map[string]string `json:"headers"`
}

type configFile struct {
	MCPServers map[string]serverEntry `json:"mcpServers"`
	Servers    map[string]serverEntry `json:"servers"` // some tools use this key
}

// FromConfig reads an MCP config file and resolves every server it declares.
// This is the flow people use daily: point it at the config you already have.
func FromConfig(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cf configFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	entries := cf.MCPServers
	if len(entries) == 0 {
		entries = cf.Servers
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no servers found in %s (expected an \"mcpServers\" object)", path)
	}
	out := make([]Target, 0, len(entries))
	for name, e := range entries {
		t, err := entryToTarget(name, e)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", name, err)
		}
		out = append(out, t)
	}
	return out, nil
}

func entryToTarget(name string, e serverEntry) (Target, error) {
	if e.URL != "" {
		return Target{Raw: e.URL, Kind: KindRemote, Name: name, URL: e.URL, Headers: e.Headers}, nil
	}
	if e.Command == "" {
		return Target{}, fmt.Errorf("entry has neither \"command\" nor \"url\"")
	}
	argv := append([]string{e.Command}, e.Args...)
	kind := KindLocal
	pkg := ""
	// Recognize npx/uvx launchers so supply-chain + prepare treat them right.
	switch e.Command {
	case "npx":
		kind, pkg = KindNPX, lastPackageArg(e.Args)
	case "uvx":
		kind, pkg = KindUVX, lastPackageArg(e.Args)
	}
	return Target{Raw: strings.Join(argv, " "), Kind: kind, Name: name,
		Command: argv, Env: envSlice(e.Env), Package: pkg}, nil
}

// lastPackageArg returns the package spec from npx/uvx args, skipping flags.
func lastPackageArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func envSlice(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}
