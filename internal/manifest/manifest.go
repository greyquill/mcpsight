// Package manifest defines the canonical manifest: a normalized,
// deterministically-serialized view of everything an MCP server exposes
// (tools, resources, prompts). Everything downstream — analyzers, scoring,
// drift detection — operates on this type. Because we hash it to detect
// rug-pulls, canonicalization (key ordering, whitespace, Unicode) is load
// bearing; see canonical.go.
package manifest

import "encoding/json"

// SchemaVersion is the manifest format version. Bump when the shape of the
// canonical document changes in a way that would alter hashes across releases.
const SchemaVersion = "1"

// Manifest is the canonical, hashable description of an MCP server's surface.
//
// Fields that vary run-to-run without reflecting a real change in the server
// (capture time, scan duration) deliberately live OUTSIDE this struct so they
// never perturb the hash. Only what the server actually exposes belongs here.
type Manifest struct {
	SchemaVersion string     `json:"schema_version"`
	Server        ServerInfo `json:"server"`
	Tools         []Tool     `json:"tools"`
	Resources     []Resource `json:"resources"`
	Prompts       []Prompt   `json:"prompts"`
}

// ServerInfo is the identity the server reports during initialize.
type ServerInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ProtocolVersion string `json:"protocol_version"`
}

// Tool is one entry from tools/list. InputSchema is stored canonicalized so
// two servers that report the same schema with different key ordering hash
// identically.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// Resource is one entry from resources/list.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MIMEType    string `json:"mime_type,omitempty"`
}

// Prompt is one entry from prompts/list.
type Prompt struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// New returns an empty manifest with the current schema version set.
func New() *Manifest {
	return &Manifest{SchemaVersion: SchemaVersion}
}
