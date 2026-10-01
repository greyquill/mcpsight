package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"golang.org/x/text/unicode/norm"
)

// Canonical returns the deterministic byte serialization of the manifest.
//
// Determinism is achieved by: (1) NFC-normalizing every string so visually
// identical text hashes identically; (2) sorting the tool/resource/prompt
// lists by a stable key so server-side ordering is irrelevant; (3) re-encoding
// each embedded input schema with sorted object keys; (4) a fixed struct field
// order with HTML escaping disabled so the same manifest always yields the same
// bytes. Two runs of the same server MUST produce identical output here, or
// drift detection reports phantom changes.
func (m *Manifest) Canonical() ([]byte, error) {
	c := m.canonicalCopy()
	return marshalDeterministic(c)
}

// Hash returns the hex-encoded SHA-256 of the canonical serialization. This is
// the manifest identity used for baselines and rug-pull detection.
func (m *Manifest) Hash() (string, error) {
	b, err := m.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalCopy returns a normalized, sorted copy safe to serialize.
func (m *Manifest) canonicalCopy() *Manifest {
	c := &Manifest{
		SchemaVersion: nfc(m.SchemaVersion),
		Server: ServerInfo{
			Name:            nfc(m.Server.Name),
			Version:         nfc(m.Server.Version),
			ProtocolVersion: nfc(m.Server.ProtocolVersion),
		},
		Tools:     make([]Tool, len(m.Tools)),
		Resources: make([]Resource, len(m.Resources)),
		Prompts:   make([]Prompt, len(m.Prompts)),
	}
	for i, t := range m.Tools {
		c.Tools[i] = Tool{
			Name:        nfc(t.Name),
			Description: nfc(t.Description),
			InputSchema: canonicalRaw(t.InputSchema),
		}
	}
	for i, r := range m.Resources {
		c.Resources[i] = Resource{
			URI:         nfc(r.URI),
			Name:        nfc(r.Name),
			Description: nfc(r.Description),
			MIMEType:    nfc(r.MIMEType),
		}
	}
	for i, p := range m.Prompts {
		c.Prompts[i] = Prompt{Name: nfc(p.Name), Description: nfc(p.Description)}
	}
	sort.Slice(c.Tools, func(i, j int) bool { return c.Tools[i].Name < c.Tools[j].Name })
	sort.Slice(c.Resources, func(i, j int) bool {
		if c.Resources[i].URI != c.Resources[j].URI {
			return c.Resources[i].URI < c.Resources[j].URI
		}
		return c.Resources[i].Name < c.Resources[j].Name
	})
	sort.Slice(c.Prompts, func(i, j int) bool { return c.Prompts[i].Name < c.Prompts[j].Name })
	return c
}

// nfc normalizes a string to Unicode NFC. Homoglyph/zero-width detection is the
// injection analyzer's job; here we only fold canonically-equivalent forms so
// they don't register as drift.
func nfc(s string) string { return norm.NFC.String(s) }

// canonicalRaw re-encodes an embedded JSON schema deterministically: object
// keys sorted (json.Marshal sorts map keys), array order preserved (schema
// arrays like "enum" can be semantic), strings NFC-normalized. Invalid or empty
// input is returned unchanged.
func canonicalRaw(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	v = normalizeValue(v)
	b, err := marshalDeterministic(v)
	if err != nil {
		return raw
	}
	return json.RawMessage(b)
}

// normalizeValue recursively NFC-normalizes strings within a decoded JSON value.
// Map keys and string values are both normalized; array order is preserved.
func normalizeValue(v any) any {
	switch t := v.(type) {
	case string:
		return nfc(t)
	case []any:
		for i := range t {
			t[i] = normalizeValue(t[i])
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[nfc(k)] = normalizeValue(val)
		}
		return out
	default:
		return v
	}
}

// marshalDeterministic encodes with sorted map keys (json default) and HTML
// escaping disabled, and trims the trailing newline the encoder appends.
func marshalDeterministic(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
