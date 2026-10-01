// Package mcp is a minimal MCP client: it completes the initialize handshake and
// introspects a server (tools/list, resources/list, prompts/list) over a
// pluggable transport (stdio or Streamable HTTP). It issues requests only; it
// is not a full bidirectional MCP implementation.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/greyquill/mcpsight/internal/manifest"
)

// ProtocolVersion is the MCP revision we advertise during initialize.
const ProtocolVersion = "2025-06-18"

// Transport carries JSON-RPC messages to a server. Roundtrip sends a request
// and returns the matching response; Notify sends a fire-and-forget
// notification. Implementations must respect context cancellation.
type Transport interface {
	Roundtrip(ctx context.Context, req *Request) (*Response, error)
	Notify(ctx context.Context, method string, params any) error
	Close() error
}

// Client drives the introspection sequence over a Transport.
type Client struct {
	t      Transport
	nextID int
}

// NewClient wraps a transport.
func NewClient(t Transport) *Client { return &Client{t: t, nextID: 1} }

// Close releases the transport.
func (c *Client) Close() error { return c.t.Close() }

func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	id := c.nextID
	c.nextID++
	req := &Request{JSONRPC: "2.0", ID: id, Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = b
	}
	resp, err := c.t.Roundtrip(ctx, req)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if resp.Error != nil {
		return &RPCError{Method: method, Code: resp.Error.Code, Message: resp.Error.Message}
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("%s: decoding result: %w", method, err)
		}
	}
	return nil
}

// Initialize completes the MCP handshake and returns the server's identity.
func (c *Client) Initialize(ctx context.Context) (manifest.ServerInfo, error) {
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	params := map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcpsight", "version": "0"},
	}
	if err := c.call(ctx, "initialize", params, &res); err != nil {
		return manifest.ServerInfo{}, err
	}
	// Per spec, the client acknowledges initialization. Best-effort.
	_ = c.t.Notify(ctx, "notifications/initialized", nil)
	return manifest.ServerInfo{
		Name:            res.ServerInfo.Name,
		Version:         res.ServerInfo.Version,
		ProtocolVersion: res.ProtocolVersion,
	}, nil
}

// Introspect performs the full read-only introspection into a manifest. A
// server that does not implement resources/list or prompts/list (method not
// found) simply yields none — that is not an error.
func (c *Client) Introspect(ctx context.Context) (*manifest.Manifest, error) {
	m := manifest.New()
	info, err := c.Initialize(ctx)
	if err != nil {
		return nil, err
	}
	m.Server = info

	tools, err := c.listTools(ctx)
	if err != nil {
		return nil, err // tools/list failing is a real probe failure
	}
	m.Tools = tools
	m.Resources = c.listResourcesTolerant(ctx)
	m.Prompts = c.listPromptsTolerant(ctx)
	return m, nil
}

func (c *Client) listTools(ctx context.Context) ([]manifest.Tool, error) {
	var res struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := c.call(ctx, "tools/list", map[string]any{}, &res); err != nil {
		return nil, err
	}
	out := make([]manifest.Tool, 0, len(res.Tools))
	for _, t := range res.Tools {
		out = append(out, manifest.Tool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return out, nil
}

func (c *Client) listResourcesTolerant(ctx context.Context) []manifest.Resource {
	var res struct {
		Resources []struct {
			URI         string `json:"uri"`
			Name        string `json:"name"`
			Description string `json:"description"`
			MIMEType    string `json:"mimeType"`
		} `json:"resources"`
	}
	if err := c.call(ctx, "resources/list", map[string]any{}, &res); err != nil {
		return nil
	}
	out := make([]manifest.Resource, 0, len(res.Resources))
	for _, r := range res.Resources {
		out = append(out, manifest.Resource{URI: r.URI, Name: r.Name, Description: r.Description, MIMEType: r.MIMEType})
	}
	return out
}

func (c *Client) listPromptsTolerant(ctx context.Context) []manifest.Prompt {
	var res struct {
		Prompts []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"prompts"`
	}
	if err := c.call(ctx, "prompts/list", map[string]any{}, &res); err != nil {
		return nil
	}
	out := make([]manifest.Prompt, 0, len(res.Prompts))
	for _, p := range res.Prompts {
		out = append(out, manifest.Prompt{Name: p.Name, Description: p.Description})
	}
	return out
}
