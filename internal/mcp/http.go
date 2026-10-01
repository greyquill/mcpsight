package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPTransport speaks JSON-RPC over MCP Streamable HTTP: each message is POSTed
// to a single endpoint, and the server replies with either application/json (a
// single response) or text/event-stream (SSE). It threads the Mcp-Session-Id
// header the server assigns at initialize through subsequent requests.
type HTTPTransport struct {
	endpoint  string
	client    *http.Client
	sessionID string
	headers   map[string]string
	// LastStatus records the HTTP status of the most recent response, which the
	// auth-posture analyzer uses to tell "unauthenticated listing" from "401".
	LastStatus int
	// LastTLSVersion records the negotiated TLS version of the most recent
	// response (0 for plaintext HTTP), for the auth-posture analyzer.
	LastTLSVersion uint16
}

// NewHTTPTransport builds a transport for a remote MCP endpoint. Extra headers
// (e.g. Authorization) may be nil.
func NewHTTPTransport(endpoint string, client *http.Client, headers map[string]string) *HTTPTransport {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPTransport{endpoint: endpoint, client: client, headers: headers}
}

func (h *HTTPTransport) post(ctx context.Context, payload any) (*http.Response, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if h.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", h.sessionID)
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return h.client.Do(req)
}

// Roundtrip POSTs a request and returns the matching response, decoding either a
// plain JSON body or an SSE stream.
func (h *HTTPTransport) Roundtrip(ctx context.Context, req *Request) (*Response, error) {
	resp, err := h.post(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	h.LastStatus = resp.StatusCode
	if resp.TLS != nil {
		h.LastTLSVersion = resp.TLS.Version
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		h.sessionID = sid
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		return readSSEResponse(resp.Body, req.ID, MaxMessageBytes)
	}
	var out Response
	if err := json.NewDecoder(&limitedReader{r: resp.Body, n: MaxMessageBytes}).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding json response: %w", err)
	}
	return &out, nil
}

// Notify POSTs a notification; a 2xx (typically 202 Accepted) is success.
func (h *HTTPTransport) Notify(ctx context.Context, method string, params any) error {
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	resp, err := h.post(ctx, msg)
	if err != nil {
		return err
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		h.sessionID = sid
	}
	resp.Body.Close()
	return nil
}

func (h *HTTPTransport) Close() error { return nil }

// readSSEResponse scans an SSE stream for the first data event carrying a
// JSON-RPC response with the matching id.
func readSSEResponse(r io.Reader, id int, max int) (*Response, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), max)
	var data strings.Builder
	flush := func() (*Response, bool) {
		defer data.Reset()
		if data.Len() == 0 {
			return nil, false
		}
		var resp Response
		if err := json.Unmarshal([]byte(data.String()), &resp); err != nil {
			return nil, false
		}
		if resp.ID == nil {
			return nil, false
		}
		if n, err := resp.ID.Int64(); err == nil && int(n) == id {
			return &resp, true
		}
		return nil, false
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "": // event boundary
			if resp, ok := flush(); ok {
				return resp, nil
			}
		case strings.HasPrefix(line, "data:"):
			chunk := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
			// An event whose data lines never end would otherwise grow forever.
			if data.Len()+len(chunk) > max {
				return nil, ErrMessageTooLarge
			}
			data.WriteString(chunk)
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, ErrMessageTooLarge
		}
		return nil, err
	}
	if resp, ok := flush(); ok {
		return resp, nil
	}
	return nil, fmt.Errorf("no matching response in event stream")
}
