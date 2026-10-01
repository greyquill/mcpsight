package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
)

// StdioTransport speaks newline-delimited JSON-RPC over a process's stdio, the
// MCP stdio transport. The process is owned by the caller (the sandbox runner);
// this type only reads and writes. Context cancellation is expected to be wired
// to killing the process, which closes the pipes and unblocks reads.
type StdioTransport struct {
	w  io.WriteCloser
	br *bufio.Reader
	mu sync.Mutex
}

// NewStdioTransport builds a transport over an already-started process's stdin
// (w) and stdout (r).
func NewStdioTransport(w io.WriteCloser, r io.Reader) *StdioTransport {
	return &StdioTransport{w: w, br: bufio.NewReaderSize(r, 1<<20)}
}

func (s *StdioTransport) writeMessage(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = s.w.Write(b)
	return err
}

// Roundtrip writes the request and reads lines until it sees the response whose
// id matches, skipping any server-initiated notifications or unrelated ids that
// arrive on stdout in the meantime.
func (s *StdioTransport) Roundtrip(ctx context.Context, req *Request) (*Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeMessage(req); err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, err := readLine(s.br, MaxMessageBytes)
		if err != nil {
			return nil, err
		}
		if len(line) == 0 {
			continue
		}
		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			continue // ignore non-JSON noise on stdout
		}
		if resp.ID == nil {
			continue // a notification from the server; not our answer
		}
		if id, err := resp.ID.Int64(); err == nil && int(id) == req.ID {
			return &resp, nil
		}
	}
}

// Notify writes a notification (no id, no response expected).
func (s *StdioTransport) Notify(_ context.Context, method string, params any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		msg["params"] = params
	}
	return s.writeMessage(msg)
}

// Close closes the write side; the process lifecycle is the runner's job.
func (s *StdioTransport) Close() error { return s.w.Close() }
