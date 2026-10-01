package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Request is a JSON-RPC 2.0 request. ID is an int for our client; MCP permits
// string or number ids, and we only ever match our own.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response. Notifications sent by the server (no id)
// are recognized by ID == nil and skipped by the stdio transport.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *json.Number    `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ErrorObject    `json:"error,omitempty"`
	Method  string          `json:"method,omitempty"` // present on inbound notifications
}

// ErrorObject is the JSON-RPC error payload.
type ErrorObject struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// RPCError is a server-returned error surfaced to callers. Method-not-found
// (-32601) is treated as "unsupported" by tolerant callers.
type RPCError struct {
	Method  string
	Code    int
	Message string
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("%s: rpc error %d: %s", e.Method, e.Code, e.Message)
}

// MethodNotFound reports whether an error is a JSON-RPC method-not-found.
func MethodNotFound(err error) bool {
	var re *RPCError
	if errors.As(err, &re) {
		return re.Code == -32601
	}
	return false
}
