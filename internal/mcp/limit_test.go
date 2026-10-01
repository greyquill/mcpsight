package mcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// endless never stops producing the byte c, like a server that never ends a line.
type endless byte

func (e endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(e)
	}
	return len(p), nil
}

func TestReadLineCapsAnEndlessLine(t *testing.T) {
	br := bufio.NewReaderSize(endless('a'), 4096)
	if _, err := readLine(br, 64<<10); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}

func TestReadLineKeepsANormalLine(t *testing.T) {
	long := strings.Repeat("x", 10000) // longer than the 4 KiB buffer, under the cap
	br := bufio.NewReaderSize(strings.NewReader(long+"\nnext\n"), 4096)
	line, err := readLine(br, 64<<10)
	if err != nil || string(line) != long+"\n" {
		t.Fatalf("got %d bytes, err %v", len(line), err)
	}
}

func TestStdioRoundtripRejectsOversizedLine(t *testing.T) {
	tr := NewStdioTransport(nopWriteCloser{io.Discard}, endless('a'))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := tr.Roundtrip(ctx, &Request{JSONRPC: "2.0", ID: 1, Method: "tools/list"}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}

func TestHTTPJSONBodyIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"pad":"`)
		io.CopyN(w, endless('a'), MaxMessageBytes+1024)
	}))
	defer srv.Close()
	tr := NewHTTPTransport(srv.URL, srv.Client(), nil)
	_, err := tr.Roundtrip(context.Background(), &Request{JSONRPC: "2.0", ID: 1, Method: "tools/list"})
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}

func TestSSEDataIsCapped(t *testing.T) {
	// Many short data lines and no blank line to end the event.
	stream := strings.Repeat("data: aaaaaaaaaaaaaaaa\n", 10000)
	if _, err := readSSEResponse(strings.NewReader(stream), 1, 64<<10); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}

func TestSSEStillFindsANormalResponse(t *testing.T) {
	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	resp, err := readSSEResponse(strings.NewReader(stream), 1, 64<<10)
	if err != nil || resp == nil {
		t.Fatalf("got %v, %v", resp, err)
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
