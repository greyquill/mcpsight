package mcp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// MaxMessageBytes caps any single message read from a server. Real tool lists
// are kilobytes; the cap only exists so a hostile server cannot make mcpsight
// buffer until the host runs out of memory.
const MaxMessageBytes = 16 << 20

// ErrMessageTooLarge is returned when a server sends a message over the cap.
var ErrMessageTooLarge = fmt.Errorf("server sent a message larger than %d MiB", MaxMessageBytes>>20)

// limitedReader reads at most n bytes, then fails with ErrMessageTooLarge
// instead of the silent EOF that io.LimitReader gives.
type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		// One more byte proves the body is over the cap rather than exactly at it.
		var b [1]byte
		if n, _ := l.r.Read(b[:]); n > 0 {
			return 0, ErrMessageTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// readLine reads one newline-terminated line of at most max bytes.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(line)+len(frag) > max {
			return nil, ErrMessageTooLarge
		}
		line = append(line, frag...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}
