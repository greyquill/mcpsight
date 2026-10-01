package sandbox

import (
	"os"
	"path/filepath"
	"sync"
)

// decoyFiles are fake secrets seeded into the sandbox home. Any read of one is
// the credential-exfil trap described in the threat model. The contents are
// obviously-fake so that if a server DOES exfiltrate one, no real secret leaks.
var decoyFiles = map[string]string{
	".ssh/id_rsa":               "-----BEGIN OPENSSH PRIVATE KEY-----\nDECOY-mcpsight-DO-NOT-USE\n-----END OPENSSH PRIVATE KEY-----\n",
	".aws/credentials":          "[default]\naws_access_key_id = AKIAMCPSIGHTDECOY000\naws_secret_access_key = 0000000000000000000000000000000000decoy0\n",
	".config/gcloud/creds.json": "{\"type\":\"service_account\",\"private_key\":\"DECOY\"}\n",
	".env":                      "OPENAI_API_KEY=sk-decoy00000000000000000000000000000000000000\nDATABASE_URL=postgres://decoy:decoy@localhost/decoy\n",
}

// DecoyRelPaths returns the decoy files' paths relative to home, so a trace
// analyzer knows which reads are exfil attempts.
func DecoyRelPaths() []string {
	paths := make([]string, 0, len(decoyFiles))
	for p := range decoyFiles {
		paths = append(paths, p)
	}
	return paths
}

func seedDecoys(home string) error {
	for rel, body := range decoyFiles {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// capBuffer is a byte buffer that stops growing past limit, so a chatty or
// hostile process cannot exhaust memory through stderr.
type capBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.limit - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	return len(p), nil // always report full write; we intentionally drop overflow
}

func (c *capBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}
