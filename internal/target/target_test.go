package target

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalRedactsSecrets(t *testing.T) {
	tgt := Target{
		Name:    "db",
		Env:     []string{"API_TOKEN=s3cret", "MODE=ro"},
		Headers: map[string]string{"Authorization": "Bearer s3cret"},
	}
	b, err := json.Marshal(tgt)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if strings.Contains(out, "s3cret") {
		t.Errorf("secret leaked into JSON: %s", out)
	}
	for _, want := range []string{"API_TOKEN=[redacted]", `"Authorization":"[redacted]"`} {
		if !strings.Contains(out, want) {
			t.Errorf("want %s in %s", want, out)
		}
	}
	if tgt.Env[0] != "API_TOKEN=s3cret" {
		t.Error("marshaling must not modify the target itself")
	}
}
