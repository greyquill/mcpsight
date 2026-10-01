package sandbox

import (
	"context"
	"os/exec"
	"testing"
)

func TestDirectReportsTraceSkipped(t *testing.T) {
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not available")
	}
	for _, trace := range []bool{true, false} {
		sess, err := (&Direct{}).Start(context.Background(), Spec{Command: []string{cat}, Trace: trace})
		if err != nil {
			t.Fatal(err)
		}
		sess.Close()
		if got := sess.TraceSkipped() != ""; got != trace {
			t.Errorf("Trace=%v: TraceSkipped()=%q", trace, sess.TraceSkipped())
		}
	}
}
