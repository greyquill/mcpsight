package sandbox

import (
	"context"
	"fmt"
)

// Direct runs a command with NO isolation. It exists only for --no-sandbox and
// must never be selected by default; the CLI prints a red warning when it is.
type Direct struct{}

func (*Direct) Name() string { return "none (unsandboxed)" }

// Available is always true — but see the type doc: this is the unsafe path.
func (*Direct) Available() (bool, string) { return true, "" }

func (*Direct) Start(ctx context.Context, spec Spec) (*Session, error) {
	if len(spec.Command) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	sess, err := startProcess(ctx, spec, spec.Command[0], spec.Command[1:], func() {}, nil)
	if err != nil {
		return nil, err
	}
	if spec.Trace {
		sess.traceSkipped = "--no-sandbox runs are not observed"
	}
	return sess, nil
}
