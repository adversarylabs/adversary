package adversary

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestConfirmUntrustedHostExecutionYesNo(t *testing.T) {
	var stderr strings.Builder
	ok, err := confirmUntrustedHostExecution(context.Background(), strings.NewReader("yes\n"), &stderr, "lang/typescript", "sha256:abc")
	if err != nil || !ok {
		t.Fatalf("yes: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(stderr.String(), "Untrusted adversary") {
		t.Fatalf("prompt missing: %q", stderr.String())
	}

	ok, err = confirmUntrustedHostExecution(context.Background(), strings.NewReader("n\n"), io.Discard, "x", "")
	if err != nil || ok {
		t.Fatalf("n: ok=%v err=%v", ok, err)
	}
}

func TestConfirmUntrustedHostExecutionRespectsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Never write to stdin; cancel while blocked on read.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	// Pipe with no data keeps ReadString blocked until cancel.
	r, w := io.Pipe()
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })

	ok, err := confirmUntrustedHostExecution(ctx, r, io.Discard, "pkg", "sha256:x")
	if ok {
		t.Fatal("expected false on cancel")
	}
	if err == nil || !errorsIsCancel(err) {
		t.Fatalf("expected context cancel, got %v", err)
	}
}

func errorsIsCancel(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}
