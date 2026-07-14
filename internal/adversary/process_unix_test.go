//go:build !windows

package adversary

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHostExecutorKillsTermIgnoringDescendantAfterLeaderExits(t *testing.T) {
	dir := realTempDir(t)
	pidFile := filepath.Join(dir, "child.pid")
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntrap 'exit 0' TERM\nsh -c 'trap \"\" TERM; sleep 60' &\necho $! > \"$1\"\nwait\n"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := systemHostExecutorForTest(nil, nil, nil).Run(ctx, RuntimeSpec{Command: []string{script, pidFile}, AdversaryPath: dir})
		done <- err
	}()
	var data []byte
	deadline := time.Now().Add(2 * time.Second)
	for len(data) == 0 && time.Now().Before(deadline) {
		data, _ = os.ReadFile(pidFile)
		time.Sleep(10 * time.Millisecond)
	}
	if len(data) == 0 {
		cancel()
		t.Fatal("descendant pid was not published")
	}
	cancel()
	canceledAt := time.Now()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(canceledAt); elapsed < 700*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("executor did not preserve the 750ms process-group grace: %s", elapsed)
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if convErr != nil {
		t.Fatal(convErr)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant %d remains after cancellation", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHostExecutorPreservesChildExitCode(t *testing.T) {
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	executor := systemHostExecutorForTest(nil, nil, nil)
	if shell != "/bin/sh" {
		if _, aliasErr := executor.Run(context.Background(), RuntimeSpec{Command: []string{"/bin/sh", "-c", "exit 0"}, AdversaryPath: t.TempDir()}); aliasErr == nil || !strings.Contains(aliasErr.Error(), "symlink component") {
			t.Fatalf("strict explicit-path policy accepted /bin/sh alias: %v", aliasErr)
		}
	}
	_, err = executor.Run(context.Background(), RuntimeSpec{Command: []string{shell, "-c", "exit 42"}, AdversaryPath: t.TempDir()})
	var processErr *ChildExitError
	if !errors.As(err, &processErr) || processErr.ExitCode != 42 {
		t.Fatalf("error = %#v", err)
	}
}
