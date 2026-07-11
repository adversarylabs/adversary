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
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntrap 'exit 0' TERM\nsh -c 'trap \"\" TERM; sleep 60' &\necho $! > \"$1\"\nwait\n"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (HostExecutor{}).Run(ctx, ContainerSpec{Command: []string{script, pidFile}, AdversaryPath: dir})
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
	if elapsed := time.Since(canceledAt); elapsed < 700*time.Millisecond {
		t.Fatalf("executor returned before descendant grace elapsed: %s", elapsed)
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
	_, err := (HostExecutor{}).Run(context.Background(), ContainerSpec{Command: []string{"/bin/sh", "-c", "exit 42"}, AdversaryPath: t.TempDir()})
	var processErr *ChildExitError
	if !errors.As(err, &processErr) || processErr.ExitCode != 42 {
		t.Fatalf("error = %#v", err)
	}
}
