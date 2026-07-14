//go:build !windows

package adversary

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntrap 'exit 0' TERM\nsh -c 'trap \"\" TERM; printf \"ARMED %s\\n\" \"$$\"; sleep 60' &\nprintf 'PID %s\\n' \"$!\"\nwait\n"), 0755); err != nil {
		t.Fatal(err)
	}
	stdoutReader, stdoutWriter := io.Pipe()
	defer stdoutReader.Close()
	defer stdoutWriter.Close()
	type readinessResult struct {
		pid int
		err error
	}
	readiness := make(chan readinessResult, 1)
	go func() {
		reader := bufio.NewReader(stdoutReader)
		publishedPID, armedPID := 0, 0
		for publishedPID == 0 || armedPID == 0 {
			line, err := reader.ReadString('\n')
			if err != nil {
				readiness <- readinessResult{err: fmt.Errorf("read readiness: %w", err)}
				return
			}
			fields := strings.Fields(line)
			if len(fields) != 2 {
				readiness <- readinessResult{err: fmt.Errorf("unexpected readiness line %q", strings.TrimSpace(line))}
				return
			}
			pid, err := strconv.Atoi(fields[1])
			if err != nil {
				readiness <- readinessResult{err: fmt.Errorf("invalid readiness pid %q: %w", fields[1], err)}
				return
			}
			if pid <= 0 {
				readiness <- readinessResult{err: fmt.Errorf("invalid non-positive readiness pid %d", pid)}
				return
			}
			switch fields[0] {
			case "PID":
				if publishedPID != 0 {
					readiness <- readinessResult{err: fmt.Errorf("duplicate PID readiness line")}
					return
				}
				publishedPID = pid
			case "ARMED":
				if armedPID != 0 {
					readiness <- readinessResult{err: fmt.Errorf("duplicate ARMED readiness line")}
					return
				}
				armedPID = pid
			default:
				readiness <- readinessResult{err: fmt.Errorf("unexpected readiness line %q", strings.TrimSpace(line))}
				return
			}
		}
		if publishedPID != armedPID {
			readiness <- readinessResult{err: fmt.Errorf("published descendant pid %d does not match armed pid %d", publishedPID, armedPID)}
			return
		}
		readiness <- readinessResult{pid: armedPID}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := systemHostExecutorForTest(nil, stdoutWriter, nil).Run(ctx, RuntimeSpec{Command: []string{script}, AdversaryPath: dir})
		done <- err
	}()
	var pid int
	select {
	case ready := <-readiness:
		if ready.err != nil {
			t.Fatal(ready.err)
		}
		pid = ready.pid
	case err := <-done:
		t.Fatalf("executor returned before descendant readiness: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("descendant readiness was not reported")
	}
	cancel()
	canceledAt := time.Now()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("executor did not return after cancellation")
	}
	if elapsed := time.Since(canceledAt); elapsed < 700*time.Millisecond || elapsed > 10*time.Second {
		t.Fatalf("executor did not preserve the 750ms process-group grace: %s", elapsed)
	}
	deadline := time.Now().Add(10 * time.Second)
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
