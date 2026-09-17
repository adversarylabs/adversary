//go:build windows

package modelreview

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
)

func tryCodexLock(f *os.File) (bool, error) {
	var o windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &o)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return err == nil, err
}
func unlockCodex(f *os.File) {
	var o windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &o)
}

// Codex tools are disabled; Windows cancellation terminates the direct child.
func configureCodexProcess(cmd *exec.Cmd) {}
