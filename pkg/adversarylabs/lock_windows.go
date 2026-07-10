//go:build windows

package adversarylabs

import (
	"golang.org/x/sys/windows"
	"os"
)

func withFileLock(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	var ol windows.Overlapped
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol); err != nil {
		return err
	}
	defer windows.UnlockFileEx(h, 0, 1, 0, &ol)
	return fn()
}
