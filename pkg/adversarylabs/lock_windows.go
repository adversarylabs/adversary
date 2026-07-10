//go:build windows

package adversarylabs

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func readCredentialFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credential path %q is not regular", path)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func withFileLock(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("credential lock %q is not regular", path)
	}
	if err := f.Chmod(0600); err != nil {
		return err
	}
	var ol windows.Overlapped
	h := windows.Handle(f.Fd())
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol); err != nil {
		return err
	}
	defer windows.UnlockFileEx(h, 0, 1, 0, &ol)
	return fn()
}
