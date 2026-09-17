//go:build !windows

package publock

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockFile(f *os.File, shared bool) error {
	mode := unix.LOCK_EX
	if shared {
		mode = unix.LOCK_SH
	}
	return unix.Flock(int(f.Fd()), mode)
}
func unlockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
