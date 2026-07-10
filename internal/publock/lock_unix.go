//go:build !windows

package publock

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockFile(f *os.File) error   { return unix.Flock(int(f.Fd()), unix.LOCK_EX) }
func unlockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
