//go:build linux

package initproject

import "golang.org/x/sys/unix"

func publishNoReplace(staging, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}
