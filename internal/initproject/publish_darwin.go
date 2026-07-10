//go:build darwin

package initproject

import "golang.org/x/sys/unix"

func publishNoReplace(staging, destination string) error {
	return unix.RenamexNp(staging, destination, unix.RENAME_EXCL)
}
