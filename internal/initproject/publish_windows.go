//go:build windows

package initproject

import "golang.org/x/sys/windows"

func publishNoReplace(staging, destination string) error {
	from, err := windows.UTF16PtrFromString(staging)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// Omitting MOVEFILE_REPLACE_EXISTING guarantees failure if destination exists.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
