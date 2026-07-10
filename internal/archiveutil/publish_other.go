//go:build !darwin

package archiveutil

import "os"

func PublishSealed(_ string, root *os.Root, from, to string) (bool, error) {
	if err := root.Rename(from, to); err != nil {
		return false, err
	}
	dest, err := root.OpenRoot(to)
	if err != nil {
		return true, err
	}
	sealErr := dest.Chmod(".", 0555)
	if sealErr == nil {
		sealErr = ValidateSealed(dest)
	}
	closeErr := dest.Close()
	if sealErr != nil {
		return true, sealErr
	}
	if closeErr != nil {
		return true, closeErr
	}
	return true, nil
}
