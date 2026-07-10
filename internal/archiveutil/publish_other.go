//go:build !darwin

package archiveutil

import "os"

func PublishSealed(_ string, root *os.Root, from, to string) (bool, error) {
	if err := root.Rename(from, to); err != nil {
		return false, err
	}
	return true, nil
}
