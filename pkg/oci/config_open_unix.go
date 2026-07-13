//go:build !windows

package oci

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

func OpenRegularNoFollow(path string) (io.ReadCloser, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("file is not regular")
	}
	return file, nil
}
