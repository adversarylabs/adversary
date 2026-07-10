package publock

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

type Lock struct{ file *os.File }

func Acquire(root, key string) (*Lock, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	rooted, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer rooted.Close()
	if err := rooted.MkdirAll(".publication-locks", 0700); err != nil {
		return nil, err
	}
	path := filepath.ToSlash(filepath.Join(".publication-locks", fmt.Sprintf("%x.lock", sha256.Sum256([]byte(key)))))
	f, err := rooted.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if os.IsNotExist(err) {
		if e := rooted.MkdirAll(".publication-locks", 0700); e == nil {
			f, err = rooted.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return &Lock{file: f}, nil
}
func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
