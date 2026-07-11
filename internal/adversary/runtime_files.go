package adversary

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// RuntimeFiles is the filesystem edge used while resolving and executing an
// adversary. OSRuntimeFiles is composed by the command package; tests may use a
// narrow fake or override individual lifecycle functions on Runner.
type RuntimeFiles interface {
	Abs(string) (string, error)
	EvalSymlinks(string) (string, error)
	Stat(string) (fs.FileInfo, error)
	WriteFile(string, []byte, fs.FileMode) error
	Open(string) (io.ReadCloser, error)
	Glob(string) ([]string, error)
	ReadDir(string) ([]fs.DirEntry, error)
	MkdirTemp(string, string) (string, error)
	RemoveAll(string) error
}

type OSRuntimeFiles struct{}

func (OSRuntimeFiles) Abs(path string) (string, error)          { return filepath.Abs(path) }
func (OSRuntimeFiles) EvalSymlinks(path string) (string, error) { return filepath.EvalSymlinks(path) }
func (OSRuntimeFiles) Stat(path string) (fs.FileInfo, error)    { return os.Stat(path) }
func (OSRuntimeFiles) WriteFile(path string, data []byte, mode fs.FileMode) error {
	return os.WriteFile(path, data, mode)
}
func (OSRuntimeFiles) Open(path string) (io.ReadCloser, error)    { return os.Open(path) }
func (OSRuntimeFiles) Glob(pattern string) ([]string, error)      { return filepath.Glob(pattern) }
func (OSRuntimeFiles) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }
func (OSRuntimeFiles) MkdirTemp(dir, pattern string) (string, error) {
	return os.MkdirTemp(dir, pattern)
}
func (OSRuntimeFiles) RemoveAll(path string) error { return os.RemoveAll(path) }
