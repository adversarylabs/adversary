//go:build !windows

package oci

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func dockerStoreForHome(home string) DockerCredentialStore {
	return DockerCredentialStore{HomeDir: home, Lstat: os.Lstat, Open: func(path string) (io.ReadCloser, error) { return os.Open(path) }}
}

func TestDockerConfigRejectsSymlinkAndFIFOWithoutOpening(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".docker")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.json")
			if kind == "symlink" {
				target := filepath.Join(home, "target")
				if err := os.WriteFile(target, []byte(`{"auths":{}}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			opened := false
			store := dockerStoreForHome(home)
			store.Open = func(string) (io.ReadCloser, error) { opened = true; return nil, errors.New("must not open") }
			if _, ok := store.Credentials("registry.example"); ok || opened {
				t.Fatalf("ok=%v opened=%v", ok, opened)
			}
		})
	}
}

type closeErrorFile struct {
	*os.File
	err error
}

func (f closeErrorFile) Close() error { _ = f.File.Close(); return f.err }

func TestDockerConfigReadJoinsCloseError(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".docker")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"auths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("close fixture")
	store := dockerStoreForHome(home)
	store.Open = func(path string) (io.ReadCloser, error) { f, err := os.Open(path); return closeErrorFile{f, want}, err }
	_, err := store.readConfig()
	if !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
}
