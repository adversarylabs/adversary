//go:build windows

package adversary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateExecutableUsesPATHEXT(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATHEXT", ".EXE;.CMD")
	exe := filepath.Join(root, "node.exe")
	if err := os.WriteFile(exe, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutable(exe); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(root, "node.txt")
	if err := os.WriteFile(plain, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutable(plain); err == nil || !strings.Contains(err.Error(), "PATHEXT") {
		t.Fatalf("error = %v", err)
	}
}
