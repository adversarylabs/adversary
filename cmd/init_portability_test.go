package cmd

import (
	"errors"
	"io/fs"
	"os"
	"reflect"
	"testing"
	"time"
)

type discoveryFileInfo struct{ directory bool }

func (discoveryFileInfo) Name() string       { return "candidate" }
func (discoveryFileInfo) Size() int64        { return 1 }
func (discoveryFileInfo) Mode() fs.FileMode  { return 0755 }
func (discoveryFileInfo) ModTime() time.Time { return time.Time{} }
func (i discoveryFileInfo) IsDir() bool      { return i.directory }
func (discoveryFileInfo) Sys() any           { return nil }

func TestCapturedNPMKeepsPATHFirst(t *testing.T) {
	want := `/captured/bin/npm`
	got, err := capturedNPM("windows", `C:\Users\Ada`, func(string) (string, bool) {
		t.Fatal("captured environment consulted after PATH success")
		return "", false
	}, func(name string) (string, error) {
		if name != "npm" {
			t.Fatalf("LookPath(%q)", name)
		}
		return want, nil
	}, func(string) (fs.FileInfo, error) {
		t.Fatal("filesystem consulted after PATH success")
		return nil, nil
	}, func(string) ([]string, error) {
		t.Fatal("glob consulted after PATH success")
		return nil, nil
	}, func(string) (string, error) {
		t.Fatal("explicit resolver consulted after PATH success")
		return "", nil
	})
	if err != nil || got != want {
		t.Fatalf("capturedNPM() = %q, %v; want %q", got, err, want)
	}
}

func TestCapturedNPMWindowsConventionalOrderAndResolverFallback(t *testing.T) {
	t.Setenv("ProgramFiles", `C:\ambient-must-not-be-read`)
	env := map[string]string{
		"ProgramFiles": `C:\Program Files`,
		"LOCALAPPDATA": `C:\Users\Ada\AppData\Local`,
		"APPDATA":      `C:\Users\Ada\AppData\Roaming`,
	}
	fnm22 := `C:\Users\Ada\AppData\Roaming\fnm\node-versions\v22\installation\npm.cmd`
	fnm20 := `C:\Users\Ada\AppData\Roaming\fnm\node-versions\v20\installation\npm.cmd`
	want := `C:\Users\Ada\AppData\Roaming\npm\npm.cmd`
	var visited []string
	got, err := capturedNPM("windows", `C:\Users\Ada`, func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}, func(string) (string, error) { return "", errors.New("not on captured PATH") }, func(path string) (fs.FileInfo, error) {
		visited = append(visited, path)
		return discoveryFileInfo{}, nil
	}, func(pattern string) ([]string, error) {
		wantPattern := `C:\Users\Ada\AppData\Roaming\fnm\node-versions\v*\installation\npm.cmd`
		if pattern != wantPattern {
			t.Fatalf("Glob(%q), want %q", pattern, wantPattern)
		}
		return []string{fnm20, fnm22}, nil
	}, func(path string) (string, error) {
		if path == want {
			return path, nil
		}
		return "", errors.New("unsafe or unresolvable")
	})
	if err != nil || got != want {
		t.Fatalf("capturedNPM() = %q, %v; want %q", got, err, want)
	}
	wantOrder := []string{
		`C:\Program Files\nodejs\npm.cmd`,
		`C:\Users\Ada\AppData\Local\Volta\bin\npm.cmd`,
		fnm22,
		fnm20,
		want,
	}
	if !reflect.DeepEqual(visited, wantOrder) {
		t.Fatalf("candidate order = %#v, want %#v", visited, wantOrder)
	}
}

func TestCapturedNPMRetainsUnixNVMThenVoltaOrder(t *testing.T) {
	want := "/home/ada/.nvm/versions/node/v22/bin/npm"
	var visited []string
	got, err := capturedNPM("linux", "/home/ada", func(string) (string, bool) { return "", false }, func(string) (string, error) {
		return "", os.ErrNotExist
	}, func(path string) (fs.FileInfo, error) {
		visited = append(visited, path)
		return discoveryFileInfo{}, nil
	}, func(string) ([]string, error) {
		return []string{"/home/ada/.nvm/versions/node/v20/bin/npm", want}, nil
	}, func(path string) (string, error) { return path, nil })
	if err != nil || got != want {
		t.Fatalf("capturedNPM() = %q, %v; want %q", got, err, want)
	}
	if len(visited) != 1 || visited[0] != want {
		t.Fatalf("visited = %#v", visited)
	}
}

func TestCapturedNodeUsesWindowsAdjacentNodeEXE(t *testing.T) {
	want := `C:\Program Files\nodejs\node.exe`
	got, err := capturedNode("windows", `C:\Program Files\nodejs\npm.cmd`, func(string) (string, error) {
		t.Fatal("PATH fallback used despite adjacent node.exe")
		return "", nil
	}, func(path string) (fs.FileInfo, error) {
		if path != want {
			t.Fatalf("Stat(%q), want %q", path, want)
		}
		return discoveryFileInfo{}, nil
	}, func(path string) (string, error) { return path, nil })
	if err != nil || got != want {
		t.Fatalf("capturedNode() = %q, %v; want %q", got, err, want)
	}
}

func TestCapturedNodeFallsBackAfterUnsafeAdjacentCandidate(t *testing.T) {
	want := `C:\captured\node.exe`
	got, err := capturedNode("windows", `C:\tools\npm.cmd`, func(name string) (string, error) {
		if name != "node" {
			t.Fatalf("LookPath(%q)", name)
		}
		return want, nil
	}, func(string) (fs.FileInfo, error) { return discoveryFileInfo{}, nil }, func(string) (string, error) {
		return "", errors.New("symlink or unsafe path")
	})
	if err != nil || got != want {
		t.Fatalf("capturedNode() = %q, %v; want %q", got, err, want)
	}
}
