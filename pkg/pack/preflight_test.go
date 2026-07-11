package pack

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/manifest"
)

func TestCheckReturnsSortedInventoryAndPathOnlyWarnings(t *testing.T) {
	dir := testProject(t)
	for name, content := range map[string]string{
		"z.txt":                    "z",
		"secrets/credentials.json": "do-not-read-as-a-secret",
		"keys/host.pem":            "not inspected",
		"credentials-example.json": "safe boundary",
		"environment.ts":           "safe boundary",
		"public-key.txt":           "safe boundary",
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Check(Options{Dir: dir, Builder: "local"})
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, len(got.Files))
	for i := range got.Files {
		paths[i] = got.Files[i].Path
	}
	wantWarnings := []string{"keys/host.pem", "secrets/credentials.json"}
	var warningPaths []string
	for _, warning := range got.Warnings {
		warningPaths = append(warningPaths, warning.Path)
	}
	if !reflect.DeepEqual(warningPaths, wantWarnings) {
		t.Fatalf("warnings=%v", warningPaths)
	}
	for i := 1; i < len(paths); i++ {
		if paths[i-1] > paths[i] {
			t.Fatalf("inventory not sorted: %v", paths)
		}
	}
}

func TestPathOnlySecretWarningHeuristicAndBoundaries(t *testing.T) {
	files := []File{
		{Path: ".npmrc"}, {Path: "home/.pypirc"}, {Path: ".netrc"},
		{Path: "tls/server.key"}, {Path: ".aws/credentials"}, {Path: ".kube/config"},
		{Path: "gcp/application_default_credentials.json"}, {Path: "azure/azureProfile.json"},
		{Path: "safe/npmrc"}, {Path: "safe/server-key.txt"}, {Path: "safe/kubeconfig.example"},
		{Path: "safe/credentials-example.json"}, {Path: "safe/azureProfile.json.example"},
	}
	got := WarningsForFiles(files)
	var paths []string
	for _, warning := range got {
		paths = append(paths, warning.Path)
	}
	want := []string{".npmrc", "home/.pypirc", ".netrc", "tls/server.key", ".aws/credentials", ".kube/config", "gcp/application_default_credentials.json", "azure/azureProfile.json"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("warning paths=%v want=%v", paths, want)
	}
}

func TestCheckedPackageEntrypointRuntimeRules(t *testing.T) {
	tests := []struct {
		name              string
		runtime           manifest.Runtime
		path              string
		required, wantErr bool
	}{
		{"node relative", manifest.Runtime{Name: "node", Command: []string{"dist/index.js"}}, "dist/index.js", true, false},
		{"process relative", manifest.Runtime{Name: "process", Command: []string{"bin/tool"}}, "bin/tool", true, false},
		{"process bare PATH", manifest.Runtime{Name: "process", Command: []string{"python3"}}, "", false, false},
		{"process escape", manifest.Runtime{Name: "process", Command: []string{"../tool"}}, "", false, true},
		{"process absolute", manifest.Runtime{Name: "process", Command: []string{"/bin/tool"}}, "", false, true},
		{"process Windows absolute", manifest.Runtime{Name: "process", Command: []string{`C:\\bin\\tool`}}, "", false, true},
		{"process nonportable separator", manifest.Runtime{Name: "process", Command: []string{`bin\\tool`}}, "", false, true},
		{"image internal command", manifest.Runtime{Image: "example.invalid/tool@sha256:00", Command: []string{"/inside/tool"}}, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, required, err := checkedPackageEntrypoint(manifest.Manifest{Runtime: tt.runtime})
			if (err != nil) != tt.wantErr || path != tt.path || required != tt.required {
				t.Fatalf("path=%q required=%v err=%v", path, required, err)
			}
		})
	}
}

func TestCheckRejectsSymlinkSwap(t *testing.T) {
	dir := testProject(t)
	target := filepath.Join(dir, "dist", "index.js")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	beforePackOpen = func(rel string) {
		if rel == "dist/index.js" {
			beforePackOpen = nil
			_ = os.Remove(target)
			_ = os.Symlink(outside, target)
		}
	}
	t.Cleanup(func() { beforePackOpen = nil })
	if _, err := Check(Options{Dir: dir}); err == nil {
		t.Fatal("check accepted symlink swap")
	}
}

type closeErrorFile struct {
	packFile
	err error
}

type readCloseErrorFile struct {
	packFile
	readErr, closeErr error
}

func (f readCloseErrorFile) Read([]byte) (int, error) { return 0, f.readErr }
func (f readCloseErrorFile) Close() error             { return errors.Join(f.packFile.Close(), f.closeErr) }

func (f closeErrorFile) Close() error { return errors.Join(f.packFile.Close(), f.err) }

func TestCheckReportsFileCloseErrors(t *testing.T) {
	dir := testProject(t)
	sentinel := errors.New("injected close failure")
	original := openPackFile
	openPackFile = func(root *os.Root, name string) (packFile, error) {
		f, err := original(root, name)
		if err != nil {
			return nil, err
		}
		return closeErrorFile{packFile: f, err: sentinel}, nil
	}
	t.Cleanup(func() { openPackFile = original })
	_, err := Check(Options{Dir: dir})
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "injected close failure") {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckJoinsReadAndCloseErrors(t *testing.T) {
	dir := testProject(t)
	readErr, closeErr := errors.New("injected read failure"), errors.New("injected close failure")
	original := openPackFile
	openPackFile = func(root *os.Root, name string) (packFile, error) {
		f, err := original(root, name)
		if err != nil {
			return nil, err
		}
		return readCloseErrorFile{packFile: f, readErr: readErr, closeErr: closeErr}, nil
	}
	t.Cleanup(func() { openPackFile = original })
	_, err := Check(Options{Dir: dir})
	if !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatalf("joined err=%v", err)
	}
}
