package initproject

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCreateCleansOwnedStageAfterInjectedRenderAndWriteFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func()
	}{
		{"render", func() {
			renderTemplate = func([]byte, map[string]string) ([]byte, error) { return nil, errors.New("injected render failure") }
		}},
		{"write", func() {
			writeTemplateFile = func(string, []byte, os.FileMode) error { return errors.New("injected write failure") }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			sentinel := filepath.Join(parent, "user-data")
			if err := os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			originalRender, originalWrite := renderTemplate, writeTemplateFile
			t.Cleanup(func() { renderTemplate, writeTemplateFile = originalRender, originalWrite })
			tc.inject()
			dst := filepath.Join(parent, "failed-project")
			if _, err := Create(Options{Destination: dst}); err == nil {
				t.Fatal("Create succeeded")
			}
			if _, err := os.Lstat(dst); !os.IsNotExist(err) {
				t.Fatalf("destination exists: %v", err)
			}
			stages, err := filepath.Glob(filepath.Join(parent, ".adversary-init-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(stages) != 0 {
				t.Fatalf("owned stages remain: %v", stages)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "preserve" {
				t.Fatalf("user data changed: %q, %v", data, err)
			}
		})
	}
}

func TestCreateClaimsDestinationExactlyOnce(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "race-project")
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, err := Create(Options{Destination: dst}); errs <- err }()
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successes = %d, want 1", success)
	}
	if _, err := os.Stat(filepath.Join(dst, "adversary.yaml")); err != nil {
		t.Fatalf("winner output removed: %v", err)
	}
}

func TestCreateRejectsUnsafeProjectNamesWithoutCreatingDestination(t *testing.T) {
	for _, name := range []string{"Has Spaces", "O'Reilly", "日本語", "UPPER"} {
		dst := filepath.Join(t.TempDir(), name)
		if _, err := Create(Options{Destination: dst}); err == nil {
			t.Fatalf("Create(%q) succeeded", name)
		}
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Fatalf("destination exists after rejection: %v", err)
		}
	}
}

func TestCreateRejectsNPMReservedAndOversizedNamesBeforeParentCreation(t *testing.T) {
	for _, name := range []string{"node_modules", "favicon.ico", "http", strings.Repeat("a", 215)} {
		root := t.TempDir()
		parent := filepath.Join(root, "must-not-exist")
		dst := filepath.Join(parent, name)
		if _, err := Create(Options{Destination: dst}); err == nil {
			t.Fatalf("Create(%q) succeeded", name)
		}
		if _, err := os.Lstat(parent); !os.IsNotExist(err) {
			t.Fatalf("parent mutated after rejecting %q: %v", name, err)
		}
	}
}

func TestCreateNeverRemovesExistingDestinationData(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "existing-project")
	if err := os.Mkdir(dst, 0755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dst, "another-actors-data")
	if err := os.WriteFile(sentinel, []byte("preserve me"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(Options{Destination: dst}); err == nil {
		t.Fatal("Create succeeded")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("sentinel removed: %v", err)
	}
	if string(data) != "preserve me" {
		t.Fatalf("sentinel changed: %q", data)
	}
}

func TestCreatePreservesDestinationCreatedAtPublishRace(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "raced-project")
	original := publishProject
	publishProject = func(staging, destination string) error {
		if err := os.Mkdir(destination, 0755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(destination, "other-data"), []byte("safe"), 0644); err != nil {
			return err
		}
		return os.Rename(staging, destination)
	}
	t.Cleanup(func() { publishProject = original })
	if _, err := Create(Options{Destination: dst}); err == nil {
		t.Fatal("Create succeeded")
	}
	data, err := os.ReadFile(filepath.Join(dst, "other-data"))
	if err != nil {
		t.Fatalf("racing actor's data removed: %v", err)
	}
	if string(data) != "safe" {
		t.Fatalf("racing actor's data changed: %q", data)
	}
}

func TestCreateDoesNotReplaceConcurrentEmptyDestination(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "empty-race")
	original := publishProject
	var before os.FileInfo
	publishProject = func(staging, destination string) error {
		if err := os.Mkdir(destination, 0711); err != nil {
			return err
		}
		var err error
		before, err = os.Stat(destination)
		if err != nil {
			return err
		}
		return original(staging, destination)
	}
	t.Cleanup(func() { publishProject = original })
	if _, err := Create(Options{Destination: dst}); err == nil {
		t.Fatal("Create succeeded")
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("concurrent empty destination was replaced")
	}
	if after.Mode().Perm() != 0711 {
		t.Fatalf("destination mode = %o, want 711", after.Mode().Perm())
	}
}

func TestCreatePublishesProjectRootMode(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "mode-project")
	if _, err := Create(Options{Destination: dst}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("project root mode = %o, want 755", info.Mode().Perm())
	}
}

func TestRenderSuccessUsesLocationAndShellQuotes(t *testing.T) {
	var out bytes.Buffer
	location := "/tmp/a path/it's-here"
	RenderSuccess(&out, Result{Location: location, SDK: "TypeScript"}, "wrong", "linux")
	if !strings.Contains(out.String(), location) || !strings.Contains(out.String(), `cd '/tmp/a path/it'"'"'s-here'`) {
		t.Fatalf("output not safely rendered:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "npm ci") || strings.Contains(out.String(), "npm install") {
		t.Fatalf("output does not use lockfile install:\n%s", out.String())
	}
}

func TestRenderSuccessUsesPowerShellLiteralPathOnWindows(t *testing.T) {
	var out bytes.Buffer
	location := `C:\Users\Ada O'Brien\review`
	RenderSuccess(&out, Result{Location: location, SDK: "TypeScript"}, "wrong", "windows")
	if !strings.Contains(out.String(), `Set-Location -LiteralPath 'C:\Users\Ada O''Brien\review'`) {
		t.Fatalf("output not safely rendered for PowerShell:\n%s", out.String())
	}
	if strings.Contains(out.String(), "  cd ") {
		t.Fatalf("output contains POSIX navigation on Windows:\n%s", out.String())
	}
}
