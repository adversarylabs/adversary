package initproject

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

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

func TestRenderSuccessUsesLocationAndShellQuotes(t *testing.T) {
	var out bytes.Buffer
	location := "/tmp/a path/it's-here"
	RenderSuccess(&out, Result{Location: location, SDK: "TypeScript"}, "wrong")
	if !strings.Contains(out.String(), location) || !strings.Contains(out.String(), `cd '/tmp/a path/it'"'"'s-here'`) {
		t.Fatalf("output not safely rendered:\n%s", out.String())
	}
}
