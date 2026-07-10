package archiveutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishSealedTransition(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "staging", "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "staging", "sub", "run"), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "final"), 0755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stage, err := root.OpenRoot("staging")
	if err != nil {
		t.Fatal(err)
	}
	if err := PreparePublish(stage); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrepared(stage); err != nil {
		t.Fatal(err)
	}
	if info, err := stage.Stat("."); err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("stage root mode=%v err=%v", info, err)
	}
	if info, err := stage.Stat("sub/run"); err != nil || info.Mode().Perm() != 0555 {
		t.Fatalf("stage child mode=%v err=%v", info, err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	published, err := PublishSealed(base, root, "staging", "final/digest")
	if err != nil || !published {
		t.Fatalf("published=%v err=%v", published, err)
	}
	dest, err := root.OpenRoot("final/digest")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSealed(dest); err != nil {
		t.Fatal(err)
	}
	_ = Unseal(dest)
	_ = dest.Close()
}

func TestPublishFailureDoesNotClaimDestination(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "staging"), 0755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	published, err := PublishSealed(base, root, "staging", "missing/digest")
	if err == nil || published {
		t.Fatalf("published=%v err=%v", published, err)
	}
	if _, err := root.Lstat("missing/digest"); !os.IsNotExist(err) {
		t.Fatalf("destination exists: %v", err)
	}
}
