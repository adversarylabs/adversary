package receipt

import (
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/dataroot"
)

func TestReceiptSaveVerify(t *testing.T) {
	r := New("run-1")
	r.SetStage("collect", dataroot.ClassReal)
	r.SetStage("judge", dataroot.ClassFixture)
	r.CaseIDs = []string{"c1"}
	r.Finish("success")
	if err := Verify(r); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path, err := Save(root, r)
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("empty path")
	}
	if _, err := filepath.Rel(root, path); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyMissingRunID(t *testing.T) {
	if err := Verify(&Receipt{}); err == nil {
		t.Fatal("expected error")
	}
}
