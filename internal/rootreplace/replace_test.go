package rootreplace

import (
	"errors"
	"os"
	"testing"
)

func TestMutableReplacesAndImmutableDoesNot(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("old", []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("new", []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Mutable(root, "new", "old"); err != nil {
		t.Fatal(err)
	}
	data, err := root.ReadFile("old")
	if err != nil || string(data) != "new" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	if err := root.WriteFile("another", []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Immutable(root, "another", "old"); err == nil {
		t.Fatal("immutable publish replaced existing target")
	}
}

func TestSyncOrderingAndFailure(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("from", []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	var order []string
	SyncHook = func(step string) error { order = append(order, step); return nil }
	defer func() { SyncHook = nil }()
	if err := Mutable(root, "from", "to"); err != nil {
		t.Fatal(err)
	}
	if len(order) < 2 || order[0] != "file" || order[1] != "directory" {
		t.Fatalf("order=%v", order)
	}
	if err := root.WriteFile("blocked", []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	SyncHook = func(step string) error {
		if step == "file" {
			return errors.New("injected")
		}
		return nil
	}
	if err := Mutable(root, "blocked", "never"); err == nil {
		t.Fatal("sync failure ignored")
	}
	if _, err := root.Stat("never"); !os.IsNotExist(err) {
		t.Fatalf("destination published after prepublish sync failure: %v", err)
	}
}
